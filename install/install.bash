#!/usr/bin/env bash
# Install remnux-mcp-server and register it with systemd.
#
# Optional environment overrides:
#   INSTALL_DIR=/opt/remnux-mcp-server
#   GIT_REPOSITORY=https://github.com/w-devin/remnux-mcp-server.git
#   GIT_BRANCH=feat/ida-integration
#   MCP_HTTP_HOST=0.0.0.0
#   MCP_HTTP_PORT=5555
#   IDA_MCP_BIN=/path/to/ida-mcp

set -euo pipefail

readonly DEFAULT_REPOSITORY="https://github.com/w-devin/remnux-mcp-server.git"
readonly DEFAULT_BRANCH="feat/ida-integration"
readonly DEFAULT_HTTP_HOST="0.0.0.0"
readonly DEFAULT_HTTP_PORT="5555"
readonly DEFAULT_IDA_MCP_BIN="/home/remnux/Downloads/ida_pro_9.4/ida-mcp/ida-mcp"
readonly SERVICE_NAME="remnux-mcp.service"
readonly SYSTEMD_UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}"
readonly ENV_DIRECTORY="/etc/remnux-mcp-server"
readonly ENV_PATH="${ENV_DIRECTORY}/remnux-mcp-server.env"
readonly TEMPLATE_RELATIVE_PATH="install/remnux-mcp-server.env"
readonly PLACEHOLDER_TOKEN="change-this-before-exposing-the-service"

log() {
  printf '[remnux-mcp-install] %s\n' "$*"
}

warn() {
  printf '[remnux-mcp-install] WARNING: %s\n' "$*" >&2
}

fail() {
  printf '[remnux-mcp-install] ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

contains_whitespace() {
  [[ "$1" =~ [[:space:]] ]]
}

run_as_install_user() {
  if (( EUID == 0 )); then
    sudo -H -u "${INSTALL_USER}" -- "$@"
  else
    "$@"
  fi
}

if (( EUID == 0 )); then
  [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]] \
    || fail "Run this script as the intended non-root service user (optionally through sudo)."
  INSTALL_USER="${SUDO_USER}"
else
  INSTALL_USER="$(id -un)"
fi
INSTALL_GROUP="$(id -gn "${INSTALL_USER}")"

INSTALL_DIR="${INSTALL_DIR:-${PWD}/remnux-mcp-server}"
GIT_REPOSITORY="${GIT_REPOSITORY:-${DEFAULT_REPOSITORY}}"
GIT_BRANCH="${GIT_BRANCH:-${DEFAULT_BRANCH}}"
MCP_HTTP_HOST="${MCP_HTTP_HOST:-${DEFAULT_HTTP_HOST}}"
MCP_HTTP_PORT="${MCP_HTTP_PORT:-${DEFAULT_HTTP_PORT}}"
IDA_MCP_BIN="${IDA_MCP_BIN:-${DEFAULT_IDA_MCP_BIN}}"

for command_name in git node npm sudo systemctl install; do
  require_command "${command_name}"
done

for value_name in INSTALL_DIR GIT_REPOSITORY GIT_BRANCH MCP_HTTP_HOST MCP_HTTP_PORT IDA_MCP_BIN; do
  value="${!value_name}"
  contains_whitespace "${value}" \
    && fail "${value_name} cannot contain whitespace because it is written to a systemd unit."
done

[[ "${MCP_HTTP_PORT}" =~ ^[0-9]+$ ]] \
  || fail "MCP_HTTP_PORT must be a numeric port number."
(( MCP_HTTP_PORT >= 1 && MCP_HTTP_PORT <= 65535 )) \
  || fail "MCP_HTTP_PORT must be between 1 and 65535."

GIT_BIN="$(command -v git)"
NODE_BIN="$(command -v node)"
NPM_BIN="$(command -v npm)"

if [[ -e "${INSTALL_DIR}" ]]; then
  [[ -d "${INSTALL_DIR}" ]] || fail "INSTALL_DIR exists but is not a directory: ${INSTALL_DIR}"
  run_as_install_user "${GIT_BIN}" -C "${INSTALL_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || fail "INSTALL_DIR exists but is not a Git working tree: ${INSTALL_DIR}"
  log "Reusing existing repository at ${INSTALL_DIR}."
else
  log "Cloning ${GIT_REPOSITORY} (${GIT_BRANCH}) into ${INSTALL_DIR}."
  run_as_install_user "${GIT_BIN}" clone --branch "${GIT_BRANCH}" --single-branch \
    "${GIT_REPOSITORY}" "${INSTALL_DIR}"
fi

TEMPLATE_PATH="${INSTALL_DIR}/${TEMPLATE_RELATIVE_PATH}"
[[ -f "${TEMPLATE_PATH}" ]] \
  || fail "Environment template is missing from the cloned repository: ${TEMPLATE_PATH}"

log "Installing Node.js dependencies as ${INSTALL_USER}."
run_as_install_user "${NPM_BIN}" --prefix "${INSTALL_DIR}" install

log "Building remnux-mcp-server."
run_as_install_user "${NPM_BIN}" --prefix "${INSTALL_DIR}" run build

[[ -f "${INSTALL_DIR}/dist/cli.js" ]] \
  || fail "Build completed without producing ${INSTALL_DIR}/dist/cli.js"

log "Installing runtime environment configuration."
sudo install -d -m 0755 "${ENV_DIRECTORY}"
if [[ -e "${ENV_PATH}" ]]; then
  warn "Keeping existing environment file: ${ENV_PATH}"
else
  sudo install -m 0600 "${TEMPLATE_PATH}" "${ENV_PATH}"
  log "Copied environment template to ${ENV_PATH}."
fi

UNIT_TEMP_FILE="$(mktemp)"
cleanup() {
  rm -f "${UNIT_TEMP_FILE}"
}
trap cleanup EXIT

cat > "${UNIT_TEMP_FILE}" <<EOF_UNIT
[Unit]
Description=REMnux MCP Server
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=${INSTALL_USER}
Group=${INSTALL_GROUP}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_PATH}
ExecStart=${NODE_BIN} ${INSTALL_DIR}/dist/cli.js --mode=local --transport=http --http-host=${MCP_HTTP_HOST} --http-port=${MCP_HTTP_PORT} --ida-bin=${IDA_MCP_BIN}
Restart=always
RestartSec=0
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF_UNIT

log "Installing systemd unit at ${SYSTEMD_UNIT_PATH}."
sudo install -m 0644 "${UNIT_TEMP_FILE}" "${SYSTEMD_UNIT_PATH}"
sudo systemctl daemon-reload
sudo systemctl enable --now "${SERVICE_NAME}"

if sudo grep -qx "MCP_TOKEN=${PLACEHOLDER_TOKEN}" "${ENV_PATH}"; then
  warn "${ENV_PATH} still contains the template token. Replace it with a strong token, then run:"
  warn "  sudo systemctl restart ${SERVICE_NAME}"
fi

log "Installation complete."
log "Service status: sudo systemctl status ${SERVICE_NAME}"
log "Service logs:   journalctl -u ${SERVICE_NAME} -f"
log "Manual update (default install path): (cd $(dirname "${INSTALL_DIR}") && bash ${INSTALL_DIR}/install/update.bash)"
log "After update:                  sudo systemctl restart ${SERVICE_NAME}"
