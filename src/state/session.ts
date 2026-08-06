/**
 * Process-level archive metadata cache shared by stateless HTTP requests.
 *
 * When extract_archive succeeds, we store the format and password used. When
 * download_file runs with archive: true, it can re-use the same metadata. The
 * cache is bounded and entries expire so stateless HTTP operation does not turn
 * this convenience state into unbounded process memory.
 */

import { basename, posix } from "node:path";

export const DEFAULT_ARCHIVE_PASSWORD = "infected";
export const DEFAULT_ARCHIVE_FORMAT = "zip" as const;

export interface ArchiveMetadata {
  format: "zip" | "7z" | "rar";
  password: string;
}

interface ArchiveMetadataEntry {
  metadata: ArchiveMetadata;
  storedAt: number;
}

export class SessionState {
  private archiveInfo = new Map<string, ArchiveMetadataEntry>();

  constructor(
    private readonly maxEntries = 1000,
    private readonly ttlMs = 24 * 60 * 60 * 1000,
  ) {}

  storeArchiveInfo(
    archiveFile: string,
    extractedFiles: string[],
    format: ArchiveMetadata["format"],
    password: string,
  ): void {
    const entry: ArchiveMetadataEntry = {
      metadata: { format, password },
      storedAt: Date.now(),
    };
    this.storeAllKeys(archiveFile, entry);
    for (const file of extractedFiles) {
      this.storeAllKeys(file, entry);
    }
    this.evictExpiredAndOverflow();
  }

  getArchiveInfo(filename: string): ArchiveMetadata | undefined {
    this.evictExpiredAndOverflow();
    for (const key of archiveKeys(filename)) {
      const entry = this.archiveInfo.get(key);
      if (entry) return entry.metadata;
    }
    return undefined;
  }

  private storeAllKeys(file: string, entry: ArchiveMetadataEntry): void {
    for (const key of archiveKeys(file)) {
      this.archiveInfo.delete(key);
      this.archiveInfo.set(key, entry);
    }
  }

  private evictExpiredAndOverflow(): void {
    const now = Date.now();
    for (const [key, entry] of this.archiveInfo) {
      if (now - entry.storedAt > this.ttlMs) this.archiveInfo.delete(key);
    }
    while (this.archiveInfo.size > this.maxEntries) {
      const oldestKey = this.archiveInfo.keys().next().value as string | undefined;
      if (oldestKey === undefined) break;
      this.archiveInfo.delete(oldestKey);
    }
  }
}

function archiveKeys(file: string): string[] {
  const normalized = normalizeArchiveKey(file);
  if (!normalized) return [];
  const base = basename(normalized);
  return base === normalized ? [normalized] : [normalized, base];
}

function normalizeArchiveKey(file: string): string {
  const slashPath = file.trim().replace(/\\/g, "/");
  if (!slashPath) return "";
  const normalized = posix.normalize(slashPath);
  return normalized === "." ? "" : normalized.replace(/^\.\//, "");
}
