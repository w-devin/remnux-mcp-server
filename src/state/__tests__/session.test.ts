import { describe, it, expect, vi, afterEach } from "vitest";
import { SessionState } from "../session.js";

describe("SessionState", () => {
  afterEach(() => { vi.useRealTimers(); });
  it("stores and retrieves archive info by archive filename", () => {
    const state = new SessionState();
    state.storeArchiveInfo("sample.7z", ["payload.exe", "readme.txt"], "7z", "malware");

    const info = state.getArchiveInfo("sample.7z");
    expect(info).toEqual({ format: "7z", password: "malware" });
  });

  it("stores and retrieves archive info by extracted filename", () => {
    const state = new SessionState();
    state.storeArchiveInfo("sample.zip", ["payload.exe"], "zip", "infected");

    const info = state.getArchiveInfo("payload.exe");
    expect(info).toEqual({ format: "zip", password: "infected" });
  });

  it("returns undefined for unknown filenames", () => {
    const state = new SessionState();
    expect(state.getArchiveInfo("unknown.bin")).toBeUndefined();
  });

  it("retrieves archive info by basename of subdirectory path", () => {
    const state = new SessionState();
    state.storeArchiveInfo("sample.zip", ["subdir/payload.exe", "subdir/readme.txt"], "zip", "infected");

    // Lookup by full path
    expect(state.getArchiveInfo("subdir/payload.exe")).toEqual({ format: "zip", password: "infected" });
    // Lookup by basename (how download_file looks it up)
    expect(state.getArchiveInfo("payload.exe")).toEqual({ format: "zip", password: "infected" });
    expect(state.getArchiveInfo("readme.txt")).toEqual({ format: "zip", password: "infected" });
  });

  it("overwrites metadata for duplicate filenames", () => {
    const state = new SessionState();
    state.storeArchiveInfo("a.zip", ["file.exe"], "zip", "pass1");
    state.storeArchiveInfo("b.7z", ["file.exe"], "7z", "pass2");

    const info = state.getArchiveInfo("file.exe");
    expect(info).toEqual({ format: "7z", password: "pass2" });
  });

  it("expires metadata after its configured TTL", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    const state = new SessionState(100, 1_000);
    state.storeArchiveInfo("sample.zip", ["payload.exe"], "zip", "infected");

    vi.advanceTimersByTime(1_001);
    expect(state.getArchiveInfo("payload.exe")).toBeUndefined();
  });
});

it("normalizes slash styles before storing and looking up archive metadata", () => {
  const state = new SessionState();
  state.storeArchiveInfo("archives\\sample.zip", ["nested\\payload.exe"], "zip", "infected");

  expect(state.getArchiveInfo("archives/sample.zip")).toEqual({ format: "zip", password: "infected" });
  expect(state.getArchiveInfo("nested/payload.exe")).toEqual({ format: "zip", password: "infected" });
});

it("evicts least-recently-stored entries when the bounded cache is full", () => {
  const state = new SessionState(2);
  state.storeArchiveInfo("a.zip", ["a.exe"], "zip", "one");
  state.storeArchiveInfo("b.zip", ["b.exe"], "7z", "two");

  expect(state.getArchiveInfo("a.exe")).toBeUndefined();
  expect(state.getArchiveInfo("b.exe")).toEqual({ format: "7z", password: "two" });
});
