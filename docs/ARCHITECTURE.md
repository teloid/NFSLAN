# Architecture (U2-focused release)

## Goal

Standalone U2 server host with same-PC join support through one launcher flow.

## Components

- `native_win32/src/NativeMain.cpp`
  - Main GUI (`NFSLAN-GUI.exe`)
  - Config editing + preflight
  - Worker lifecycle (`Start` / `Stop`)
  - `UG2 Bundle` orchestration (worker + patcher)

- `NFSLAN.cpp`
  - Worker runtime (`--worker`)
  - Loads `server.dll`, calls `StartServer` / `StopServer`
  - Normalizes U2 config keys and lobby ids
  - Performs runtime compatibility checks and logging

- `native_win32/src/U2PatchLauncher.cpp`
  - Runtime patch loop for `SPEED2.EXE`
  - Keeps U2 LAN row visible on same-PC host/client scenarios
  - Injects fallback row when LAN manager has no active row

## Build modes

- Embedded worker mode (recommended): one GUI EXE starts worker internally.
- External worker mode: GUI starts `NFSLAN.exe` next to it.

## Current scope boundary

- Underground 2 is the active supported path in this release.
- Most Wanted work is intentionally paused.
