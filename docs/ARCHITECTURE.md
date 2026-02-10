# Architecture

This project structure was expanded with AI-assisted implementation and documentation, while preserving legacy worker runtime logic.

## Components

- `NFSLAN-GUI` (Qt)
  - Manages game profiles (Most Wanted, Underground 2)
  - Stores launcher settings via `QSettings`
  - Starts/stops worker process (or embedded worker mode on Windows)
  - Streams worker logs into the GUI

- `NFSLAN` worker (Windows)
  - Loads `server.dll`
  - Resolves `StartServer`, `IsServerRunning`, `StopServer`
  - Applies Most Wanted runtime patching (injector/hooking)
  - Runs server loop and handles shutdown signals

## Cross-platform model

- Windows default: `NFSLAN-GUI.exe` -> internal `--worker` mode -> `server.dll`
- Windows legacy: `NFSLAN-GUI` -> `NFSLAN.exe` -> `server.dll`
- Linux: `NFSLAN-GUI` -> `wine NFSLAN.exe` -> `server.dll`
- macOS: `NFSLAN-GUI` -> `wine/CrossOver wrapper` -> `NFSLAN.exe` -> `server.dll`

This split isolates Windows-only binary logic into the worker and keeps GUI code portable.

## Why non-Windows uses compatibility runtime

`server.dll` and the patching flow are based on Win32 APIs and x86 binary signatures.
A native Linux loader would require a complete reimplementation or an equivalent Linux server binary, which is not available in this repository.

## Future extension points

- Replace Wine path with a truly native backend if a Linux-compatible server implementation appears.
- Implement Underground 2 patching in worker (`PatchServerUG2`).
- Add profile export/import and packaging scripts.
