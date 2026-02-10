# Architecture

This fork includes AI-assisted implementation and documentation updates while preserving legacy worker runtime logic.

## Components

- Native Win32 GUI (`native_win32`)
  - No Qt runtime dependency
  - Includes `server.cfg` editor in UI
  - Starts/stops worker and streams logs
- Qt GUI (`gui`)
  - Optional cross-platform launcher path
- Worker runtime (`NFSLAN.cpp`)
  - Loads `server.dll`
  - Resolves `StartServer`, `IsServerRunning`, `StopServer`
  - Applies Most Wanted runtime patching (injector/hooking)
  - Applies startup `server.cfg` compatibility preflight (`ENABLE_GAME_ADDR_FIXUPS`, optional same-machine `FORCE_LOCAL`)

## Runtime models

- Windows native x64 GUI mode: `NFSLAN-GUI.exe` -> external `NFSLAN.exe` (x86) -> `server.dll`
- Windows native single-EXE (Win32/x86): `NFSLAN-GUI.exe` -> internal `--worker` mode -> `server.dll`
- Linux/macOS via compatibility layer: launch Windows worker through Wine/Proton/CrossOver

## Architecture constraints

- `server.dll` and worker patching are Win32/x86-oriented.
- Native non-Windows loading of `server.dll` is not supported in this repository.
- Embedded single-EXE mode requires Win32/x86 process architecture.

## Future extension points

- Implement Underground 2 patching in worker (`PatchServerUG2`).
- Add richer config schema and validation in native GUI.
- Add packaged installer workflow for portable distribution.

## Reverse-engineering notes currently used

From decompiled `server.dll`, two config toggles are now surfaced and used in launcher flow:

- `FORCE_LOCAL`
- `ENABLE_GAME_ADDR_FIXUPS`

The launcher uses these to improve same-machine host+client behavior without hardcoding binary offsets for this part.
