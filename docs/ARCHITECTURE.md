# Architecture

This fork includes AI-assisted implementation and documentation updates while preserving legacy worker runtime logic.

## Components

- Native Win32 GUI (`native_win32`)
  - No Qt runtime dependency
  - Includes `server.cfg` editor in UI
  - Starts/stops worker and streams logs
  - Launches embedded relay UI and standalone U2 self-filter patch launcher
- Qt GUI (`gui`)
  - Optional cross-platform launcher path
- U2 patch launcher (`native_win32/src/U2PatchLauncher.cpp`)
  - Starts `speed2.exe`
  - Applies runtime memory patch loop that clears UG2 LAN self-filter flags (`entry+0x19c`)
  - Targets same-machine host+client visibility issue in NFSU2 client
- Worker runtime (`NFSLAN.cpp`)
  - Loads `server.dll`
  - Resolves `StartServer`, `IsServerRunning`, `StopServer`
  - Applies Most Wanted runtime patching (injector/hooking)
  - Applies startup `server.cfg` compatibility preflight (`ENABLE_GAME_ADDR_FIXUPS`, optional same-machine `FORCE_LOCAL`)
  - Applies profile-specific key normalization for MW vs UG2 network config keys (including `LOBBY_IDENT`/`LOBBY` defaults)
  - Validates/selects compatible game report file (`gamefile.bin`/`gameplay.bin`) by header, not only filename
  - Optional same-machine LAN discovery loopback bridge (`UDP 9999`) in `--same-machine` / `--local-emulation` modes
  - UG2 sendto hook now mirrors discovery beacons for local visibility diagnostics without forcing beacon field rewrites

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
