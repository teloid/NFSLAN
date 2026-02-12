# NFSLAN Server Manager

Cross-platform GUI launcher for NFS LAN server hosting with a Windows native worker runtime.

## AI-Enhanced Fork Notice

This fork includes AI-enhanced implementation and documentation updates for architecture, GUI workflow, build system, and diagnostics.
Legacy worker behavior and reverse-engineered server limitations still apply.

## What is included

- Native Win32 launcher (`NFSLAN-GUI`) with integrated `server.cfg` editor and embedded relay tool launcher (`Relay tool` button) in the same EXE
- Native Win32 U2 patch launcher (`NFSLAN-U2-Patcher`) to bypass NFSU2 same-machine self-discovery filtering in `speed2.exe`
- Native Win32 relay app (`NFSLAN-Relay`) for cross-subnet/cross-site LAN discovery forwarding (UG2/MW style UDP `9999` broadcast relay)
- Native Win32 relay app includes beacon capture/diff workflow (in-game sample vs standalone sample) with detailed report export
- Relay capture path includes UDP bind + raw fallback sniff mode when `9999` is already occupied (admin recommended)
- Native Win32 launcher includes explicit `FORCE_LOCAL`, `LOCAL_EMULATION`, and `ENABLE_GAME_ADDR_FIXUPS` toggles for same-machine host+client scenarios
- Native Win32 launcher includes `U2_START_MODE` (`0..13`) and `LAN_DIAG` controls with profile-aware preflight validation before launch
- Native Win32 launcher preflight now blocks local port conflicts (`UDP 9999`, service UDP/TCP `PORT`) and duplicate server identity (`LOBBY_IDENT` + `PORT`)
- Native Win32 launcher logs build tag, executable path, worker launch mode, and effective profile/runtime paths at startup
- Qt launcher (`NFSLAN-GUI`/`NFSLAN-NativeGUI` depending on build options) for cross-platform workflows
- Windows single-executable mode: GUI + worker runtime embedded in the same EXE (Win32/x86 build)
- Optional separate `NFSLAN` worker build on Windows in external-worker mode
- Existing injector/hooking code used by the worker for Most Wanted patching
- Worker-side MW/UG2 config normalization and game-report file header validation (`gamefile.bin` / `gameplay.bin`)
- Worker now auto-fills missing `LOBBY_IDENT`/`LOBBY` defaults (`NFSU2NA` for UG2, `NFSMWNA` for MW) and can run a same-machine LAN discovery loopback bridge on UDP `9999`
- Worker supports `LOCAL_EMULATION`/`--local-emulation` with configurable discovery probe endpoint (`DISCOVERY_ADDR`/`DISCOVERY_PORT`)
- Worker supports `--u2-mode` and `--diag-lan` for UG2 mode control and deep LAN packet diagnostics
- Worker now supports UG2 synthetic beacon fallback (`UG2_BEACON_EMULATION=1`, `--ug2-beacon-emu`) and beacon-only discovery mode (`--beacon-only`)
- Worker enforces the same server identity lock; UG2 beacon handling now stays close to stock server behavior (mirror/diagnostics without forced beacon rewrites)

## Important platform reality

`server.dll` from Need for Speed Most Wanted (2005) and Underground 2 is a Windows PE library.

- Windows:
  - Native Win32 GUI can run in external-worker mode (x64 GUI + x86 worker)
  - Single-EXE mode requires 32-bit (Win32/x86) build because worker + `server.dll` are x86-only
- Linux/macOS: run the same Windows worker through a runtime command (`wine`, or a Proton/wrapper command)

Native Linux loading of this `server.dll` is not available in this project because the game server binary itself is Windows-only.

## Quick start

1. Build on Windows:
   - native Win32 GUI in x64 (external worker mode), or
   - native single EXE in Win32/x86 (embedded worker mode).
   - optional relay app (`NFSLAN-Relay`) for LAN discovery forwarding across subnets/VPN/internet.
2. Place game `server.dll` and `server.cfg` in a server folder.
3. Open `NFSLAN-GUI`, choose game profile, set server name/path, and start.
4. If needed for cross-subnet discovery, click `Relay tool` in the same app to open embedded `NFSLAN-Relay` mode (`--relay-ui`).
5. If host and client run on the same PC (UG2), run `NFSLAN-U2-Patcher.exe`, then enable `FORCE_LOCAL` and (optionally) `LOCAL_EMULATION`.
6. If server still does not appear in UG2 list, enable synthetic beacon fallback:
   - normal mode: set `UG2_BEACON_EMULATION=1` or pass `--ug2-beacon-emu`
   - discovery-only test: run worker with `--beacon-only` to broadcast a visible LAN beacon without loading `server.dll`
6. On Linux/macOS, install a Windows compatibility runtime and run the Windows build via Proton/Wine, or use the Qt launcher path.

## Documentation

- Build instructions: `docs/BUILD.md`
- Runtime usage: `docs/RUNNING.md`
- Client and internet setup: `docs/CLIENT_SETUP.md`
- Architecture notes: `docs/ARCHITECTURE.md`
- U2 patch launcher guide: `docs/U2_PATCHER.md`
- Legacy worker notes: `docs/LEGACY_CONSOLE.md`

## Current limitations

- Underground 2 patching is still not implemented in the worker (`PatchServerUG2` is a stub).
- You still need original game server files (`server.dll`, `server.cfg`).
- Non-Windows runtime depends on a Windows compatibility layer because of the Windows server binary.
