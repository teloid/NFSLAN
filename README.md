# NFSLAN Server Manager

Cross-platform GUI launcher for NFS LAN server hosting with a Windows native worker runtime.

## AI-Enhanced Fork Notice

This fork includes AI-assisted enhancements for architecture, GUI workflow, build system, and documentation.
Legacy worker behavior and reverse-engineered server limitations still apply.

## What is included

- `NFSLAN-GUI`: desktop GUI launcher (Qt, Windows/Linux/macOS)
- Windows single-executable mode: GUI + worker runtime embedded in the same EXE (default Windows build)
- Optional separate `NFSLAN` worker build on Windows (legacy mode)
- Existing injector/hooking code used by the worker for Most Wanted patching

## Important platform reality

`server.dll` from Need for Speed Most Wanted (2005) and Underground 2 is a Windows PE library.

- Windows: default build runs worker from inside the GUI executable
- Linux/macOS: run the same Windows worker through a runtime command (`wine`, or a Proton/wrapper command)

Native Linux loading of this `server.dll` is not available in this project because the game server binary itself is Windows-only.

## Quick start

1. Build on Windows (single EXE mode is default).
2. Place game `server.dll` and `server.cfg` in a server folder.
3. Open `NFSLAN-GUI`, choose game profile, set server name/path, and start.
4. On Linux/macOS, install a Windows compatibility runtime and run the Windows build via Proton/Wine, or keep using native GUI + separate worker setup.

## Documentation

- Build instructions: `docs/BUILD.md`
- Runtime usage: `docs/RUNNING.md`
- Client and internet setup: `docs/CLIENT_SETUP.md`
- Architecture notes: `docs/ARCHITECTURE.md`
- Legacy worker notes: `docs/LEGACY_CONSOLE.md`

## Current limitations

- Underground 2 patching is still not implemented in the worker (`PatchServerUG2` is a stub).
- You still need original game server files (`server.dll`, `server.cfg`).
- Non-Windows runtime depends on a Windows compatibility layer because of the Windows server binary.
