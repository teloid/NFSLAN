# NFSLAN Bundle (U2 + MW)

Standalone Need for Speed Underground 2 + Most Wanted LAN server launcher for Windows, with same-PC join support.

## AI-enhanced release note

This repository version is AI-enhanced and focused on one goal:

`Run the LAN server outside the game, and still join from the same PC.`

## Scope of this release

- Native Win32 UI (no Qt runtime required).
- Bundle mode: starts worker + launches the appropriate game patcher.
- Live `Events` + `Raw logs` panes in UI for runtime monitoring.
- Manual `Start` / `Stop` kept for direct worker control.
- Simplified UI and docs for fast setup.

## Quick start (recommended)

1. Run `NFSLAN-GUI.exe` as Administrator.
2. Select game mode (Underground 2 or Most Wanted).
3. Enter server name.
4. Pick `Game folder` (folder that contains the game EXE + `server.dll` + `server.cfg`).
5. Press `Start Bundle (Recommended)`.

That is the primary workflow.

## Manual mode (fallback)

- Press `Start` to run only the standalone worker.
- Press `Stop` to stop it.

Use this if you want server-only runtime without launching the game patcher.

## Required files

In your selected game folder:

- `server.dll` (from that game)

## Build (Windows 11)

Use Visual Studio 2022 + CMake.

Single EXE (recommended, Win32/x86):

```powershell
cmake -S . -B build-win32-single -G "Visual Studio 17 2022" -A Win32 `
  -DNFSLAN_BUILD_NATIVE_WIN32_GUI=ON `
  -DNFSLAN_BUILD_GUI=OFF `
  -DNFSLAN_BUILD_WORKER=ON `
  -DNFSLAN_EMBED_WORKER_IN_GUI=ON
cmake --build build-win32-single --config Release
```

Outputs:

- `build-win32-single/native_win32/Release/NFSLAN-GUI.exe`
- `build-win32-single/native_win32/Release/NFSLAN-U2-Patcher.exe`
- `build-win32-single/native_win32/Release/NFSLAN-MW-Patcher.exe`

## Internet/LAN notes

- Server listens on your configured `PORT` (default `9900`).
- Set `ADDR` to your reachable host IP for your target setup.
- If hosting over internet, forward required ports to the server machine.
- Same-PC join uses bundle patching path; run as admin.

## Documentation

- `docs/BUILD.md` - build matrix and commands
- `docs/RUNNING.md` - runtime usage and GUI flow
- `docs/CLIENT_SETUP.md` - client/network setup notes
- `docs/U2_PATCHER.md` - patcher behavior and diagnostics
