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
- If a client build (for example SteamOS/Proton) cannot see the server on LAN, check `LOBBY_IDENT`/`LOBBY`:
  those protocol IDs must match your client build/region. Capture `udp.port == 9999` on the client to see which ID it expects.

## Documentation

- `docs/BUILD.md` - build matrix and commands
- `docs/RUNNING.md` - runtime usage and GUI flow
- `docs/CLIENT_SETUP.md` - client/network setup notes
- `docs/U2_PATCHER.md` - patcher behavior and diagnostics

## Tested on the following pirated releases (EXE pacth specifically)

 - NFSU2 (US version 1.2 MagiPack Repack)
```
FileName       : SPEED2.EXE
FullPath       : C:\Program Files (x86)\Need for Speed - Underground 2\SPEED2.EXE
Size_MB        : 4,58
Size_Bytes     : 4800512
Date_Modified  : 09.03.2005 0:37:24
SHA256         : F9DD86C054878CE6276BEB07C1FD61874F7A1E4BF1F241B084C65B73E24168A7
```

 - NFSMW (version 1.3 Black Edition Repack)
```
FileName       : speed.exe
FullPath       : C:\Program Files (x86)\EA GAMES\Need for Speed Most Wanted\speed.exe
Size_MB        : 5,75
Size_Bytes     : 6029312
Date_Modified  : 25.11.2023 16:12:09
SHA256         : 80774C2E5D619B4F120B48D4462896FD504C263399D203A238769CFFDE1D253C
```
