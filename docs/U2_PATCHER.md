# U2 Same-Machine Patch Launcher Guide

## Purpose

`NFSLAN-U2-Patcher.exe` is a tiny helper for **Need for Speed Underground 2** same-machine hosting.

It addresses a client-side visibility issue where `speed2.exe` can hide LAN servers discovered from the same machine (self-filter behavior), even when server beacons are valid.

This file is part of the AI-enhanced fork documentation.

## What it does

1. Starts `speed2.exe`.
2. Monitors the game process while it runs.
3. Clears the LAN entry self-filter flag in game memory (`entry + 0x19c`) repeatedly.
4. Forces one visible UG2 LAN row in game memory when needed, synchronized to configured name/port/IP injection target.

It does **not** modify `server.dll` on disk.

## When to use it

Use it when:
- you run U2 client and standalone server on the same Windows PC
- server runs fine but does not appear in in-game LAN list
- relay diff report shows near-identical beacons but visibility still fails

## How to run

### Option A: from `NFSLAN-GUI`

1. Build native Win32 targets.
2. Ensure `NFSLAN-U2-Patcher.exe` is next to `NFSLAN-GUI.exe`.
3. In `NFSLAN-GUI`, set `U2 game EXE` path to `speed2.exe`.
4. Click `UG2 Same-PC` (recommended one-click flow).
5. Keep patcher running while playing/hosting.

### Option B: direct CLI

```powershell
NFSLAN-U2-Patcher.exe "C:\Games\NFS Underground 2\speed2.exe"
```

Optional explicit injection target:

```powershell
NFSLAN-U2-Patcher.exe --inject-name "UG2 Dedicated Server" --inject-port 9900 --inject-ip 127.0.0.1 "C:\Games\NFS Underground 2\speed2.exe"
```

You can pass extra game args after exe path (or after `--`):

```powershell
NFSLAN-U2-Patcher.exe "C:\Games\NFS Underground 2\speed2.exe" -somearg
```

If no path is passed, a file picker opens.

## Typical workflow (same machine)

1. Start `NFSLAN-U2-Patcher.exe`.
2. Launch standalone server from `NFSLAN-GUI` with:
   - `FORCE_LOCAL=1`
   - `ENABLE_GAME_ADDR_FIXUPS=1`
   - optional `LOCAL_EMULATION=1`
3. In game, search LAN servers.

Preferred simplified workflow:

1. In `NFSLAN-GUI`, set profile to Underground 2.
2. Set `U2 game EXE`.
3. Click `UG2 Same-PC`.
4. In game, search LAN servers.

## Verification

Patcher console/log should show:
- game launched
- patch loop alive
- periodic `cleared self-filter flag(s)` lines
- `Injection target: ...` line with expected name/port/IP

If cleared count stays `0`, it may still be fine (depends on timing and list refresh activity).

## Troubleshooting

- `Failed to start game process`:
  - verify path to `speed2.exe`
  - run from folder with read/execute permissions
- No server in list:
  - confirm correct U2 `server.dll` and profile
  - check `LOBBY_IDENT=LOBBY=NFSU2NA`
  - try different `PORT` (not only `9900`)
  - generate relay diff report and inspect heuristic section
- Crash or no effect on custom exe:
  - patcher offsets are based on the analyzed U2 client layout used in this repository
  - different executable builds may require offset updates

## Safety notes

- Runtime-only patching: no permanent disk patch is written by this launcher.
- Keep anti-cheat/online integrity implications in mind for non-LAN contexts.
