# U2 Patcher Guide

`NFSLAN-U2-Patcher.exe` is used by `Start Bundle (Recommended)` when `Mode = Underground 2`.

## Purpose

It patches `speed2.exe` at runtime to keep standalone U2 server rows visible/joinable on the same machine.

No on-disk game binary modification is performed.

## Recommended usage

Do not run this manually unless you are debugging.

Use:

1. Run `NFSLAN-GUI.exe` as admin.
2. Select `Game folder` (contains `SPEED2.EXE`, `server.dll`, `server.cfg`).
3. Click `Start Bundle (Recommended)`.

The launcher starts worker first, then starts patcher with synchronized:

- injected protocol ID (`LOBBY_IDENT`)
- injected name
- injected port
- injected ip

## CLI usage (debug only)

```powershell
NFSLAN-U2-Patcher.exe "C:\Games\NFS Underground 2\SPEED2.EXE"
```

Optional:

```powershell
NFSLAN-U2-Patcher.exe --inject-ident NFSU2NA --inject-name "Test Server" --inject-port 9900 --inject-ip 192.168.1.98 "C:\Games\NFS Underground 2\SPEED2.EXE"
```

## Expected log signals

- patch loop alive
- module base resolved
- non-zero `totalInjected` in fallback situations
- `totalCleared` increasing when self-filter flags are observed
