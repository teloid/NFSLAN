# U2 Patcher Guide

`NFSLAN-U2-Patcher.exe` is used by `UG2 Bundle` mode.

## Purpose

It patches `speed2.exe` at runtime to keep standalone U2 server rows visible/joinable on the same machine.

No on-disk game binary modification is performed.

## Recommended usage

Do not run this manually unless you are debugging.

Use:

1. Run `NFSLAN-GUI.exe` as admin.
2. Set `U2 game EXE`.
3. Click `UG2 Bundle (Recommended)`.

The launcher starts worker first, then starts patcher with synchronized:

- injected name
- injected port
- injected ip

## CLI usage (debug only)

```powershell
NFSLAN-U2-Patcher.exe "C:\Games\NFS Underground 2\SPEED2.EXE"
```

Optional:

```powershell
NFSLAN-U2-Patcher.exe --inject-name "Test Server" --inject-port 9900 --inject-ip 192.168.1.98 "C:\Games\NFS Underground 2\SPEED2.EXE"
```

## Expected log signals

- patch loop alive
- module base resolved
- non-zero `totalInjected` in fallback situations
- `totalCleared` increasing when self-filter flags are observed
