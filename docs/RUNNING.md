# Runtime Guide (U2-focused)

## Intended flow

1. Run `NFSLAN-GUI.exe` as Administrator.
2. Set `Server name`.
3. Set `Server directory` (must contain `server.dll` + `server.cfg`).
4. Set `U2 game EXE` (`SPEED2.EXE`).
5. Click `UG2 Bundle (Recommended)`.

This launches:

- standalone worker server process
- U2 patcher for same-PC server visibility/join

## Manual fallback

- `Start`: starts worker only.
- `Stop`: stops worker process.

Use this when you want server runtime without game patch launcher.

## Key config fields

- `PORT`: server port (`9900` default)
- `ADDR`: server bind/identity address
- `U2_START_MODE`: `0..13` (`0` default)
- `LOBBY_IDENT`: must be `NFSU2NA`
- `LOBBY`: must be `NFSU2NA`

The launcher enforces U2 protocol IDs and writes compatibility values before start.

## Required files in server directory

- `server.dll` (U2)
- `server.cfg`
- optional game report file (`gamefile.bin` or compatible `gameplay.bin`)

## Common startup checks

Preflight blocks launch when:

- `PORT` is invalid.
- `ADDR` is empty.
- `server.dll` looks like MW profile.
- local ports are already occupied (`UDP 9999`, service `PORT`).
- same identity already running (`LOBBY_IDENT + PORT`).

## Same-PC behavior

Bundle mode is the supported way for same-machine host+client.

If discovery still fails:

1. Confirm you run GUI as Administrator.
2. Confirm `server.dll` is U2.
3. Confirm worker is listening on `PORT`.
4. Re-run bundle and check patcher log build tag + injection target.
