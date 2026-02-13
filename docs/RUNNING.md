# Runtime Guide (U2 + MW)

## Intended flow

1. Run `NFSLAN-GUI.exe` as Administrator.
2. Select `Mode` (Underground 2 or Most Wanted).
3. Set `Server name`.
4. Set `Game folder` (must contain game EXE + `server.dll` + `server.cfg`).
5. Click `Start Bundle (Recommended)`.

This launches:

- standalone worker server process
- game patcher for same-PC server visibility/join (U2 or MW)
- live UI panes:
  - `Live events` (connection/race/lifecycle extraction)
  - `Raw logs` (full worker stream with repetitive game-report noise filtered)

## Manual fallback

- `Start`: starts worker only.
- `Stop`: stops worker process.

Use this when you want server runtime without game patch launcher.

## Key config fields

- `PORT`: server port (`9900` default)
- `ADDR`: server bind/identity address
- `U2_START_MODE`: `0..13` (`0` default, UG2 only)
- `LOBBY_IDENT`: protocol ID (must match your client build/region)
- `LOBBY`: must match `LOBBY_IDENT`

The launcher writes compatibility values before start and keeps `LOBBY` aligned to `LOBBY_IDENT` without forcing a region.

## Required files in game folder

- `server.dll`
- `server.cfg`

## Common startup checks

Preflight blocks launch when:

- `PORT` is invalid.
- `ADDR` is empty.
- `server.dll` looks like the wrong profile for the selected mode.
- local ports are already occupied (`UDP 9999`, service `PORT`).
- same identity already running (`LOBBY_IDENT + PORT`).

## Same-PC behavior

Bundle mode is the supported way for same-machine host+client.

If discovery still fails:

1. Confirm you run GUI as Administrator.
2. Confirm `server.dll` matches your selected mode.
3. Confirm worker is listening on `PORT`.
4. Re-run bundle and check patcher log build tag + injection target.
