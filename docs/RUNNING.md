# Runtime Guide

## Required files per server instance

In your chosen server directory, place:

- `server.dll`
- `server.cfg`

Use the correct `server.dll` for the selected game profile.
Do not run server directly from your game installation folder; use a separate server folder copy.

## Start from GUI

1. Open launcher (`NFSLAN-GUI`).
2. Select profile:
   - Most Wanted (2005): use MW `server.dll`
   - Underground 2: use UG2 `server.dll`
3. Set `Server name`.
4. Set `Server directory` where `server.dll` and `server.cfg` exist.
5. Configure `PORT` and `ADDR` fields.
6. Configure compatibility flags:
   - `FORCE_LOCAL`: enable when hosting and playing from the same machine
   - `ENABLE_GAME_ADDR_FIXUPS`: keep enabled (recommended for mixed local/public address setups)
7. Edit advanced keys in `server.cfg` editor and save.
8. Start server.

## Worker mode behavior

- Native single-EXE (Win32/x86 embed): GUI launches itself with `--worker` internally.
- Native x64 GUI mode: GUI launches external `NFSLAN.exe` worker.
- Qt launcher mode: same as above depending on your build options.
- Console worker also supports `--same-machine` (`--local-host` alias) to force same-PC compatibility values in `server.cfg`.

## Internet notes

If logs show slave update with a local/private address such as `192.168.x.x`, remote internet players will not join correctly.

For internet hosting:

- Set `ADDR` to public IP or DNS name.
- Forward/open UDP ports required by your config (`PORT` and related service ports if customized).
- Ensure client patch setup matches your server setup (see `docs/CLIENT_SETUP.md`).

## Same-machine host + client notes

If the host also runs the game client on the same Windows machine:

- Enable `FORCE_LOCAL`.
- Keep `ENABLE_GAME_ADDR_FIXUPS=1`.
- If local client still cannot find/join, test a non-default `PORT` instead of `9900` to avoid client/server UDP bind conflicts in some patch sets.

## Notes on stopping

- GUI stop terminates worker process.
- If worker does not exit cleanly, process is force-terminated.
