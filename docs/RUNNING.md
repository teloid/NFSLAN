# Runtime Guide

## Required files per server instance

In your chosen server directory, place:

- `server.dll`
- `server.cfg`

Use the correct `server.dll` for the selected game profile.

## Start from GUI

1. Open launcher (`NFSLAN-GUI`).
2. Select profile:
   - Most Wanted (2005): use MW `server.dll`
   - Underground 2: use UG2 `server.dll`
3. Set `Server name`.
4. Set `Server directory` where `server.dll` and `server.cfg` exist.
5. Configure `PORT` and `ADDR` fields.
6. Edit advanced keys in `server.cfg` editor and save.
7. Start server.

## Worker mode behavior

- Native single-EXE (Win32/x86 embed): GUI launches itself with `--worker` internally.
- Native x64 GUI mode: GUI launches external `NFSLAN.exe` worker.
- Qt launcher mode: same as above depending on your build options.

## Internet notes

If logs show slave update with a local/private address such as `192.168.x.x`, remote internet players will not join correctly.

For internet hosting:

- Set `ADDR` to public IP or DNS name.
- Forward/open UDP ports required by your config (`PORT` and related service ports if customized).
- Ensure client patch setup matches your server setup (see `docs/CLIENT_SETUP.md`).

## Notes on stopping

- GUI stop terminates worker process.
- If worker does not exit cleanly, process is force-terminated.
