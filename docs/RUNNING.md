# Runtime Guide

## Required files per server instance

In your chosen server directory, place:

- `server.dll`
- `server.cfg`

Use the correct `server.dll` for the selected game profile.

## Start from GUI

1. Open `NFSLAN-GUI`.
2. Select profile:
   - Most Wanted (2005): use MW `server.dll`
   - Underground 2: use UG2 `server.dll`
3. Set `Server name`.
4. Set `Server directory` where `server.dll` and `server.cfg` exist.
5. On Windows single-EXE mode, worker path is embedded automatically.
6. If using native GUI on non-Windows hosts, set `Worker executable` path.
7. On non-Windows hosts, set `Runtime command`:
   - `wine` (default)
   - `proton run` (if `proton` is in PATH)
   - Absolute path to wrapper script if Proton is not directly executable
8. Click `Start Server`.

The log panel displays worker output and start/stop status.

## Worker arguments

The GUI passes these arguments to the worker:

- `NFSLAN <ServerName>`
- Optional: `-n` to disable runtime patching

In Windows single-EXE mode, GUI launches itself with `--worker` internally.

## Internet usage

For internet play setup and client requirements, see `docs/CLIENT_SETUP.md`.

## Notes on stopping

- GUI stop sends process termination first.
- If worker does not exit quickly, GUI force-kills the process.
