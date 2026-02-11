# Runtime Guide

## Required files per server instance

In your chosen server directory, place:

- `server.dll`
- `server.cfg`
- a valid game report file (`gamefile.bin` and/or `gameplay.bin`) with expected header

Use the correct `server.dll` for the selected game profile.
Do not run server directly from your game installation folder; use a separate server folder copy.

## Start from GUI

1. Open launcher (`NFSLAN-GUI`).
2. Select profile:
   - Most Wanted (2005): use MW `server.dll`
   - Underground 2: use UG2 `server.dll`
   - If `MW`/`U2` subfolders exist next to the GUI EXE, launcher auto-selects them as profile defaults.
3. Set `Server name`.
4. Set `Server directory` where `server.dll` and `server.cfg` exist.
5. Configure `PORT` and `ADDR` fields.
6. Configure compatibility flags:
   - `FORCE_LOCAL`: enable when hosting and playing from the same machine (UI also switches `ADDR` to `127.0.0.1`)
   - `ENABLE_GAME_ADDR_FIXUPS`: keep enabled (recommended for mixed local/public address setups)
   - `LAN_DIAG`: optional deep LAN discovery diagnostics (verbose packet-level logs)
   - `U2_START_MODE`: Underground 2-only StartServer mode (`0..13`, default `0`)
7. Edit advanced keys in `server.cfg` editor and save.
8. Start server.
9. Verify startup diagnostics in GUI log:
   - UI build tag
   - executable path
   - worker launch mode
   - selected profile
   - effective server directory and `server.cfg` path

## Worker mode behavior

- Native single-EXE (Win32/x86 embed): GUI launches itself with `--worker` internally.
- Native x64 GUI mode: GUI launches external `NFSLAN.exe` worker.
- Qt launcher mode: same as above depending on your build options.
- Console worker also supports `--same-machine` (`--local-host` alias) to force same-PC compatibility values in `server.cfg`.
- Console worker options:
  - `--u2-mode <0..13>`: sets UG2 StartServer mode and writes `U2_START_MODE`.
  - `--diag-lan`: enables deep LAN diagnostics (same as `LAN_DIAG=1`).
- Worker applies profile-specific config normalization:
  - MW: keeps `ENABLE_GAME_ADDR_FIXUPS` enabled and mirrors `ADDR/PORT` to MW auxiliary keys.
  - UG2: mirrors `ADDR/PORT` to UG2 keys (`MADDR/RADDR/AADDR`, `MPORT/RPORT/APORT`) when missing.
  - Both profiles: ensures non-empty `LOBBY_IDENT`/`LOBBY` defaults (`NFSMWNA` for MW, `NFSU2NA` for UG2) when missing.
- Worker validates game report file header (`ident=0x9A3E`, `version=2`) and auto-selects compatible file from `GAMEFILE`, `gamefile.bin`, `gameplay.bin`.

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
- Use `--same-machine` from worker/GUI so the local LAN discovery loopback bridge is enabled.
- If local client still cannot find/join, test a non-default `PORT` instead of `9900` to avoid client/server UDP bind conflicts in some patch sets.

## Preflight validation

Before launch, native UI now performs profile-aware `server.cfg` validation and blocks start on critical issues (for example wrong lobby ident for selected game profile, invalid `PORT`, invalid `U2_START_MODE`).

Native UI also now enforces strict local conflict checks before launch:

- blocks if UDP `9999` is already occupied
- blocks if configured service `PORT` is already occupied (UDP/TCP)
- blocks if another NFSLAN instance already owns the same identity (`LOBBY_IDENT` + `PORT`)

Worker runtime also acquires the same identity lock, so duplicate same-profile/same-port launches are rejected even outside GUI preflight.

## Notes on stopping

- GUI stop terminates worker process.
- If worker does not exit cleanly, process is force-terminated.

## Relay app (`NFSLAN-Relay`)

Use relay when clients/servers are on different subnets and game LAN discovery broadcast (`UDP 9999`) does not cross routing boundaries.

In `NFSLAN-GUI` builds with embedded relay, open it from the `Relay tool` button (same EXE, launched with `--relay-ui`).

### When to use

- Cross-subnet LAN with routers/firewalls between players
- VPN-linked sites where broadcast does not traverse as expected
- Internet tests where you want explicit discovery forwarding behavior

### Start relay

1. Open `NFSLAN-Relay.exe`.
2. Choose mode:
   - `Transparent spoof (VPN/LAN, admin)`: forwards with original source IP (closest to legacy relay behavior).
   - `Fixed source spoof (-e style, admin)`: forwards with manually configured source IPv4.
   - `No spoof (compat mode, no admin)`: normal UDP forward without raw packet spoofing.
3. Set `Listen UDP port` (default `9999`) and `Target UDP port` (default `9999`).
4. Enter peer IPv4 addresses (one per line).
5. If using fixed-source mode, provide `Fixed source IPv4`.
6. Click `Start Relay`.

### Notes

- Spoof modes require running the app as Administrator on Windows because raw sockets + `IP_HDRINCL` are used.
- Relay only handles discovery forwarding. Once players discover each other, game traffic still depends on normal host/client connectivity and required forwarded ports.
- Start with `No spoof` mode for first diagnostics, then move to spoof mode if discovery still fails.
