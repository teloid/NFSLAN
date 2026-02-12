# Client and Internet Setup

## Scope and limitation

This repository contains the server launcher/manager. It does not include client patch files for MW/UG2.

For internet play, each client still needs a compatible client patch/mod setup for their exact game executable/version.

Runtime note:

- Windows native GUI is available without Qt runtime.
- Embedded single-EXE mode is x86/Win32 only.
- Native x64 GUI mode uses external `NFSLAN.exe` worker.
- Native Linux/macOS GUI mode still needs a Windows worker executable for the runtime command path.

## Server-side checklist (both games)

1. Create one server directory per game.
2. Copy matching game files into that directory:
   - `server.dll`
   - `server.cfg`
3. Set at least these values in `server.cfg`:
   - `PORT=<public port>` (commonly `9900`)
   - `ADDR=<public server IP or DNS name>`
   - `LOBBY_IDENT=<game lobby ident>` (`NFSMWNA` for MW, `NFSU2NA` for UG2 if missing)
   - `LOBBY=<game lobby ident>` (`NFSMWNA` for MW, `NFSU2NA` for UG2 if missing)
   - `ENABLE_GAME_ADDR_FIXUPS=1` (recommended)
   - `U2_START_MODE=0` for UG2 unless you intentionally need another mode (`0..13`)
   - `LAN_DIAG=1` only while troubleshooting discovery/join issues (verbose logs)
   - `GAMEFILE=<valid game report file>` (must match header expected by server.dll)
4. Open/forward your server UDP port in firewall/router (at least the `PORT` value).
5. Start the matching GUI profile:
   - `Need for Speed Most Wanted (2005)` with MW `server.dll`
   - `Need for Speed Underground 2` with UG2 `server.dll`
6. Confirm logs do not advertise private-only slave address for internet clients.
   - Example bad for internet clients: `addr=192.168.x.x:9900`
   - Fix: set `ADDR` to public IP or DNS in `server.cfg`

## Host plays on same machine

If the server host also runs the game client on the same PC:

1. Enable `FORCE_LOCAL=1` in `server.cfg` (or via native GUI `Same-machine mode`, which also sets `ADDR=127.0.0.1`).
2. Keep `ENABLE_GAME_ADDR_FIXUPS=1`.
3. For Underground 2, use native UI `UG2 Same-PC` button (recommended) or run `NFSLAN-U2-Patcher.exe` manually while playing/hosting on the same machine.
4. If UG2 server list is still empty, enable synthetic beacon fallback (`UG2_BEACON_EMULATION=1` or worker `--ug2-beacon-emu`).
5. For discovery-only verification without `server.dll`, run worker with `--beacon-only`.
6. If client still cannot join, test a server `PORT` other than `9900`.
7. Start the server with `--same-machine` when using console worker directly.
8. In `--same-machine` mode, worker enables a local LAN discovery loopback bridge on UDP `9999`.
9. For deeper packet troubleshooting, launch with `--diag-lan` (or set `LAN_DIAG=1`).

## Game-specific notes

### Most Wanted (2005)

- Worker patching for MW exists in this project and is enabled by default.
- Keep patching enabled unless you are troubleshooting (`-n` checkbox disables it).

### Underground 2

- UG2 patching is not implemented in current worker code (`PatchServerUG2` is still a stub).
- LAN hosting can still start, but internet behavior may require additional external patches/tools.
- Worker normalizes UG2 config keys (`MADDR/RADDR/AADDR`, `MPORT/RPORT/APORT`) from `ADDR/PORT` when missing.
- Worker now keeps outgoing UG2 discovery beacons close to stock server behavior (no forced field rewrites).
- Same-machine visibility issue is primarily client-side (`speed2.exe` self-filter), handled by `NFSLAN-U2-Patcher`.

## Client requirements for internet play (known from current reverse engineering)

These are known expectations from the existing worker patch logic:

- Client should report public IP data in SKU flow (LanIP-style behavior).
- Client should expose a UDP responder on port `9901` for local challenge checks.
- Client may need a patch to skip client game UDP bind conflict.
- Client may need a patch that ignores slave-server returned IP and keeps the public endpoint.

This repository does not ship those client patches.

## What game files usually need updates on client side

Exact file names depend on the client patch package you use. Usually one of these is modified:

- game executable patch (MW/UG2 EXE)
- plugin/ASI module loaded by the game
- patch config INI/JSON for server address overrides

If your patch package uses hostnames, update OS hosts mapping to your public server IP.

- Windows hosts file: `C:\Windows\System32\drivers\etc\hosts`
- Linux hosts file: `/etc/hosts`
- macOS hosts file: `/etc/hosts`

Use hostnames required by your chosen client patch package (they are not defined in this repository).

## Internet troubleshooting quick checks

1. Verify server logs in `NFSLAN-GUI` show clean startup and expected build/runtime diagnostics (build tag + executable path + profile).
2. If server is still invisible, enable `LAN_DIAG=1` and compare `LAN-DIAG` beacon logs (ident/stats/name) with packet capture.
   - Use relay capture diff report to confirm packet-level similarity and check heuristic diagnosis.
3. Confirm firewall/router forwarding to the server machine for your configured UDP port(s).
4. Confirm all players use the same game version + same client patch package.
5. Confirm public IP/DNS in `server.cfg` (`ADDR`) is reachable from outside your LAN.
