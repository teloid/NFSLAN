# Client and Internet Setup

## Scope and limitation

This repository contains the server launcher/manager. It does not include client patch files for MW/UG2.

For internet play, each client still needs a compatible client patch/mod setup for their exact game executable/version.

Runtime note:

- Windows default build is single-EXE (GUI + embedded worker).
- Native Linux/macOS GUI mode still needs a Windows worker executable for the runtime command path.

## Server-side checklist (both games)

1. Create one server directory per game.
2. Copy matching game files into that directory:
   - `server.dll`
   - `server.cfg`
3. Set at least these values in `server.cfg`:
   - `PORT=<public port>` (commonly `9900`)
   - `ADDR=<public server IP or DNS name>`
4. Open/forward your server UDP port in firewall/router (at least the `PORT` value).
5. Start the matching GUI profile:
   - `Need for Speed Most Wanted (2005)` with MW `server.dll`
   - `Need for Speed Underground 2` with UG2 `server.dll`

## Game-specific notes

### Most Wanted (2005)

- Worker patching for MW exists in this project and is enabled by default.
- Keep patching enabled unless you are troubleshooting (`-n` checkbox disables it).

### Underground 2

- UG2 patching is not implemented in current worker code (`PatchServerUG2` is still a stub).
- LAN hosting can still start, but internet behavior may require additional external patches/tools.

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

1. Verify server logs in `NFSLAN-GUI` show clean startup.
2. Confirm firewall/router forwarding to the server machine for your configured UDP port(s).
3. Confirm all players use the same game version + same client patch package.
4. Confirm public IP/DNS in `server.cfg` (`ADDR`) is reachable from outside your LAN.
