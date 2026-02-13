# Client and Network Setup (U2 + MW)

This release is focused on standalone server + same-PC join support for U2 and MW.

## Minimum server config

In `server.cfg` (launcher also normalizes these):

- `PORT=9900` (or your chosen port)
- `ADDR=<host ip>`
- `LOBBY_IDENT=<protocol id>` (must match your client build/region)
- `LOBBY=<protocol id>` (must match `LOBBY_IDENT`)
- `U2_START_MODE=0` (U2 only)

Common IDs:

- U2 (NA builds): `NFSU2NA`
- MW (NA builds): `NFSMWNA`

Notes:

- `LOBBY_IDENT` must match the selected game (must start with `NFSU2` for Underground 2, `NFSMW` for Most Wanted).
- The exact suffix can vary by build/region (for example `...NA`, `...EU`).

If one platform/build cannot see the server (e.g., SteamOS vs Windows), capture `udp.port == 9999` on the client and look at the ASCII ID in the beacon payload (8-byte field). Use that value for `LOBBY_IDENT`/`LOBBY`.

## Same-PC host + client

Use `Start Bundle (Recommended)` from GUI.

This is the intended path for:

- standalone worker host
- game client on same machine
- visible server row in U2 list
- join attempts routed to real worker endpoint

## Internet hosting checklist

1. Set `ADDR` to the host address clients can reach.
2. Forward/open configured server `PORT`.
3. Keep host firewall rules open for worker and game traffic.
4. Make sure clients use compatible game build/patch setup.

## Diagnostics

If join fails:

1. Confirm worker process is running and listening on `PORT`.
2. Confirm patcher log shows active loop and injection target.
3. Capture traffic on `tcp.port == 9900` and verify bidirectional payload (not only SYN/ACK).
4. Check GUI log for preflight errors and server runtime warnings.

## Verify normal LAN clients

1. Start server host on PC-A with `ADDR=<PC-A LAN IPv4>` and `PORT=9900`.
2. On PC-B (same subnet), open the LAN browser in the same game and locate the server row.
3. Join from PC-B and confirm on host:
   - `netstat -ano | findstr :9900` shows established client sessions
   - GUI `Live events` shows connection/lifecycle entries
4. Start a race from lobby and confirm both:
   - in-game transition succeeds for all clients
   - GUI `Live events` receives race-related lines (when emitted by server logs)
5. Run for 10+ minutes and watch for:
   - disconnect loops
   - repeated TCP resets on `9900`
   - port rebind failures after stop/start
