# Client and Network Setup (U2)

This release is focused on Underground 2 standalone server + same-PC join support.

## Minimum server config

In `server.cfg` (launcher also normalizes these):

- `PORT=9900` (or your chosen port)
- `ADDR=<host ip>`
- `LOBBY_IDENT=NFSU2NA`
- `LOBBY=NFSU2NA`
- `U2_START_MODE=0`

## Same-PC host + client

Use `UG2 Bundle (Recommended)` from GUI.

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
