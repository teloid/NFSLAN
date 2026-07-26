# LAN protocol notes

What the games put on the wire. Field layouts here were read out of the stock
`server.dll` and game EXE decompiles, then verified byte-for-byte against a
running `nfslan-server`. Where something is still a guess, it says so.

This covers **discovery** in full — everything needed for a server to appear in
the LAN list and advertise where to connect — plus the lobby **connect
handshake**, which is implemented and verified against both retail games. The
persona/room/game layer after that is not implemented; see
[Open questions](#open-questions).

Citations point into Ghidra decompiles of the games' own `server.dll` and
executables. Those are deliberately **not** in this repository (it ships no game
code); the line numbers are provenance for anyone working from their own copy.

## Ports

| Port | Transport | Used for |
| --- | --- | --- |
| 9999 | UDP | LAN discovery: beacons and queries, broadcast. **Hardcoded in both the game and `server.dll`** — a real client never looks elsewhere. |
| 9900 | TCP | Lobby/session (`PORT` in `server.cfg`, default `0x26AC`). Advertised inside the beacon. |
| 9901 | UDP | `LOCAL?` locality challenge. Project-specific, Most Wanted path only, needs a client-side plugin. |

Discovery always leaves from source port 9999 and goes to `255.255.255.255:9999`.

## The beacon

A server announces itself with exactly **0x180 (384) bytes** on UDP 9999. The
field widths come from the stock receiver's own stack layout, which partitions
the packet exactly: `4 + 4 + 0x20 + 0x20 + 0xC0 + 0x78 = 0x180`.

```
offset  size  contents
0x000   3     'g' 'E' 'A'
0x003   1     re-advertise interval, seconds (stock sends 3)
0x004   4     ad-instance id
0x008   0x20  ident, ASCII + NUL      "NFSU2NA", "NFSMWNA", ...
0x028   0x20  server name, ASCII + NUL
0x048   0xC0  stats, ASCII            "<port>|<players>", e.g. "9900|0"
0x108   0x78  transport, ASCII        "TCP:~1:1024\tUDP:~1:1024"
0x148   0x38  zero
```

Things that are easy to get wrong, and were:

- **Byte 3 is not a message type.** It is the re-advertise interval in seconds,
  and **stock receivers never validate it**. Rejecting anything other than `3`
  (as an earlier version of this code did, and as `NFSLAN.cpp`'s
  `LooksLikeUg2LanBeacon` still does) drops legitimate beacons. The library
  clamps the value: `0` becomes 30, `1` becomes 2, and anything above 250 becomes
  250.
- **It also drives expiry.** A receiver holds a row until
  `arrival + 1000 + interval * 2000` ms — 7 seconds for the stock interval of 3.
- **The second half of `stats` is the live player count**, not a flag. Stock
  servers re-emit the beacon whenever the count changes, or every 3000 ms
  otherwise.
- **The transport field contains a literal TAB** (0x09) between the TCP and UDP
  clauses. A decoder whose field alphabet is "printable ASCII" stops at the tab
  and silently truncates — a real bug the test suite caught here.
- **An empty transport field means "withdrawn."** Receivers drop the row
  immediately, and stock servers send exactly that as a goodbye on shutdown.
  `encodeWithdrawal()` does this; never send an empty transport otherwise.
- **The ident field is 0x20 bytes, not 8.** All four known idents are short, so
  this rarely bites, but rewriting a longer ident into an 8-byte field truncates.
- **Comparisons are case-insensitive.** Stock receivers fold case on ident, name,
  and stats when matching rows.
- **The beacon carries no server address.** Clients connect back to the packet's
  source address. Any relay must therefore forward session traffic too, or
  clients will dial the relay instead of the server.

The ad-instance id at `0x004` appears to be uninitialised heap in stock builds —
allocated without zeroing, and read before the field it is derived from is set.
It stays constant for an ad's lifetime and receivers include it in a row's
identity. Sending zeros works.

## Queries

A client discovers servers by broadcasting a query to UDP 9999 — the same
0x180-byte envelope with `'?'` at offset 0x008 and byte 3 left at zero:

```
0x000   'g' 'E' 'A'
0x008   '?'
        (rest zero)
```

The receive-side rules, in the stock order:

1. Accept if bytes 0..2 are `'g' 'E' 'A'`. Byte 3 is **not** checked.
2. If the ident field is exactly `"?"`, it is a **query**.
3. Else if the name field at 0x028 is non-empty, it is an **announcement**.
4. Else ignore.

That is why `isBeacon()` tests for a non-empty name rather than for a known ident
prefix: an unfamiliar ident is still a server the game would list.

**Stock servers do not unicast a reply to a query.** They pull every local ad's
next send forward to `now + 1000` ms and re-broadcast on the next poll, so
worst-case discovery latency is about a second. Passive listening also works,
since ads repeat every 3 seconds. `nfslan-server` additionally unicasts the
beacon straight back to the querier — a superset of stock behaviour, and what
makes same-machine discovery reliable.

## `LOBBY_IDENT` — why servers go invisible

The ident is a **protocol identifier, not a display name**. Clients filter the
LAN list on it and hide non-matching servers with no message at all.

| Ident | Build |
| --- | --- |
| `NFSU2NA` | Underground 2, North American |
| `NFSU2` | Underground 2, some RU/EU releases |
| `NFSMWNA` | Most Wanted, North American |
| `NFSMW` | Most Wanted, other releases |

Both sides choose their ident from a build-baked value, which is the root of the
whole problem:

- **Server:** stock `server.dll` builds the ident from the `StartServer` *mode*
  argument — `0` yields `NFSU2NA`, non-zero yields `NFSU2`. **`server.cfg` does
  not control it.** This is exactly why the Windows worker hooks `sendto` and
  rewrites the ident on the way out, and why editing `server.cfg` alone can look
  like it does nothing.
- **Client:** the EXE picks `NFSU2NA` when its region global is 0, else `NFSU2`
  (`NFSMWNA`/`NFSMW` for Most Wanted). Two copies of the same game can therefore
  disagree.

`nfslan-server` sets the ident directly, so `--ident` is authoritative. To
discover what a particular client expects, run `nfslan-server --discover` on that
machine, or capture `udp.port == 9999` and read the ASCII at offset 0x008.

Unexplained literals `NFSU2SD` and `NFSMWSD` also exist in the client binaries;
their role is unknown.

Rewriting an ident in place must clear the whole field first, or changing
`NFSU2NA` to `NFSU2` leaves a trailing `NA`. See `rewriteBeaconIdent()`.

## Same-machine play

Broadcast alone is unreliable when client and server share a machine: the game
may bind UDP 9999 first, and a broadcast a process sends is not necessarily
delivered back to itself. `nfslan-server` handles the network half by setting
`SO_REUSEADDR` (plus `SO_REUSEPORT` on macOS/BSD) before `bind()`, and by
announcing to `127.0.0.1` explicitly.

The remaining half is client-side: stock clients set a **self filter** flag on
any row whose sender address equals their own, and hide it. Clearing that needs
the Windows worker's game patcher, which pokes the client's discovery table
(`+0x19C` on a 0x1A4-byte row; manager singleton at RVA `0x004B7E28` for U2,
`0x005C3878` for MW).

## Lobby / session (TCP 9900) — handshake works, session does not

The framing and the connect handshake are implemented and **verified against a
real Underground 2 client** (retail 1.2, `SKU=14705`, running under Proton on a
Steam Deck, talking to `nfslan-server` on macOS). The client gets past
"connecting to lobby" and sits on the LAN Main screen. Entering the lobby proper
still fails, because the persona/room/game layer is not implemented.

Most Wanted follows the same path and gets **further** than Underground 2: it
reaches the "Create New Persona" screen and then waits on "Creating persona…".
Its parameter block differs only in the expected places — `PROD=nfs-pc-2006`,
`VERS="pc/1.3-Nov 21 2005"`, `SLUS=SLUS_21351`, `NETV=20` (U2 sends 40) — and it
skips the `sele` step that U2 sends. Creating a persona folds the name into the
`auth` request rather than a separate verb:

```
client -> auth  REGN=NA CLST=194010 NETV=20 ... SDKVERS=3.9.3.0
                NAME=<persona> REGKEY= MAC=$<mac> PASS=<persona> MASK=0
```

This matches the note in the fork's own README that Most Wanted is the less
strict of the two.

### The exchange, as observed on the wire

```
client -> @tic  "RC4+MD5-V2"
server -> @tic  code 0, empty body          # not 84 bytes, so crypto stays off
client -> @dir  REGN=NA CLST=126890 NETV=40 FROM=US LANG=EN
                MID=$b00c9da60aaf PROD=nfs-pc-2005
                VERS="pc/1.2-Feb  9 2005" SLUS=SLUS_21065 SKU=14705
server -> @dir  code 0, ADDR=<server ip>\tPORT=9900
                                            # client DISCONNECTS here
                                            # and reconnects to that address
client -> addr  ADDR=<its own ip> PORT=<its own port>
server -> addr  code 0
client -> skey  SKEY=$5075626c6963204b6579   # hex for "Public Key"
server -> skey  code 0
client -> news  NAME=7
client -> sele  MYGAME=1 STATS=5000 ASYNC=1 MESGS=1
client -> auth  <the same parameter block as @dir>
```

Two things worth knowing before implementing further:

- **The client's own request bodies use `\n` separators**, even though the spec
  and stock servers emit TAB. The parser treats any byte below 0x21 as a
  separator, so both work — but emit TAB to stay faithful.
- **The redirect is mandatory and it really does reconnect.** Answering `@dir`
  with `ADDR=0` (or not answering) is what produces the classic "server is down"
  behaviour, and is the same failure the Windows worker patches around for Most
  Wanted by rewriting `DOWN=`/`IDOWN=` bodies.

### What the client reads out of each reply

From the U2 client's state machine (`SPEEDEXE/SPEEDEXE.c` around 615929-615990),
each of these reads has a **default** argument, so a missing key yields the
default rather than a hard failure — which is why bare `code 0` acks get the
client as far as they do:

| Reply | Client reads |
| --- | --- |
| `auth` | a 20-byte (0x14) string field, and an address field |
| `sele` | a number, then `SLOTS`, then `STATS` |
| `pers` | a 16-byte (0x10) name field |
| `acct` | nothing; success just advances the state to `acct` |
| `snap` | decrements a pending counter, reads one number |

Tags beginning `+` (e.g. `+usr`, `+gam`, `+rom`) are async notifications the
server pushes; tags beginning `$` are a second async class.

### Finishing this

The remaining work is the persona/room/game layer: replying to `auth` with the
fields above, then handling persona selection, room listing, and game creation
(`+gam`/`+usr`/`+rom` pushes). Server-side handlers are documented in
`SERVER/U2/server.dll.c` — the create-game path at 19809-20191 is the most
useful entry point, including its error vocabulary (`maut`, `ingm`, `urom`,
`filt`, `dupl`, `nown`).

### Never fake a success

Replying `code 0` to a request the server cannot actually fulfil **hangs the
game**: the client believes the operation is underway and blocks waiting for a
result that never arrives, and backing out of the menu with that request
outstanding deadlocks the UI. Observed with Most Wanted, which froze on the way
back to the main menu after being told persona creation had succeeded.

So the default for an unmapped verb is a clean failure: reply with the request's
own tag and a non-zero 4CC error code (`nfnd`), and put a human-readable message
in the body — the client displays it and backs out. Stock error codes include
`nfnd`, `miss`, `uusr`, `maut`, `ingm`, `urom`, `filt`, `dupl` and `nown`.

`nfslan-server --ack-unknown` opts back into the fake-success behaviour, because
it is the only way to make the client reveal what it would ask next. It is a
discovery tool only, and it can hang the game — which is why it is not the
default.

## Titan framing reference

Messages use EA's "Titan" framing: a 12-byte header, **big-endian**, then an
ASCII body.

```
[0..3]   4-char ASCII tag, e.g. '@dir', '@tic', '@cnt', '@alv',
                              'SLAV', 'TERM', 'PING', 'PERS',
                              '*put', '*gst', '*fgt', '*sdp', '+uss'
[4..7]   u32  transaction / result word (usually 0)
[8..11]  u32  total length = 12 + body length
[12..]   body: "KEY=VALUE\n" lines, NUL-terminated by the receiver
```

Known behaviour: a `@dir` response whose body contains `DOWN=` or `IDOWN=` makes
a Most Wanted client treat a reachable server as down. The Windows worker rewrites
such bodies in place to `ADDR=<addr>\nPORT=<port>\n`, preserving the total length.

The connect sequence **is** mapped and implemented — see "The exchange, as
observed on the wire" above. What remains is the persona/account layer that
follows it.

To capture a client's traffic for that work:

```bash
nfslan-server --capture lobby.txt
```

## Open questions

- **The lobby handshake.** See above. Highest-value unknown.
- **Whether a stats change forces a withdraw/recreate cycle.** The update path
  zeroes the expiry field after copying changed stats, and expiry `0` is the
  withdraw trigger — implying every player-count change emits a goodbye and
  re-creates the ad (which would make LAN rows blink). The decompiled comparison's
  branch sense is ambiguous. Settle it by capturing UDP 9999 while a player joins.
- **Whether clients parse the transport string or only check it is non-empty.**
  Non-empty is proven load-bearing; the `~1:1024` numbers were not traced. The
  portable server sends the stock string verbatim.
- **Whether the name field is matched against anything** or is purely display
  text. It is part of the receive-side row identity, so renaming mid-session
  creates a second row.
- **The full region-code mapping** behind the client's ident choice, including
  what `NFSU2SD` / `NFSMWSD` are for. Until that is known, `--ident` stays
  trial-and-error.
- **U2 start modes 1..13.** In U2's `server.dll` the mode argument is stored once
  and read once, and only `!= 0` matters — its sole effect is choosing `NFSU2`
  over `NFSU2NA`. The worker's 0..13 knob is effectively a boolean. Worth
  re-checking against a second `server.dll` build.
- **The `LOCAL?` responder.** The challenge (`0x6A093EC9` = `bStringHash("LOCAL?")`,
  expected reply `0x8DB682D1` = `bStringHash("YESIMLOCAL")`, hash is
  `h = 0xFFFFFFFF; h = h * 33 + c`) is sent as four raw little-endian bytes with
  no header. No responder exists in this repository, so the reply framing is
  inferred from the sender only.
