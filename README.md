# NFSLAN

Run a **Need for Speed Underground 2 / Most Wanted LAN server as its own process** — instead of relying on the game to host one.

Some retail and repack builds can't spawn a server at all, and others spawn one that nobody else can see. This project fixes both cases: it runs the game's own `server.dll` outside the game (so hosting works even when the in-game option doesn't), and it ships a portable standalone server that makes a host **visible** to clients whose build would otherwise filter it out.

And because the ports for this game are documented essentially nowhere: **[they're all right here](#ports--firewall).**

---

## Which piece do I want?

| I want to… | Use | Runs on |
| --- | --- | --- |
| Actually host a game, with same-PC join | **Windows worker + GUI** | Windows (x86 build) |
| Make a server appear in a client that can't see servers | **`nfslan-server`** | macOS, Linux, Windows — any CPU |
| Find out what's on the LAN / which ident a client wants | **`nfslan-server --discover`** | macOS, Linux, Windows |

The two halves are independent. The worker hosts the real `server.dll` and can run
a full session. `nfslan-server` speaks the LAN discovery protocol natively — no
`server.dll`, no Wine, no x86 — and is the tool for diagnosing and fixing
visibility problems. It does **not** yet run a session (see [Status](#status)).

---

## Quick start

### Windows — host a game (recommended)

1. Grab `NFSLAN-GUI.exe` from a [release](../../releases), or [build it](docs/BUILD.md).
2. Run it **as Administrator**.
3. Pick the game (Underground 2 / Most Wanted).
4. Set **Game folder** — the folder holding the game EXE plus `server.dll` and
   `server.cfg` (U2: `SPEED2.EXE`, MW: `speed.exe`).
5. Type a server name and press **Start Bundle (Recommended)**.

The game launches patched so you can join your own server from the same PC. Open
the LAN server list and connect.

Only `server.dll` needs to be present in that folder — it ships with the game.

### macOS / Linux / Windows — make a server visible

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/bin/nfslan-server --name "Living Room" --game u2
```

```
nfslan-server running
  game        Underground2
  name        Living Room
  ident       NFSU2NA
  address     192.168.1.10
  discovery   UDP 9999, announcing every 1000 ms
  lobby       TCP 9900, capture mode
```

The server now appears in the game's LAN list on any machine on the same network.

### See what's actually on the LAN

```bash
./build/bin/nfslan-server --discover 10
```

```
Listening for NFS LAN servers on UDP 9999 for 10 seconds...
  Living Room              ident=NFSU2NA  port=9900  from 192.168.1.10
```

This is the fastest way to answer "is anything advertising, and under which
ident?" — run it on the machine that can't see servers.

---

## Ports & firewall

Every port this game and this project use. **Nothing else is needed.**

| Port | Protocol | Direction | Required? | What it is |
| --- | --- | --- | --- | --- |
| **9999** | UDP | in + out, **broadcast** | **Yes** | LAN discovery. Beacons and `?` queries. Hardcoded in both the game and `server.dll` — **not configurable**, don't try. |
| **9900** | TCP | inbound | **Yes** | Lobby / session. This is `PORT` in `server.cfg`; change it there and the beacon advertises the new value automatically. |
| 9901 | UDP | in + out | No | Optional same-PC/locality check (`LOCAL?`). Only used by the Windows worker on the Most Wanted path. |

Notes that trip people up:

- **UDP 9999 must allow broadcast**, not just unicast. Discovery is sent to
  `255.255.255.255:9999` and to each interface's broadcast address. A firewall
  that permits only established/unicast UDP will silently hide every server.
- The beacon **does not contain the server's address** — clients connect back to
  the packet's source address. So the host must be directly reachable; NAT
  between client and server breaks joining even when discovery works.
- `9999` is fixed in the retail binaries on **both** sides. `--discovery-port`
  exists for local plumbing and testing only; a real client will never look
  anywhere else.

### Windows Firewall

Run in an **Administrator** PowerShell. Adjust the program paths to yours.

```powershell
New-NetFirewallRule -DisplayName "NFSLAN discovery (UDP 9999)" -Direction Inbound -Protocol UDP -LocalPort 9999 -Action Allow
New-NetFirewallRule -DisplayName "NFSLAN lobby (TCP 9900)" -Direction Inbound -Protocol TCP -LocalPort 9900 -Action Allow
```

Also allow the executables themselves, which is what Windows actually prompts
about:

```powershell
New-NetFirewallRule -DisplayName "NFSLAN worker" -Direction Inbound -Program "C:\path\to\NFSLAN.exe" -Action Allow
New-NetFirewallRule -DisplayName "NFS Underground 2" -Direction Inbound -Program "C:\Games\NFSU2\SPEED2.EXE" -Action Allow
```

To remove them later:

```powershell
Get-NetFirewallRule -DisplayName "NFSLAN*" | Remove-NetFirewallRule
```

Check whether a rule is actually the problem by temporarily allowing everything
on the private profile — if the server appears, it was the firewall:

```powershell
Set-NetFirewallProfile -Profile Private -Enabled False
```

(Turn it back on with `-Enabled True` when you're done.)

### macOS

The built-in firewall may block inbound UDP to an unsigned binary, which stops
clients' queries from arriving. Outbound announcements still go out, so servers
usually appear anyway. If not: **System Settings → Network → Firewall → Options**
→ allow `nfslan-server`.

### Linux

```bash
sudo ufw allow 9999/udp
sudo ufw allow 9900/tcp
```

```bash
sudo firewall-cmd --add-port=9999/udp --add-port=9900/tcp --permanent && sudo firewall-cmd --reload
```

---

## My server doesn't show up

In order of how often it's the cause:

**1. `LOBBY_IDENT` doesn't match the client's build.** This is nearly always it.
The ident is a protocol tag, *not* the display name, and a client silently hides
every server whose ident it doesn't recognise — no error, no empty-list message.

| Ident | Build |
| --- | --- |
| `NFSU2NA` | Underground 2, North American |
| `NFSU2` | Underground 2, some RU/EU releases |
| `NFSMWNA` | Most Wanted, North American |
| `NFSMW` | Most Wanted, other releases |

The client picks its expected ident from a region value baked into the EXE, so
**two copies of the same game can disagree.** Find out what yours wants:

```bash
nfslan-server --discover 15     # on the machine that can't see servers
```

…then match it:

```bash
nfslan-server --name "Living Room" --ident NFSU2
```

For the Windows worker, set it in `server.cfg`:

```ini
LOBBY_IDENT=NFSU2NA
LOBBY=NFSU2NA
```

Careful: stock `server.dll` derives the ident from a **start-mode argument**, not
from `server.cfg` — mode `0` gives `NFSU2NA`, anything else gives `NFSU2`. That's
precisely why the worker has to rewrite it on the way out, and why editing
`server.cfg` alone sometimes appears to do nothing.

**2. UDP 9999 broadcast is blocked.** See [Ports & firewall](#ports--firewall).

**3. Client and server aren't on the same broadcast domain.** Different subnets,
guest/AP isolation on the Wi-Fi, a VPN capturing the default route, or Docker
bridge networks all break discovery. Wired and wireless on the *same* router are
usually fine; "Guest network" almost never is.

**4. Same-PC play needs the loopback path.** `nfslan-server` announces to
`127.0.0.1` by default. Stock clients also deliberately hide servers that look
like they came from the client itself; defeating that needs the Windows worker's
game patcher (`Start Bundle`).

---

## `nfslan-server` options

```
--name <text>          Server name shown in the LAN list
--game <u2|mw>         Which game to advertise (default: u2)
--ident <IDENT>        Protocol ident; defaults from --game
--port <n>             Lobby port to advertise (default: 9900)
--addr <ip>            Address to advertise (default: auto-detect)
--config <path>        Read a server.cfg (default: ./server.cfg if present)
--interval <ms>        Beacon announce interval (default: 1000)
--no-broadcast         Only answer queries; never announce unsolicited
--no-loopback          Don't announce to 127.0.0.1 (breaks same-PC visibility)
--discover [secs]      List servers on the LAN instead of serving
--capture <path>       Log the lobby handshake as a hex dump
--verbose              Log every packet decision
```

A stock `server.cfg` works unchanged — unknown keys are ignored, and `PORT`,
`ADDR`, `LOBBY_IDENT`, and `LOBBY` are honoured. Command-line flags win over the
file.

---

## Status

**Works today**

- LAN discovery, fully: beacon encode/decode at the real field offsets, `?`
  queries answered, periodic announcements, and a goodbye beacon on shutdown so
  the row disappears from clients immediately instead of lingering.
- Live player count in the advertised stats.
- Cross-region ident rewriting — the fix for invisible servers.
- Native builds on macOS (Apple Silicon and Intel), Linux, and Windows, with no
  `server.dll` and no x86 requirement.
- The Windows worker + GUI path for actual gameplay, unchanged.

**Not done yet**

- `nfslan-server` does not run a *session*. The lobby protocol on TCP 9900 (EA's
  "Titan" framing) isn't implemented, so a client that picks a native server
  reaches "connecting to lobby" and stops. `--capture` records exactly what the
  client sends, which is how that gets finished — contributions very welcome.
- Use the **Windows worker** for real matches.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the wire format, including what is
verified and what is still guesswork.

---

## Documentation

- [docs/BUILD.md](docs/BUILD.md) — build matrix for every platform
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — the wire format, field by field
- [docs/RUNNING.md](docs/RUNNING.md) — runtime usage and the GUI flow
- [docs/CLIENT_SETUP.md](docs/CLIENT_SETUP.md) — client and network setup
- [docs/U2_PATCHER.md](docs/U2_PATCHER.md) — same-PC join patcher behaviour
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the pieces fit together

## Building

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Needs a C++20 compiler and CMake 3.21+. Nothing else. Full matrix, including the
Windows single-EXE build, in [docs/BUILD.md](docs/BUILD.md).

## Legal

NFSLAN ships **no game code and no game assets**. `server.dll` comes from your
own copy of the game. Underground 2 and Most Wanted are © Electronic Arts; this
project is unaffiliated with and unendorsed by EA.

Licensed under the terms in [LICENSE](LICENSE).

## Credits

- `injector` and `Hooking.Patterns` by aap / Silent, under their own licenses.
- The `Network.h` UDP wrapper originated from a Stack Overflow answer by Peter R,
  adapted by Xan / Tenjoin. The portable replacement in `core/` is new code.
- Looking for **online** play rather than LAN? See
  [NFSOR](https://discord.gg/BB27nMjSCp), an official-server revival project for
  PS2 and PC.
