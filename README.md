# NFSLAN

Run a **Need for Speed Underground 2 / Most Wanted LAN server as its own process** — instead of relying on the game to host one.

Some retail and repack builds can't spawn a server at all, and others spawn one that nobody else can see. This project fixes both: it can run the game's own `server.dll` outside the game, and it ships a portable standalone server that makes a host **visible** to clients whose build would otherwise filter it out.

And because the ports for this game are documented essentially nowhere: **[they're all right here](#ports--firewall).**

Everything is a plain CMake build — one command, no IDE, no dependencies.

---

## Which piece do I want?

| I want to… | Use | Runs on |
| --- | --- | --- |
| Make a server appear in a client that can't see servers | **`nfslan-server`** | macOS, Linux, Windows — any CPU |
| Find out what's on the LAN / which ident a client wants | **`nfslan-server --discover`** | macOS, Linux, Windows |
| Actually host a race, with same-PC join | **`NFSLAN-GUI.exe`** (or the `NFSLAN.exe` worker) | Windows, x86 build |

`nfslan-server` speaks the LAN protocol itself — no `server.dll`, no Wine, no x86 — and is the tool for diagnosing and fixing visibility problems. It can carry a real client through the connect handshake, but **cannot run a race yet**; see [Status](#status).

The worker hosts the game's real `server.dll` and runs full sessions, and comes with a Windows GUI that wraps it in a single executable.

## Downloads

Grab a [release](../../releases) — each download is one self-contained file, no installer:

| File | For |
| --- | --- |
| `nfslan-server-macos-universal` | macOS 11+, Apple Silicon and Intel |
| `nfslan-server-linux-x86_64` | Linux x86_64 (glibc 2.17+, so anything modern) |
| `nfslan-server-windows-x64.exe` | Windows x64 — no runtime to install |

On macOS and Linux, mark it executable first: `chmod +x nfslan-server-*`.

### macOS: "cannot be opened because it is from an unidentified developer"

Expected. The binary is not signed with an Apple Developer ID or notarized —
that needs a paid Apple account, which this project does not have. The file is
fine; macOS just cannot vouch for it.

One command clears it:

```bash
chmod +x nfslan-server-macos-universal
xattr -d com.apple.quarantine nfslan-server-macos-universal
```

Or without the terminal: **right-click the file → Open → Open**. Note that
*double-clicking* will always be refused — only the right-click route offers the
override. You can also allow it after the fact in **System Settings → Privacy &
Security**, where it appears as "was blocked".

If `xattr` reports "No such xattr", the file was never quarantined — just run it.

`NFSLAN-GUI.exe` (for hosting an actual race) is **not** published yet — it has to
be built with MSVC on Windows, because the worker it embeds uses MSVC-only inline
assembly. See [docs/WINDOWS.md](docs/WINDOWS.md); it is two commands.

---

## Quick start

### Any platform — build and run the standalone server

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
  lobby       TCP 9900, answering handshake
```

The server now appears in the game's LAN list on any machine on the same network. For Most Wanted use `--game mw`.

Needs only a C++20 compiler and CMake 3.21+. No Qt, no external dependencies.

### See what's actually on the LAN

```bash
./build/bin/nfslan-server --discover 10
```

```
Listening for NFS LAN servers on UDP 9999 for 10 seconds...
  Living Room              ident=NFSU2NA  port=9900  from 192.168.1.10
```

Run this on the machine that *can't* see servers — it answers "is anything advertising, and under which ident?" in ten seconds.

### Windows — host a real race

Download `NFSLAN-GUI.exe`, or build it:

```powershell
cmake -S . -B build-win32 -G "Visual Studio 17 2022" -A Win32
cmake --build build-win32 --config Release
```

`-A Win32` is required — the worker hosts a 32-bit `server.dll`.

Run `NFSLAN-GUI.exe` **as Administrator**, pick the game, point it at the folder
holding the game EXE + `server.dll` + `server.cfg`, name your server, and press
**Start Bundle**. The game launches patched so you can join from the same PC.

It's a single self-contained executable — the worker is embedded, no runtime to
install. There's a command-line path too (`NFSLAN.exe "Server Name"`), plus the
patcher details and every flag, in **[docs/WINDOWS.md](docs/WINDOWS.md)**.

---

## Ports & firewall

Every port this game and this project use. **Nothing else is needed.**

| Port | Protocol | Direction | Required? | What it is |
| --- | --- | --- | --- | --- |
| **9999** | UDP | in + out, **broadcast** | **Yes** | LAN discovery. Beacons and `?` queries. Hardcoded in both the game and `server.dll` — **not configurable**, don't try. |
| **9900** | TCP | inbound | **Yes** | Lobby / session. This is `PORT` in `server.cfg`; change it there and the beacon advertises the new value automatically. |
| 9901 | UDP | in + out | No | Optional same-PC/locality check (`LOCAL?`). Worker only, Most Wanted path. |

Notes that trip people up:

- **UDP 9999 must allow broadcast**, not just unicast. Discovery goes to `255.255.255.255:9999` and to each interface's broadcast address. A firewall that permits only established/unicast UDP will silently hide every server.
- The beacon **does not contain the server's address** — clients connect back to the packet's source address. The host must be directly reachable; NAT between client and server breaks joining even when discovery works.
- `9999` is fixed in the retail binaries on **both** sides. `--discovery-port` exists for local plumbing and testing only.

### Windows Firewall

Run in an **Administrator** PowerShell. Adjust the program paths to yours.

```powershell
New-NetFirewallRule -DisplayName "NFSLAN discovery (UDP 9999)" -Direction Inbound -Protocol UDP -LocalPort 9999 -Action Allow
New-NetFirewallRule -DisplayName "NFSLAN lobby (TCP 9900)" -Direction Inbound -Protocol TCP -LocalPort 9900 -Action Allow
```

Also allow the executables themselves, which is what Windows actually prompts about:

```powershell
New-NetFirewallRule -DisplayName "NFSLAN worker" -Direction Inbound -Program "C:\path\to\NFSLAN.exe" -Action Allow
New-NetFirewallRule -DisplayName "NFS Underground 2" -Direction Inbound -Program "C:\Games\NFSU2\SPEED2.EXE" -Action Allow
```

Remove them later:

```powershell
Get-NetFirewallRule -DisplayName "NFSLAN*" | Remove-NetFirewallRule
```

Check whether the firewall is the problem by briefly disabling the private profile — if the server appears, it was:

```powershell
Set-NetFirewallProfile -Profile Private -Enabled False
```

(Turn it back on with `-Enabled True`.)

### macOS

The built-in firewall may block inbound UDP to an unsigned binary, which stops clients' queries from arriving. Outbound announcements still go out, so servers usually appear anyway. If not: **System Settings → Network → Firewall → Options** → allow `nfslan-server`.

### Linux

```bash
sudo ufw allow 9999/udp && sudo ufw allow 9900/tcp
```

```bash
sudo firewall-cmd --add-port=9999/udp --add-port=9900/tcp --permanent && sudo firewall-cmd --reload
```

---

## My server doesn't show up

In order of how often it's the cause:

**1. `LOBBY_IDENT` doesn't match the client's build.** This is nearly always it. The ident is a protocol tag, *not* the display name, and a client silently hides every server whose ident it doesn't recognise — no error, no empty-list message.

| Ident | Build |
| --- | --- |
| `NFSU2NA` | Underground 2, North American |
| `NFSU2` | Underground 2, some RU/EU releases |
| `NFSMWNA` | Most Wanted, North American |
| `NFSMW` | Most Wanted, other releases |

Both sides pick their ident from a value baked into the binary, so **two copies of the same game can disagree.** Find out what yours wants:

```bash
nfslan-server --discover 15     # on the machine that can't see servers
```

…then match it:

```bash
nfslan-server --name "Living Room" --ident NFSU2
```

Careful with the worker: stock `server.dll` derives the ident from its **start-mode argument**, not from `server.cfg` — `--u2-mode 0` gives `NFSU2NA`, non-zero gives `NFSU2`. That is why editing `server.cfg` alone sometimes appears to do nothing, and why the worker rewrites the ident on the way out.

**2. UDP 9999 broadcast is blocked.** See [Ports & firewall](#ports--firewall).

**3. Client and server aren't on the same broadcast domain.** Different subnets, guest/AP isolation on the Wi-Fi, a VPN capturing the default route, or Docker bridge networks all break discovery. Wired and wireless on the *same* router are usually fine; "Guest network" almost never is.

**4. Same-PC play needs more than loopback.** `nfslan-server` announces to `127.0.0.1` by default, but stock clients also deliberately hide servers that look like they came from themselves. Defeating that needs the worker's patcher.

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
--no-lobby             Don't listen on the lobby port at all
--capture <path>       Log the lobby handshake as a hex dump
--capture-only         Log the handshake without answering it at all
--ack-unknown          Claim success for lobby verbs with no handler, so a client
                       keeps walking its state machine and reveals its next
                       request. Discovery tool only — it can hang the game
--verbose              Log every packet decision
```

A stock `server.cfg` works unchanged — unknown keys are ignored, and `PORT`, `ADDR`, `LOBBY_IDENT` and `LOBBY` are honoured. Command-line flags win over the file.

---

## Status

**Works today**

- LAN discovery, fully: beacon encode/decode at the real field offsets, `?` queries answered, periodic announcements, live player count, and a goodbye beacon on shutdown so the row disappears from clients immediately.
- Cross-region ident rewriting — the fix for invisible servers.
- The lobby connect handshake (EA "Titan" framing), verified against **both** retail games running under Proton on a Steam Deck against `nfslan-server` on macOS:
  - **Underground 2** (1.2, `SKU=14705`) — appears in the LAN list, connects, and reaches the LAN Main screen.
  - **Most Wanted** (1.3, `SKU=14705`) — appears in the LAN list, connects, and gets as far as **creating an online persona**.
- Native builds on macOS (Apple Silicon and Intel), Linux and Windows, with no `server.dll` and no x86 requirement. 116 protocol checks, all passing.
- The Windows worker for real matches.

**Not done yet**

- `nfslan-server` cannot run a *race*. The persona/account layer stalls: Underground 2 bounces out of the lobby, and Most Wanted waits on "Creating persona…". Both need reply bodies whose field names still have to be pulled out of the client binaries.
- `--ack-unknown` and `--capture` exist for exactly this work, and [docs/PROTOCOL.md](docs/PROTOCOL.md) records the observed traffic plus what the client reads from each reply. Contributions very welcome.
- **Use the Windows worker for actual racing.**

## Documentation

- [docs/WINDOWS.md](docs/WINDOWS.md) — hosting a real race on Windows: the GUI, the worker, the patchers
- [docs/BUILD.md](docs/BUILD.md) — build matrix for every platform, and how the releases are made
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — the wire format, field by field, verified vs guesswork
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the pieces fit together

## Legal

NFSLAN ships **no game code and no game assets**. `server.dll` comes from your own copy of the game. Underground 2 and Most Wanted are © Electronic Arts; this project is unaffiliated with and unendorsed by EA.

Licensed under the terms in [LICENSE](LICENSE).

## Credits

- `injector` and `Hooking.Patterns` by aap / Silent, under their own licenses.
- The original `Network.h` UDP wrapper came from a Stack Overflow answer by Peter R, adapted by Xan / Tenjoin. The portable replacement in `core/` is new code.
- Looking for **online** play rather than LAN? See [NFSOR](https://discord.gg/BB27nMjSCp), an official-server revival project for PS2 and PC.
