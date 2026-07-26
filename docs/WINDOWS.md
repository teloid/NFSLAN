# Windows: hosting a real race

This is the path that runs an actual multiplayer session. It hosts the game's own
`server.dll` outside the game, and patches the running game so you can join your
own server from the same PC.

It is Windows-and-x86 only, by construction: `server.dll` is a 32-bit Windows
library that has to be loaded into the host process and patched in memory.

For simply making a server *visible* to a client that can't see one — on any OS —
use `nfslan-server` instead; see the [README](../README.md).

## What you need

In one folder, the game's own files:

| Game | Executable | Also needed |
| --- | --- | --- |
| Underground 2 | `SPEED2.EXE` | `server.dll`, `server.cfg` |
| Most Wanted | `speed.exe` | `server.dll`, `server.cfg` |

Both ship with the game. NFSLAN provides no game files.

## Option A — the GUI (single executable)

`NFSLAN-GUI.exe` is self-contained: with the default build the worker is embedded,
so there is no separate runtime to install and nothing else to copy.

1. Run it **as Administrator** (the patcher needs it).
2. Pick the game.
3. Set **Game folder** to the folder described above.
4. Type a server name.
5. Press **Start Bundle (Recommended)**.

The game launches patched. Open the LAN server list and join. That's the whole flow.

## Option B — the command line

Same functionality, fewer moving parts, scriptable. Run from the game folder:

```powershell
.\NFSLAN.exe "Living Room"
```

| Flag | What it does |
| --- | --- |
| `--same-machine` | Host and play on one PC (sets `FORCE_LOCAL` plus address fixups) |
| `--u2-mode N` | Underground 2 `StartServer` mode, 0–13. `0` advertises as `NFSU2NA`, non-zero as `NFSU2` |
| `--beacon-only` | Advertise without loading `server.dll` at all |
| `--diag-lan` | Verbose LAN discovery diagnostics |
| `--local-emulation` | Enable the discovery loopback bridge |

For same-PC play also run the patcher for your game, as Administrator:

```powershell
.\NFSLAN-U2-Patcher.exe      # Underground 2
.\NFSLAN-MW-Patcher.exe      # Most Wanted
```

### Why the patcher is needed

Stock clients deliberately hide any server whose beacon appears to come from
their own address — so without it, a server on your own PC is invisible to you.
The patcher starts the game, finds its LAN-discovery table, and clears the
per-entry "this is me" flag, polling every 100 ms so the row stays visible.

It is an external memory poker (`ReadProcessMemory`/`WriteProcessMemory`), not a
DLL injection, and it touches one DWORD per table row. It also synthesises a row
if the table has none. Hard-coded table addresses: `0x004B7E28` (U2),
`0x005C3878` (MW) — so a differently-patched EXE may need those updated.

## `server.cfg`

A stock file works. The keys that matter:

| Key | Meaning |
| --- | --- |
| `PORT` | Lobby/session port. Default `9900`. Advertised to clients automatically. |
| `ADDR` | Address to advertise. `0.0.0.0` or a `%%bind(...)` expression means auto-detect. |
| `LOBBY_IDENT` | Protocol ident. See below — this is the one that matters. |
| `LOBBY` | Should match `LOBBY_IDENT`. |

### The one big gotcha

`LOBBY_IDENT` is a **protocol tag, not a display name**, and a client silently
hides every server whose ident it does not recognise — no error, no message.

| Ident | Build |
| --- | --- |
| `NFSU2NA` | Underground 2, North American |
| `NFSU2` | Underground 2, some RU/EU releases |
| `NFSMWNA` | Most Wanted, North American |
| `NFSMW` | Most Wanted, other releases |

**Editing `server.cfg` alone may not change it.** Stock `server.dll` derives the
ident from `StartServer`'s mode argument, not from the config file — which is why
the worker rewrites it on the way out, and why `--u2-mode 0` vs non-zero matters.

To find out what a client actually expects, run this on the client's machine:

```
nfslan-server --discover 15
```

It prints the idents it sees on the network.

## Ports

`9999/UDP` (discovery, must allow **broadcast**) and `9900/TCP` (lobby). Full
table and copy-pasteable firewall rules are in the
[README](../README.md#ports--firewall).

## Building

```powershell
cmake -S . -B build-win32 -G "Visual Studio 17 2022" -A Win32
cmake --build build-win32 --config Release
```

`-A Win32` is required — the worker hosts a 32-bit DLL. An x64 configure prints a
status line explaining that it is skipping the worker.

Outputs in `build-win32/native_win32/Release/`:

- `NFSLAN-GUI.exe` — the launcher, worker embedded
- `NFSLAN-U2-Patcher.exe`, `NFSLAN-MW-Patcher.exe` — the patchers

Turning the GUI off (`-DNFSLAN_BUILD_NATIVE_WIN32_GUI=OFF`) still builds the
patchers, and `-DNFSLAN_EMBED_WORKER_IN_GUI=OFF` gives you a standalone
`NFSLAN.exe` worker instead of an embedded one.

## Troubleshooting

- **Server not in the LAN list** — almost always `LOBBY_IDENT`. See above.
- **Can't see your own server on the hosting PC** — run the patcher, as
  Administrator, and use `--same-machine`.
- **"Address already in use" on startup** — something already holds UDP 9999.
  Usually the game itself, or another server instance.
- **Bundle mode does nothing** — not running as Administrator.
- **Nothing at all happens for a client on another subnet** — discovery is
  broadcast-based and does not cross subnets, guest-network isolation, or a VPN
  that has captured the default route.

## Known issues in the worker

These are long-standing and only affect this Windows path; the portable server
does not share the code:

- `LooksLikeUg2LanBeacon` (`NFSLAN.cpp:757`) requires beacon byte 3 to be `0x03`.
  That byte is the re-advertise interval, not a type tag, and stock receivers
  never check it — so beacons using a different interval are wrongly ignored.
- `TitanCmdEqualsIgnoreCase` compares lobby tags case-insensitively, but tag case
  is semantic: lowercase is client-to-lobby and uppercase is server-to-server.
  Tags should be compared as raw 32-bit values.
- The beacon ident field is treated as 8 bytes (`NFSLAN.cpp:84`); it is actually
  0x20. Harmless for the four known idents, truncating for anything longer.

See [PROTOCOL.md](PROTOCOL.md) for the wire format these refer to.
