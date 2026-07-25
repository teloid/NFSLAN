# Architecture

The project is two independent halves over one protocol.

```
                        ┌─────────────────────────────────────┐
                        │  nfslan-core  (portable library)    │
                        │  net · beacon · config · discovery  │
                        │  lobby (capture)                    │
                        └───────────────┬─────────────────────┘
                                        │
                 ┌──────────────────────┴──────────────┐
                 │                                     │
      ┌──────────▼───────────┐            ┌────────────▼──────────────┐
      │ nfslan-server        │            │ nfslan-tests              │
      │ standalone LAN server│            │ protocol codec tests      │
      │ macOS/Linux/Windows  │            └───────────────────────────┘
      └──────────────────────┘

      ── Windows only, unchanged ─────────────────────────────────────
      ┌──────────────────────┐   spawns   ┌──────────────────────────┐
      │ NFSLAN-GUI.exe       ├───────────►│ NFSLAN.exe (worker)      │
      │ native_win32/        │  pipe/log  │ NFSLAN.cpp               │
      │ config + preflight   │            │ hosts the game server.dll│
      └──────────┬───────────┘            └──────────────────────────┘
                 │ launches
      ┌──────────▼────────────────────────┐
      │ NFSLAN-U2/MW-Patcher.exe          │
      │ in-memory patch for same-PC join  │
      └───────────────────────────────────┘
```

## Portable half

**`core/`** — `nfslan-core`, a static library with no Windows, x86, or
`server.dll` dependency. Builds anywhere with a C++20 compiler.

| Unit | Responsibility |
| --- | --- |
| `net` | BSD/Winsock socket wrappers, address helpers, interface broadcast enumeration. Replaces the Winsock-only `Network.h`. |
| `beacon` | Encode/decode the 0x180-byte LAN beacon; ident rewriting; withdrawal beacons. |
| `config` | `server.cfg` reader. Accepts stock files unchanged; warns on the mismatches that hide servers. |
| `discovery` | The service loop: answers `?` queries, announces on an interval, says goodbye on shutdown. |
| `lobby` | TCP listener for the advertised port. Currently capture-only — logs the client handshake for reverse engineering. |

**`cli/`** — `nfslan-server`. Argument parsing, config merge, status output, and
a `--discover` mode that lists what is on the LAN.

**`tests/`** — `nfslan-tests`, run via `ctest`. Pure codec tests: field offsets,
truncation, rejection rules, config parsing. No network, no fixtures.

## Windows half

Unchanged by the portable work, and still the only path that runs a real session.

| Component | Responsibility |
| --- | --- |
| `native_win32/src/NativeMain.cpp` | `NFSLAN-GUI.exe`: config editing, preflight validation, worker lifecycle over an anonymous pipe, and "Start Bundle" orchestration. |
| `NFSLAN.cpp` | The worker. Loads the game's `server.dll`, calls `StartServer`/`StopServer`, hooks `sendto`/`send` to rewrite the beacon ident and Most Wanted `@dir` bodies, and mirrors beacons to loopback. |
| `native_win32/src/U2PatchLauncher.cpp`, `MWPatchLauncher.cpp` | Start the game suspended and poll its discovery table, clearing the per-row self filter so a same-PC server stays visible. |
| `injector/` | Third-party pattern scanning and x86 trampolines used by the worker. |

Why this half cannot be ported: the worker exists to load a **32-bit Windows
`server.dll`** into its own address space and patch that module's import table
and code. That is Windows-and-x86 by construction. Everything reusable about it
was the protocol knowledge, which now lives in `core/`.

## Data flow

Discovery is the same on both paths:

1. A client broadcasts a `gEA?` query to `255.255.255.255:9999`, and/or listens
   passively.
2. The server broadcasts a 0x180-byte beacon carrying its ident, name, and the
   lobby port. `nfslan-server` also unicasts a reply straight to the querier.
3. The client matches the beacon's ident against what its build expects. A
   mismatch means the server is silently hidden.
4. The client connects back to the **source address** of the beacon, on the port
   from the beacon's stats field.

At step 4 the two halves diverge: the worker hands the connection to the real
`server.dll`, which runs the session. `nfslan-server` accepts and logs it, because
the lobby protocol is not implemented yet.

See [PROTOCOL.md](PROTOCOL.md) for the wire format and what remains unknown.

## Scope

- Underground 2 is the best-tested path; Most Wanted shares the discovery code
  and the worker supports it, including the `@dir` address rewriting.
- For real matches, use the Windows worker. `nfslan-server` is for making servers
  visible, diagnosing why they are not, and as the base for a native session
  implementation.
