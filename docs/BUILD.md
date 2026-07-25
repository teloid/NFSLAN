# Build Guide

The project has two halves, and which one you build depends on what you want:

| Want | Build | Platforms |
| --- | --- | --- |
| A standalone LAN server | `nfslan-server` | macOS, Linux, Windows, any CPU |
| To host the game's own `server.dll` + same-PC join | the Windows worker + GUI | Windows x86 only |

The portable half needs nothing but a C++20 compiler and CMake 3.21+. The
Windows half needs Win32 and a 32-bit x86 target, because it loads the game's
32-bit `server.dll` into its own process and patches that module's code.

## Portable server (macOS, Linux, Windows)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Outputs:

- `build/bin/nfslan-server` — the standalone LAN server
- `build/bin/nfslan-tests` — protocol codec tests

Nothing else is built by default off Windows, and the configure summary says
exactly what was enabled:

```
NFSLAN configuration (Darwin/arm64, Release):
  nfslan-core           always
  nfslan-server         ON
  nfslan-tests          ON
  Qt GUI                OFF
  Windows worker        OFF
  native Win32 GUI      OFF
```

### macOS notes

- Apple Silicon and Intel both work; the binary is a native Mach-O for the host
  architecture. No Rosetta, no Wine.
- The system firewall may block *inbound* UDP to an unsigned binary, which stops
  clients' discovery queries from arriving. Outbound announcements still go out,
  so the server usually still appears in the LAN list. If a client cannot see it,
  allow the binary in **System Settings → Network → Firewall → Options**.
- Homebrew is not required.

### Linux notes

- Any distro with GCC 11+ or Clang 14+. No dependencies beyond libstdc++ and
  pthreads.
- Binding UDP 9999 does not need root.

### Windows notes (portable server)

The portable server builds on Windows too, and does not need an x86 target:

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Output: `build\bin\Release\nfslan-server.exe`.

### CMake options

| Option | Default | Meaning |
| --- | --- | --- |
| `NFSLAN_BUILD_SERVER` | `ON` | The portable standalone server |
| `NFSLAN_BUILD_TESTS` | `ON` | Protocol codec tests |
| `NFSLAN_BUILD_GUI` | `OFF` | Qt Widgets launcher (needs Qt 5 or 6) |
| `NFSLAN_BUILD_WORKER` | `ON` on Windows, else `OFF` | Worker that hosts `server.dll` |
| `NFSLAN_BUILD_NATIVE_WIN32_GUI` | `ON` on Windows, else `OFF` | Native Win32 GUI |
| `NFSLAN_EMBED_WORKER_IN_GUI` | `ON` | Single-EXE mode (Win32/x86 only) |

The Windows-only options turn themselves off on other platforms and say so once
during configure.

## Windows: worker + GUI (single EXE)

This is the build for actual gameplay, including same-PC join. Needs Visual
Studio 2022 and an x86 target.

```powershell
cmake -S . -B build-win32-single -G "Visual Studio 17 2022" -A Win32 `
  -DNFSLAN_BUILD_NATIVE_WIN32_GUI=ON `
  -DNFSLAN_BUILD_GUI=OFF `
  -DNFSLAN_BUILD_WORKER=ON `
  -DNFSLAN_EMBED_WORKER_IN_GUI=ON
cmake --build build-win32-single --config Release
```

Outputs:

- `build-win32-single/native_win32/Release/NFSLAN-GUI.exe`
- `build-win32-single/native_win32/Release/NFSLAN-U2-Patcher.exe`
- `build-win32-single/native_win32/Release/NFSLAN-MW-Patcher.exe`

### External-worker mode (optional)

Only if you do not want the worker embedded. The GUI may be x64 while the worker
stays x86:

```powershell
cmake -S . -B build-x64-native -G "Visual Studio 17 2022" -A x64 `
  -DNFSLAN_BUILD_NATIVE_WIN32_GUI=ON `
  -DNFSLAN_BUILD_GUI=OFF `
  -DNFSLAN_BUILD_WORKER=ON `
  -DNFSLAN_EMBED_WORKER_IN_GUI=OFF
cmake --build build-x64-native --config Release
```

Expected:

- GUI: `build-x64-native/native_win32/Release/NFSLAN-GUI.exe`
- Worker: `build-x64-native/Release/NFSLAN.exe`
- Patcher: `build-x64-native/native_win32/Release/NFSLAN-U2-Patcher.exe`

An x64 configure will *not* produce the worker — it prints a status line saying
so, because `server.dll` is 32-bit. Configure with `-A Win32` for `NFSLAN.exe`.

## Qt GUI (optional, cross-platform)

```bash
cmake -S . -B build-gui -DNFSLAN_BUILD_GUI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-gui -j
```

Needs Qt 6 (or Qt 5) Widgets. On macOS: `brew install qt`. Note the GUI is a
launcher for the *Windows* worker — on non-Windows hosts it shells out to `wine`,
so it is only useful there with Wine plus a Windows worker binary. For a native
macOS or Linux server, run `nfslan-server` directly.

## Troubleshooting

- **"Address already in use" on startup.** Something already holds UDP 9999 —
  another server instance, or the game itself. Stop it, or use
  `--discovery-port`.
- **Server does not appear in the game's LAN list.** Almost always a
  `LOBBY_IDENT` mismatch rather than a network problem; see
  [PROTOCOL.md](PROTOCOL.md). Run `nfslan-server --discover` on the client's
  network to see which idents are actually in use.
- **Linker says the target EXE is in use** (Windows): close the running
  `NFSLAN-GUI.exe` and rebuild.
- **CMake generator cache conflicts**: configure into a fresh build directory.
- **Bundle mode does nothing** (Windows): run the GUI as Administrator.
