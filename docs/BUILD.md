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
  Windows worker        OFF
  Win32 GUI             OFF
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
| `NFSLAN_BUILD_WORKER` | `ON` on Windows, else `OFF` | Worker that hosts `server.dll` |
| `NFSLAN_BUILD_NATIVE_WIN32_GUI` | `ON` on Windows, else `OFF` | Win32 GUI launcher. The two game patchers build on Windows regardless of this. |
| `NFSLAN_EMBED_WORKER_IN_GUI` | `ON` | Single-EXE mode (Win32/x86 only) |

The Windows-only options turn themselves off on other platforms and say so once
during configure.

## Windows: worker + GUI (single EXE)

This is the build for actual gameplay, including same-PC join. Needs Visual
Studio 2022 and an x86 target.

```powershell
cmake -S . -B build-win32-single -G "Visual Studio 17 2022" -A Win32 `
  -DNFSLAN_BUILD_NATIVE_WIN32_GUI=ON `
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

## Release binaries

How the published artifacts are produced, if you want to reproduce them:

**macOS universal** (arm64 + x86_64, runs back to macOS 11):

```bash
cmake -S . -B build-universal -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0
cmake --build build-universal -j
lipo -archs build-universal/bin/nfslan-server   # expect: x86_64 arm64
```

**Linux x86_64** (portable back to glibc 2.17). Built in a Debian 11 container so
the glibc baseline is old, with the C++ runtime linked statically so users do not
need a matching `libstdc++`:

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc"
cmake --build build-release -j
strip --strip-unneeded build-release/bin/nfslan-server
```

A *fully* static build links, but do not ship one: glibc's `getaddrinfo` needs
matching shared NSS libraries at runtime, and a statically-linked resolver
segfaults on a host with a different glibc. `nfslan::resolveHost()` uses it.

**Windows x86_64**, cross-compiled from macOS or Linux with MinGW-w64 — no Windows
machine needed (`brew install mingw-w64`, or your distro's package):

```bash
cmake -S . -B build-win64 -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-win64 -j
x86_64-w64-mingw32-strip --strip-unneeded build-win64/bin/nfslan-server.exe
```

The toolchain file static-links the GCC and C++ runtimes, so the `.exe` needs no
MinGW DLLs beside it. Stripping matters: unstripped these come out around 16 MB
and drop to about 1.3 MB.

### What cross-compiling can and cannot produce

| Target | MinGW | Note |
| --- | --- | --- |
| `nfslan-server.exe` | ✅ | Fully functional. Verified under Wine: all protocol checks pass, and it was discovered across the network by the macOS build. |
| `NFSLAN-U2/MW-Patcher.exe` | ✅ | Link cleanly. Only useful alongside a worker, so they are not published from a cross-build. |
| `NFSLAN-GUI.exe` | ⚠️ | Links, but an x86_64 build cannot embed the 32-bit worker, so it has nothing to host. Build it with MSVC. |
| `NFSLAN.exe` (worker) | ❌ | **Impossible.** Needs MSVC. |

The worker's blockers, if anyone wants to try:

- `injector/assembly.hpp:30` — `#error Cannot use this header in another compiler other than MSVC`
- `injector/assembly.hpp:100` — MSVC `_asm` inline assembly
- `injector/hooking/Hooking.Patterns.h:201` — missing `template` disambiguator, which
  GCC rejects (a genuine portability bug, but fixing it alone unlocks nothing)

Unicode entry points need `-municode` under MinGW, or the link fails with
`undefined reference to WinMain`; `native_win32/CMakeLists.txt` handles that.

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

For the Windows racing path in detail, see [WINDOWS.md](WINDOWS.md).
