# Build Guide

## Prerequisites

### Windows

- Visual Studio 2022 (MSVC)
- CMake 3.21+
- Qt 6.5+ (Widgets)

### Linux

- GCC or Clang with C++20 support
- CMake 3.21+
- Qt 6.5+ development packages (`qt6-base-dev` or distro equivalent)
- A Windows compatibility runtime (`wine64`, Proton wrapper, or equivalent) for running the Windows worker

### macOS

- Xcode Command Line Tools (`xcode-select --install`)
- CMake 3.21+ (`brew install cmake`)
- Qt 6.5+ (`brew install qt`)
- Optional runtime layer (`wine`, CrossOver, or equivalent) to run Windows worker

## Build on Windows

```powershell
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

Expected output by default (`NFSLAN_EMBED_WORKER_IN_GUI=ON`):

- Single executable: `build/gui/Release/NFSLAN-GUI.exe` (GUI + embedded worker)

Optional legacy output (`NFSLAN_EMBED_WORKER_IN_GUI=OFF`):

- GUI: `build/gui/Release/NFSLAN-GUI.exe`
- Worker: `build/Release/NFSLAN.exe` (separate worker)

## Build on Linux

```bash
cmake -S . -B build
cmake --build build -j
```

Expected output:

- GUI: `build/gui/NFSLAN-GUI`

Notes:

- `nfslan-worker` is intentionally skipped on non-Windows hosts in this CMake setup.
- Use a Windows-built `NFSLAN.exe` worker and run it with your runtime command from GUI.

## Build on macOS (GUI only)

The worker target cannot be built natively on macOS because it depends on Win32 APIs.

```bash
brew install cmake qt
cmake -S . -B build -DNFSLAN_BUILD_WORKER=OFF -DCMAKE_PREFIX_PATH=\"$(brew --prefix qt)\"
cmake --build build -j
```

Typical output:

- `build/gui/NFSLAN-GUI.app` (bundle) or `build/gui/NFSLAN-GUI` (binary)

## Optional: disable components

- Disable GUI: `-DNFSLAN_BUILD_GUI=OFF`
- Disable worker: `-DNFSLAN_BUILD_WORKER=OFF`
- Disable embedding on Windows (restore two binaries): `-DNFSLAN_EMBED_WORKER_IN_GUI=OFF`
