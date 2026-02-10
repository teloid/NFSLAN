# Build Guide

## Prerequisites

### Windows

- Visual Studio 2022 (MSVC)
- CMake 3.21+
- Qt kit matching your target architecture:
  - Single EXE mode: 32-bit Qt kit (for Win32 build, typically Qt 5.x MSVC x86)
  - Split mode x64 GUI: Qt 6.x MSVC 64-bit kit

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

### Single executable mode (GUI + embedded worker, x86)

Use Win32 target because worker + `server.dll` are x86-only.

```powershell
cmake -S . -B build-win32 -G "Visual Studio 17 2022" -A Win32 `
  -DNFSLAN_BUILD_WORKER=ON -DNFSLAN_EMBED_WORKER_IN_GUI=ON `
  -DCMAKE_PREFIX_PATH="C:\Qt\5.15.2\msvc2019"
cmake --build build-win32 --config Release
```

Expected output:

- `build-win32/gui/Release/NFSLAN-GUI.exe`

### Split mode (x64 GUI + separate worker)

```powershell
cmake -S . -B build-x64 -G "Visual Studio 17 2022" -A x64 `
  -DNFSLAN_BUILD_WORKER=OFF `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.8.3\msvc2022_64"
cmake --build build-x64 --config Release
```

For worker in split mode, build an x86 worker separately:

```powershell
cmake -S . -B build-worker-x86 -G "Visual Studio 17 2022" -A Win32 `
  -DNFSLAN_BUILD_GUI=OFF -DNFSLAN_BUILD_WORKER=ON -DNFSLAN_EMBED_WORKER_IN_GUI=OFF
cmake --build build-worker-x86 --config Release
```

Expected outputs:

- GUI: `build-x64/gui/Release/NFSLAN-GUI.exe`
- Worker: `build-worker-x86/Release/NFSLAN.exe`

### Notes

- If single-EXE mode is enabled on x64, configure will fail intentionally with an x86 requirement message.

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
