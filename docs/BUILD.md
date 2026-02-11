# Build Guide

## Prerequisites

### Windows

- Visual Studio 2022 (MSVC / Build Tools)
- CMake 3.21+
- Qt is optional (only needed for `NFSLAN_BUILD_GUI=ON`)

### Linux

- GCC or Clang with C++20 support
- CMake 3.21+
- Qt 6.5+ development packages (`qt6-base-dev` or distro equivalent)
- A Windows compatibility runtime (`wine64`, Proton wrapper, or equivalent) for running the Windows worker

### macOS

- Xcode Command Line Tools (`xcode-select --install`)
- CMake 3.21+ (`brew install cmake`)
- Qt 6.5+ (`brew install qt`) for Qt launcher build
- Optional runtime layer (`wine`, CrossOver, or equivalent) to run Windows worker

## Build on Windows

### Native Win32 GUI (x64, external worker mode)

No Qt required.
This build now includes embedded relay UI entry (`Relay tool` button, `--relay-ui`) in the same executable.

```powershell
cmake -S . -B build-x64-native -G "Visual Studio 17 2022" -A x64 `
  -DNFSLAN_BUILD_NATIVE_WIN32_GUI=ON `
  -DNFSLAN_BUILD_GUI=OFF `
  -DNFSLAN_BUILD_WORKER=OFF
cmake --build build-x64-native --config Release
```

Expected output:

- GUI: `build-x64-native/native_win32/Release/NFSLAN-GUI.exe`

### Worker executable (x86)

```powershell
cmake -S . -B build-worker-x86 -G "Visual Studio 17 2022" -A Win32 `
  -DNFSLAN_BUILD_NATIVE_WIN32_GUI=OFF `
  -DNFSLAN_BUILD_GUI=OFF `
  -DNFSLAN_BUILD_WORKER=ON `
  -DNFSLAN_EMBED_WORKER_IN_GUI=OFF
cmake --build build-worker-x86 --config Release
```

Expected output:

- Worker: `build-worker-x86/Release/NFSLAN.exe`

### Native single EXE (x86 embedded worker)

No Qt required.

```powershell
cmake -S . -B build-win32-single -G "Visual Studio 17 2022" -A Win32 `
  -DNFSLAN_BUILD_NATIVE_WIN32_GUI=ON `
  -DNFSLAN_BUILD_GUI=OFF `
  -DNFSLAN_BUILD_WORKER=ON `
  -DNFSLAN_EMBED_WORKER_IN_GUI=ON
cmake --build build-win32-single --config Release
```

Expected output:

- Single launcher: `build-win32-single/native_win32/Release/NFSLAN-GUI.exe`

### Native relay app (x64 or x86)

No Qt required. This target does not require `server.dll`.

```powershell
cmake -S . -B build-relay -G "Visual Studio 17 2022" -A x64 `
  -DNFSLAN_BUILD_RELAY_WIN32_GUI=ON `
  -DNFSLAN_BUILD_NATIVE_WIN32_GUI=OFF `
  -DNFSLAN_BUILD_GUI=OFF `
  -DNFSLAN_BUILD_WORKER=OFF
cmake --build build-relay --config Release
```

Expected output:

- Relay GUI: `build-relay/native_win32/Release/NFSLAN-Relay.exe`

## Build Qt launcher (optional)

If you still want the Qt launcher path, provide Qt in `CMAKE_PREFIX_PATH` and enable `NFSLAN_BUILD_GUI=ON`.

Example on Windows (Qt 6 x64):

```powershell
cmake -S . -B build-qt -G "Visual Studio 17 2022" -A x64 `
  -DNFSLAN_BUILD_GUI=ON `
  -DNFSLAN_BUILD_NATIVE_WIN32_GUI=OFF `
  -DNFSLAN_BUILD_WORKER=OFF `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.8.3\msvc2022_64"
cmake --build build-qt --config Release
```

## Build on Linux/macOS (Qt launcher)

```bash
cmake -S . -B build -DNFSLAN_BUILD_WORKER=OFF
cmake --build build -j
```

Expected output:

- GUI: `build/gui/NFSLAN-GUI` (or app bundle on macOS)

## Optional flags

- Disable Qt launcher: `-DNFSLAN_BUILD_GUI=OFF`
- Disable native Win32 launcher: `-DNFSLAN_BUILD_NATIVE_WIN32_GUI=OFF`
- Disable relay GUI: `-DNFSLAN_BUILD_RELAY_WIN32_GUI=OFF`
- Disable worker target: `-DNFSLAN_BUILD_WORKER=OFF`
- Disable embedding: `-DNFSLAN_EMBED_WORKER_IN_GUI=OFF`
