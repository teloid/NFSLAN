# Build Guide

## Prerequisites (Windows)

- Visual Studio 2022 (Build Tools or full IDE)
- CMake 3.21+

## Recommended build: single EXE (Win32/x86)

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

## External-worker mode (optional)

Use this only if you do not want embedded worker.

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
- Worker: `build-x64-native/Release/NFSLAN.exe` (or equivalent target output path)
- Patcher: `build-x64-native/native_win32/Release/NFSLAN-U2-Patcher.exe`

## Troubleshooting

- If linker says target EXE is in use, close running `NFSLAN-GUI.exe` and rebuild.
- If CMake/VS generator cache conflicts, create a fresh build directory.
- Run the final GUI as Administrator for bundle mode.
