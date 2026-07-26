# Cross-compile Windows x86_64 binaries with MinGW-w64.
#
# Lets the portable server (and the Win32 GUI and patchers) be built from macOS
# or Linux without a Windows machine. The worker is NOT buildable this way — it
# needs MSVC for the x86 inline assembly in injector/.
#
#   cmake -S . -B build-win64 -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake \
#         -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-win64 -j

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)

set(CMAKE_C_COMPILER   ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
set(CMAKE_RC_COMPILER  ${TOOLCHAIN_PREFIX}-windres)

# Look for libraries and headers in the target sysroot, not the host's.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Static-link the GCC and C++ runtimes so the .exe needs no MinGW DLLs beside it.
# Without this, users would have to ship libstdc++-6.dll and libgcc_s_seh-1.dll.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static-libgcc -static-libstdc++ -static")
