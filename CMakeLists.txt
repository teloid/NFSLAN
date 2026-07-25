cmake_minimum_required(VERSION 3.21)

project(NFSLAN LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include(CTest)

# ---------------------------------------------------------------------------
# The project splits cleanly in two:
#
#   PORTABLE  - nfslan-core, nfslan-server, nfslan-tests. Plain sockets, no
#               server.dll, no x86 assumptions. Build anywhere.
#   WINDOWS   - the worker that hosts the game's 32-bit server.dll, the native
#               Win32 GUI, and the in-memory game patchers. These need Win32
#               APIs and x86 code patching, so they only exist on Windows.
# ---------------------------------------------------------------------------

option(NFSLAN_BUILD_SERVER "Build the portable standalone LAN server" ON)
option(NFSLAN_BUILD_TESTS "Build the protocol tests" ON)
# Legacy launcher GUIs. Neither is recommended: the worker and patchers are
# command-line programs, and the Qt GUI only shells out to wine off Windows,
# which the portable server makes pointless. Kept building so they do not rot.
option(NFSLAN_BUILD_GUI "Build the legacy Qt GUI launcher (not recommended)" OFF)

# Windows-only components. Defaulted off elsewhere so a non-Windows configure
# never has to warn about disabling something the user did not ask for.
if(WIN32)
    set(NFSLAN_WINDOWS_DEFAULT ON)
else()
    set(NFSLAN_WINDOWS_DEFAULT OFF)
endif()

option(NFSLAN_BUILD_WORKER "Build the Windows worker that hosts server.dll (Windows x86 only)"
       ${NFSLAN_WINDOWS_DEFAULT})
option(NFSLAN_BUILD_NATIVE_WIN32_GUI "Build the legacy native Win32 GUI launcher (Windows only)"
       ${NFSLAN_WINDOWS_DEFAULT})
option(NFSLAN_EMBED_WORKER_IN_GUI "Embed the worker into the GUI executable (single EXE mode)" ON)

if(NOT WIN32)
    foreach(windows_only NFSLAN_BUILD_WORKER NFSLAN_BUILD_NATIVE_WIN32_GUI)
        if(${windows_only})
            message(STATUS
                "${windows_only} is Windows-only; disabling it for this ${CMAKE_SYSTEM_NAME} build. "
                "The portable server (nfslan-server) does not need it.")
            set(${windows_only} OFF)
        endif()
    endforeach()
endif()

if(WIN32 AND NFSLAN_EMBED_WORKER_IN_GUI AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(WARNING
        "NFSLAN_EMBED_WORKER_IN_GUI requires a Win32/x86 build; disabling embedding. "
        "Configure with -A Win32 to enable it.")
    set(NFSLAN_EMBED_WORKER_IN_GUI OFF)
endif()

# --- Portable targets -------------------------------------------------------

add_subdirectory(core)

if(NFSLAN_BUILD_SERVER)
    add_subdirectory(cli)
endif()

if(NFSLAN_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(NFSLAN_BUILD_GUI)
    add_subdirectory(gui)
endif()

# --- Windows-only targets ---------------------------------------------------

if(NFSLAN_BUILD_NATIVE_WIN32_GUI)
    add_subdirectory(native_win32)
endif()

if(NFSLAN_BUILD_WORKER AND WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 4 AND NOT NFSLAN_EMBED_WORKER_IN_GUI)
    add_executable(nfslan-worker
        NFSLAN.cpp
        injector/hooking/Hooking.Patterns.cpp
    )

    target_include_directories(nfslan-worker PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/injector
        ${CMAKE_CURRENT_SOURCE_DIR}/injector/hooking
    )

    target_compile_definitions(nfslan-worker PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )

    target_link_libraries(nfslan-worker PRIVATE ws2_32 iphlpapi)

    set_target_properties(nfslan-worker PROPERTIES OUTPUT_NAME "NFSLAN")
endif()

if(NFSLAN_BUILD_WORKER AND WIN32 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(STATUS
        "Skipping nfslan-worker: it hosts a 32-bit server.dll, so it needs a Win32/x86 build "
        "(configure with -A Win32).")
endif()

# --- Configuration summary --------------------------------------------------

message(STATUS "")
message(STATUS "NFSLAN configuration (${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR}, ${CMAKE_BUILD_TYPE}):")
message(STATUS "  nfslan-core           always")
message(STATUS "  nfslan-server         ${NFSLAN_BUILD_SERVER}")
message(STATUS "  nfslan-tests          ${NFSLAN_BUILD_TESTS}")
message(STATUS "  Qt GUI (legacy)       ${NFSLAN_BUILD_GUI}")
message(STATUS "  Windows worker        ${NFSLAN_BUILD_WORKER}")
message(STATUS "  Win32 GUI (legacy)    ${NFSLAN_BUILD_NATIVE_WIN32_GUI}")
message(STATUS "")
