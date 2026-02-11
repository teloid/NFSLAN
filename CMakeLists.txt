cmake_minimum_required(VERSION 3.21)

project(NFSLAN LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
    set(NFSLAN_BUILD_GUI_DEFAULT OFF)
    set(NFSLAN_BUILD_NATIVE_WIN32_GUI_DEFAULT ON)
    set(NFSLAN_BUILD_RELAY_WIN32_GUI_DEFAULT ON)
else()
    set(NFSLAN_BUILD_GUI_DEFAULT ON)
    set(NFSLAN_BUILD_NATIVE_WIN32_GUI_DEFAULT OFF)
    set(NFSLAN_BUILD_RELAY_WIN32_GUI_DEFAULT OFF)
endif()

option(NFSLAN_BUILD_GUI "Build the Qt GUI launcher" ${NFSLAN_BUILD_GUI_DEFAULT})
option(NFSLAN_BUILD_NATIVE_WIN32_GUI "Build native Win32 GUI launcher (no Qt runtime)" ${NFSLAN_BUILD_NATIVE_WIN32_GUI_DEFAULT})
option(NFSLAN_BUILD_RELAY_WIN32_GUI "Build native Win32 LAN relay GUI" ${NFSLAN_BUILD_RELAY_WIN32_GUI_DEFAULT})
option(NFSLAN_BUILD_WORKER "Build the native Windows worker executable" ON)
option(NFSLAN_EMBED_WORKER_IN_GUI "Embed the Windows worker into the GUI executable (single EXE mode)" ON)

if(WIN32 AND NFSLAN_EMBED_WORKER_IN_GUI AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(WARNING
        "NFSLAN_EMBED_WORKER_IN_GUI requires a Win32/x86 build. "
        "Disabling embedding for this configure run.")
    set(NFSLAN_EMBED_WORKER_IN_GUI OFF)
endif()

if(NFSLAN_BUILD_NATIVE_WIN32_GUI AND NOT WIN32)
    message(WARNING "NFSLAN_BUILD_NATIVE_WIN32_GUI is Windows-only. Disabling it.")
    set(NFSLAN_BUILD_NATIVE_WIN32_GUI OFF)
endif()

if(NFSLAN_BUILD_RELAY_WIN32_GUI AND NOT WIN32)
    message(WARNING "NFSLAN_BUILD_RELAY_WIN32_GUI is Windows-only. Disabling it.")
    set(NFSLAN_BUILD_RELAY_WIN32_GUI OFF)
endif()

if(NFSLAN_BUILD_GUI)
    add_subdirectory(gui)
endif()

if(NFSLAN_BUILD_NATIVE_WIN32_GUI OR NFSLAN_BUILD_RELAY_WIN32_GUI)
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

    target_link_libraries(nfslan-worker PRIVATE
        ws2_32
        iphlpapi
    )

    set_target_properties(nfslan-worker PROPERTIES OUTPUT_NAME "NFSLAN")
endif()

if(NFSLAN_BUILD_WORKER AND WIN32 AND NFSLAN_EMBED_WORKER_IN_GUI)
    message(STATUS "Worker embedding is enabled (x86-only); compatible GUI targets may embed the runtime")
endif()

if(NFSLAN_BUILD_WORKER AND WIN32 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(STATUS "Skipping standalone nfslan-worker in x64 build: worker is x86-only. Use '-A Win32' for NFSLAN.exe.")
endif()

if(NFSLAN_BUILD_WORKER AND NOT WIN32)
    message(STATUS "Skipping nfslan-worker: build it on Windows (or MinGW) because it requires Win32 APIs and server.dll")
endif()
