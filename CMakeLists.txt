cmake_minimum_required(VERSION 3.21)

project(NFSLAN LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(NFSLAN_BUILD_GUI "Build the Qt GUI launcher" ON)
option(NFSLAN_BUILD_WORKER "Build the native Windows worker executable" ON)
option(NFSLAN_EMBED_WORKER_IN_GUI "Embed the Windows worker into the GUI executable (single EXE mode)" ON)

if(NFSLAN_EMBED_WORKER_IN_GUI AND NOT NFSLAN_BUILD_GUI)
    message(WARNING "NFSLAN_EMBED_WORKER_IN_GUI requires NFSLAN_BUILD_GUI=ON. Disabling embedding.")
    set(NFSLAN_EMBED_WORKER_IN_GUI OFF)
endif()

if(WIN32 AND NFSLAN_BUILD_WORKER AND NFSLAN_EMBED_WORKER_IN_GUI AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR
        "Embedded worker mode requires a 32-bit (Win32) build because NFSLAN worker and server.dll are x86-only. "
        "Configure with '-A Win32' and use a 32-bit Qt kit.")
endif()

if(NFSLAN_BUILD_GUI)
    add_subdirectory(gui)
endif()

if(NFSLAN_BUILD_WORKER AND WIN32 AND NOT NFSLAN_EMBED_WORKER_IN_GUI)
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
    message(STATUS "Worker runtime will be embedded into the GUI executable on Windows (single EXE mode)")
endif()

if(NFSLAN_BUILD_WORKER AND NOT WIN32)
    message(STATUS "Skipping nfslan-worker: build it on Windows (or MinGW) because it requires Win32 APIs and server.dll")
endif()
