# nfslan-core: portable protocol + networking library.
#
# No Windows-only code, no server.dll, no x86 assumptions. Builds on macOS,
# Linux and Windows, on any architecture.

add_library(nfslan-core STATIC
    src/net.cpp
    src/beacon.cpp
    src/config.cpp
    src/discovery.cpp
    src/lobby.cpp
    src/titan.cpp
)

target_include_directories(nfslan-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(nfslan-core PUBLIC cxx_std_20)

if(WIN32)
    target_link_libraries(nfslan-core PUBLIC ws2_32 iphlpapi)
    target_compile_definitions(nfslan-core PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

if(NOT MSVC)
    target_compile_options(nfslan-core PRIVATE -Wall -Wextra -Wpedantic)
endif()

find_package(Threads REQUIRED)
target_link_libraries(nfslan-core PUBLIC Threads::Threads)
