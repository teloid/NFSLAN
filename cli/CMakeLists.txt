# nfslan-server: the portable standalone LAN server.

add_executable(nfslan-server
    src/main.cpp
)

target_link_libraries(nfslan-server PRIVATE nfslan-core)

if(NOT MSVC)
    target_compile_options(nfslan-server PRIVATE -Wall -Wextra)
endif()

set_target_properties(nfslan-server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
