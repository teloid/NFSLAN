# Protocol codec tests. Run with `ctest` or by invoking the binary directly.

add_executable(nfslan-tests
    test_protocol.cpp
)

target_link_libraries(nfslan-tests PRIVATE nfslan-core)

if(NOT MSVC)
    target_compile_options(nfslan-tests PRIVATE -Wall -Wextra)
endif()

set_target_properties(nfslan-tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_test(NAME protocol COMMAND nfslan-tests)
