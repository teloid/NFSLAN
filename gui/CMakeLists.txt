cmake_minimum_required(VERSION 3.21)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets)

qt_standard_project_setup()

qt_add_executable(nfslan-gui
    src/main.cpp
    src/MainWindow.cpp
    src/MainWindow.h
)

target_link_libraries(nfslan-gui PRIVATE Qt6::Widgets)

if(WIN32 AND NFSLAN_BUILD_WORKER AND NFSLAN_EMBED_WORKER_IN_GUI)
    target_sources(nfslan-gui PRIVATE
        ${CMAKE_SOURCE_DIR}/NFSLAN.cpp
        ${CMAKE_SOURCE_DIR}/injector/hooking/Hooking.Patterns.cpp
    )

    target_include_directories(nfslan-gui PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/injector
        ${CMAKE_SOURCE_DIR}/injector/hooking
    )

    target_compile_definitions(nfslan-gui PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        NFSLAN_WORKER_NO_MAIN
        NFSLAN_WINDOWS_EMBED_WORKER
    )

    target_link_libraries(nfslan-gui PRIVATE
        ws2_32
        iphlpapi
    )
endif()

set_target_properties(nfslan-gui PROPERTIES
    OUTPUT_NAME "NFSLAN-GUI"
)
