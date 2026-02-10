cmake_minimum_required(VERSION 3.21)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_executable(nfslan-gui
    src/main.cpp
    src/MainWindow.cpp
    src/MainWindow.h
)

target_link_libraries(nfslan-gui PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

if(WIN32 AND NFSLAN_BUILD_WORKER AND NFSLAN_EMBED_WORKER_IN_GUI AND CMAKE_SIZEOF_VOID_P EQUAL 4)
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

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(nfslan-gui)
endif()
