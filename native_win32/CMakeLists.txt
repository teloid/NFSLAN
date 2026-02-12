cmake_minimum_required(VERSION 3.21)

if(NFSLAN_BUILD_NATIVE_WIN32_GUI)
    set(NFSLAN_NATIVE_WIN32_CAN_EMBED OFF)
    if(NFSLAN_BUILD_WORKER AND NFSLAN_EMBED_WORKER_IN_GUI AND CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(NFSLAN_NATIVE_WIN32_CAN_EMBED ON)
    endif()

    add_executable(nfslan-native-gui WIN32
        src/NativeMain.cpp
    )

    target_compile_definitions(nfslan-native-gui PRIVATE
        UNICODE
        _UNICODE
    )

    target_link_libraries(nfslan-native-gui PRIVATE
        comdlg32
        comctl32
        dwmapi
        shell32
        ws2_32
        iphlpapi
        uxtheme
    )

    if(NFSLAN_NATIVE_WIN32_CAN_EMBED)
        target_sources(nfslan-native-gui PRIVATE
            ${CMAKE_SOURCE_DIR}/NFSLAN.cpp
            ${CMAKE_SOURCE_DIR}/injector/hooking/Hooking.Patterns.cpp
        )

        target_include_directories(nfslan-native-gui PRIVATE
            ${CMAKE_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/injector
            ${CMAKE_SOURCE_DIR}/injector/hooking
        )

        target_compile_definitions(nfslan-native-gui PRIVATE
            NFSLAN_WORKER_NO_MAIN
            NFSLAN_NATIVE_EMBED_WORKER
        )

    else()
        message(STATUS "native_win32 GUI: external worker mode (no embedded worker)")
    endif()

    if(NFSLAN_BUILD_GUI)
        set(NFSLAN_NATIVE_OUTPUT_NAME "NFSLAN-NativeGUI")
    else()
        set(NFSLAN_NATIVE_OUTPUT_NAME "NFSLAN-GUI")
    endif()

    set_target_properties(nfslan-native-gui PROPERTIES
        OUTPUT_NAME "${NFSLAN_NATIVE_OUTPUT_NAME}"
    )
endif()

if(WIN32)
    add_executable(nfslan-u2-patcher
        src/U2PatchLauncher.cpp
    )

    target_compile_definitions(nfslan-u2-patcher PRIVATE
        UNICODE
        _UNICODE
    )

    target_link_libraries(nfslan-u2-patcher PRIVATE
        comdlg32
    )

    set_target_properties(nfslan-u2-patcher PROPERTIES
        OUTPUT_NAME "NFSLAN-U2-Patcher"
    )
endif()
