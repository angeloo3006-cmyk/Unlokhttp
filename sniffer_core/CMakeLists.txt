cmake_minimum_required(VERSION 3.20)
project(sniffer_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(TARGET_NAME sniffer_core)
add_executable(${TARGET_NAME} main.cpp)
target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(WIN32)
    if(NOT DEFINED NPCAP_SDK_DIR)
        if(EXISTS "C:/npcap-sdk")
            set(NPCAP_SDK_DIR "C:/npcap-sdk")
        elseif(EXISTS "$ENV{PROGRAMFILES}/Npcap/sdk")
            set(NPCAP_SDK_DIR "$ENV{PROGRAMFILES}/Npcap/sdk")
        else()
            message(FATAL_ERROR
                "Npcap SDK not found. Pass -DNPCAP_SDK_DIR=<path> to CMake. "
                "Download the SDK from https://npcap.com/#download")
        endif()
    endif()

    if(NOT EXISTS "${NPCAP_SDK_DIR}/Include/pcap/pcap.h")
        message(FATAL_ERROR
            "Npcap SDK header not found at ${NPCAP_SDK_DIR}/Include/pcap/pcap.h")
    endif()

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(NPCAP_LIB_SUBDIR "Lib/x64")
    else()
        set(NPCAP_LIB_SUBDIR "Lib/Win32")
    endif()

    target_include_directories(${TARGET_NAME} PRIVATE "${NPCAP_SDK_DIR}/Include")
    target_link_directories(${TARGET_NAME} PRIVATE "${NPCAP_SDK_DIR}/${NPCAP_LIB_SUBDIR}")
    target_link_libraries(${TARGET_NAME} PRIVATE wpcap Packet ws2_32)

    if(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            /W3 /permissive- /Zc:__cplusplus
            $<$<CONFIG:Release>:/O2 /GL>)
        target_link_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Release>:/LTCG>)
        target_sources(${TARGET_NAME} PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/sniffer_core.manifest")
    else()
        target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra)
    endif()
elseif(APPLE)
    find_library(PCAP_LIBRARY pcap REQUIRED)
    target_link_libraries(${TARGET_NAME} PRIVATE ${PCAP_LIBRARY})
    target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -O2)
else()
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(PCAP QUIET libpcap)
    endif()

    if(PCAP_FOUND)
        target_include_directories(${TARGET_NAME} PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(${TARGET_NAME} PRIVATE ${PCAP_LINK_LIBRARIES})
    else()
        find_path(PCAP_INCLUDE_DIR pcap/pcap.h
            PATHS /usr/include /usr/local/include)
        find_library(PCAP_LIBRARY NAMES pcap
            PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu)
        if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
            message(FATAL_ERROR "libpcap not found. Install the libpcap development package.")
        endif()
        target_include_directories(${TARGET_NAME} PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(${TARGET_NAME} PRIVATE ${PCAP_LIBRARY})
    endif()

    target_link_libraries(${TARGET_NAME} PRIVATE pthread)
    target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -O2)
endif()

option(COPY_TO_TAURI "Copy binary to the Tauri binaries folder after build" OFF)
if(COPY_TO_TAURI)
    if(WIN32)
        set(TAURI_TRIPLE "x86_64-pc-windows-msvc")
        set(TAURI_EXT ".exe")
    elseif(APPLE)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
            set(TAURI_TRIPLE "aarch64-apple-darwin")
        else()
            set(TAURI_TRIPLE "x86_64-apple-darwin")
        endif()
        set(TAURI_EXT "")
    else()
        set(TAURI_TRIPLE "x86_64-unknown-linux-gnu")
        set(TAURI_EXT "")
    endif()

    set(TAURI_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../netscope/src-tauri/binaries")
    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${TAURI_BIN_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy
            "$<TARGET_FILE:${TARGET_NAME}>"
            "${TAURI_BIN_DIR}/${TARGET_NAME}-${TAURI_TRIPLE}${TAURI_EXT}"
        COMMENT "Copying sniffer_core to the Tauri binaries folder")
endif()

message(STATUS "sniffer_core platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "sniffer_core compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
if(WIN32)
    message(STATUS "Npcap SDK: ${NPCAP_SDK_DIR}")
endif()
