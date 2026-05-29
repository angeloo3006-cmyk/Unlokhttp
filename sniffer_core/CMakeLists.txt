cmake_minimum_required(VERSION 3.20)
project(sniffer_core LANGUAGES CXX)

# ─────────────────────────────────────────────────────────────
# C++17 required (std::optional, structured bindings, etc.)
# ─────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─────────────────────────────────────────────────────────────
# Output binary name
# ─────────────────────────────────────────────────────────────
set(TARGET_NAME sniffer_core)
add_executable(${TARGET_NAME} main.cpp)

# ─────────────────────────────────────────────────────────────
# nlohmann/json — single-header; bundled next to main.cpp.
# If you prefer to use the installed system/vcpkg version,
# replace with: find_package(nlohmann_json REQUIRED)
#               target_link_libraries(... nlohmann_json::nlohmann_json)
# ─────────────────────────────────────────────────────────────
target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# ─────────────────────────────────────────────────────────────
# Platform-specific: pcap / Npcap linkage
# ─────────────────────────────────────────────────────────────
if(WIN32)
    # ── Windows / Npcap SDK ───────────────────────────────────
    # Set NPCAP_SDK_DIR to your Npcap SDK root, e.g.:
    #   cmake -B build -DNPCAP_SDK_DIR="C:/npcap-sdk"
    # Default to the most common install location.
    if(NOT DEFINED NPCAP_SDK_DIR)
        if(EXISTS "C:/npcap-sdk")
            set(NPCAP_SDK_DIR "C:/npcap-sdk")
        elseif(EXISTS "$ENV{PROGRAMFILES}/Npcap/sdk")
            set(NPCAP_SDK_DIR "$ENV{PROGRAMFILES}/Npcap/sdk")
        else()
            message(FATAL_ERROR
                "Npcap SDK not found. Pass -DNPCAP_SDK_DIR=<path> to cmake.\n"
                "Download the SDK from https://npcap.com/#download")
        endif()
    endif()

    message(STATUS "Npcap SDK: ${NPCAP_SDK_DIR}")

    # Detect MSVC vs MinGW
    if(MSVC)
        set(NPCAP_ARCH "$<IF:$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>,x64,Win32>")
        target_include_directories(${TARGET_NAME} PRIVATE
            "${NPCAP_SDK_DIR}/Include")
        target_link_directories(${TARGET_NAME} PRIVATE
            "${NPCAP_SDK_DIR}/Lib/${NPCAP_ARCH}")
        target_link_libraries(${TARGET_NAME}
            wpcap Packet ws2_32)

        # MSVC compiler flags: treat warnings-as-errors, fast optimisations
        target_compile_options(${TARGET_NAME} PRIVATE
            /W3 /permissive- /Zc:__cplusplus
            $<$<CONFIG:Release>:/O2 /GL>)
        target_link_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Release>:/LTCG>)

    else()
        # MinGW / MSYS2 cross-compile path
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(NPCAP_LIB_SUBDIR "Lib/x64")
        else()
            set(NPCAP_LIB_SUBDIR "Lib/Win32")
        endif()
        target_include_directories(${TARGET_NAME} PRIVATE
            "${NPCAP_SDK_DIR}/Include")
        target_link_directories(${TARGET_NAME} PRIVATE
            "${NPCAP_SDK_DIR}/${NPCAP_LIB_SUBDIR}")
        target_link_libraries(${TARGET_NAME}
            wpcap Packet ws2_32)
        target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra)
    endif()

    # Embed manifest so the binary requests admin privileges (required for raw
    # socket access on Windows even with Npcap installed).
    if(MSVC)
        target_sources(${TARGET_NAME} PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/sniffer_core.manifest")
        set_target_properties(${TARGET_NAME} PROPERTIES
            LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")
    endif()

elseif(APPLE)
    # ── macOS — system libpcap (ships with Xcode command-line tools) ───────
    find_library(PCAP_LIBRARY pcap REQUIRED)
    target_link_libraries(${TARGET_NAME} ${PCAP_LIBRARY})
    target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -O2)

    # macOS: allow packet capture without sudo via ChmodBPF (Wireshark installs
    # this), or add the binary to the 'access_bpf' group.
    message(STATUS "macOS: ensure your user is in the 'access_bpf' group or "
                   "install Wireshark's ChmodBPF helper.")

else()
    # ── Linux — libpcap ────────────────────────────────────────────────────
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(PCAP QUIET libpcap)
    endif()

    if(PCAP_FOUND)
        target_include_directories(${TARGET_NAME} PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(${TARGET_NAME} ${PCAP_LINK_LIBRARIES})
    else()
        # Fallback: manual search
        find_path(PCAP_INCLUDE_DIR pcap/pcap.h
            PATHS /usr/include /usr/local/include)
        find_library(PCAP_LIB NAMES pcap
            PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu)

        if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIB)
            message(FATAL_ERROR
                "libpcap not found.\n"
                "Install it with:\n"
                "  Debian/Ubuntu: sudo apt install libpcap-dev\n"
                "  Fedora/RHEL  : sudo dnf install libpcap-devel\n"
                "  Arch         : sudo pacman -S libpcap")
        endif()

        target_include_directories(${TARGET_NAME} PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(${TARGET_NAME} ${PCAP_LIB})
    endif()

    target_link_libraries(${TARGET_NAME} pthread)
    target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -O2)

    # Linux: set net_raw + net_admin capabilities so the binary works without root.
    # Run once after build:
    #   sudo setcap cap_net_raw,cap_net_admin=eip sniffer_core
    install(TARGETS ${TARGET_NAME} DESTINATION bin)
    install(CODE
        "execute_process(COMMAND setcap cap_net_raw,cap_net_admin=eip \
            \$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/${TARGET_NAME})")
endif()

# ─────────────────────────────────────────────────────────────
# Tauri sidecar placement helper
# If you build in Release mode and want the binary automatically
# copied to the Tauri src-tauri/binaries/ folder, enable this:
# ─────────────────────────────────────────────────────────────
option(COPY_TO_TAURI "Copy binary to src-tauri/binaries after build" OFF)
if(COPY_TO_TAURI)
    # Tauri sidecar naming convention: <name>-<target-triple>
    # Adjust the triple for your host platform.
    if(WIN32)
        set(TAURI_TRIPLE "x86_64-pc-windows-msvc")
        set(TAURI_EXT ".exe")
    elseif(APPLE)
        set(TAURI_TRIPLE "aarch64-apple-darwin")  # change to x86_64-apple-darwin on Intel
        set(TAURI_EXT "")
    else()
        set(TAURI_TRIPLE "x86_64-unknown-linux-gnu")
        set(TAURI_EXT "")
    endif()

    set(TAURI_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src-tauri/binaries")
    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${TAURI_BIN_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy
            "$<TARGET_FILE:${TARGET_NAME}>"
            "${TAURI_BIN_DIR}/${TARGET_NAME}-${TAURI_TRIPLE}${TAURI_EXT}"
        COMMENT "Copying sniffer_core to Tauri binaries folder")
endif()

# ─────────────────────────────────────────────────────────────
# Print summary
# ─────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "┌─ sniffer_core build configuration ─────────────")
message(STATUS "│  Platform  : ${CMAKE_SYSTEM_NAME}")
message(STATUS "│  Compiler  : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "│  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "│  C++ std   : ${CMAKE_CXX_STANDARD}")
if(WIN32)
message(STATUS "│  Npcap SDK : ${NPCAP_SDK_DIR}")
endif()
message(STATUS "└────────────────────────────────────────────────")
message(STATUS "")
