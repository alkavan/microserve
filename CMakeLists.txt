# SPDX-FileCopyrightText: 2025-2026 Igal Alkon
# SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
# SPDX-License-Identifier: BSD-3-Clause

cmake_minimum_required(VERSION 3.31)
project(microserve LANGUAGES CXX VERSION 0.5.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_SCAN_FOR_MODULES ON)

option(MICROSERVE_BUILD_TESTS "Build microserve tests" ${PROJECT_IS_TOP_LEVEL})
option(MICROSERVE_INSTALL "Install microserve executable and runtime assets" ${PROJECT_IS_TOP_LEVEL})
option(MICROSERVE_BUILD_TAILWIND "Build Tailwind CSS assets" ${PROJECT_IS_TOP_LEVEL})

if(WIN32)
#    add_compile_definitions(_WIN32_WINNT=0x0601) # Target Windows 7 or newer
    set(PLATFORM_LIBRARIES
            zstd::libzstd
            ws2_32
            mswsock
            bcrypt
    )
endif()

if(LINUX)
    set(PLATFORM_LIBRARIES zstd)
    # For boost local installation
    #set(BOOST_ROOT "deps/boost")
    #set(Boost_NO_SYSTEM_PATHS ON) # Force CMake to use BOOST_ROOT
endif()

# Find the boost libraries
find_package(Boost REQUIRED COMPONENTS system thread program_options)

# Find OpenSSL (provides OpenSSL::SSL and OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)

# spdlog: MSYS2 provides a shared lib, but GCC modules + SPDLOG_SHARED_LIB
# leave __imp_ spdlog::details::log_msg unresolved. Use the same install in
# header-only mode (no DLL link, no SPDLOG_COMPILED_LIB / SPDLOG_SHARED_LIB).
find_package(spdlog CONFIG REQUIRED)

# Find nghttp3 (HTTP/3)
find_package(nghttp3 CONFIG QUIET)
if(NOT nghttp3_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NGHTTP3 REQUIRED IMPORTED_TARGET libnghttp3)
endif()

# Find nghttp2 (HTTP/2)
find_package(nghttp2 CONFIG QUIET)
if(NOT nghttp2_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2)
endif()

find_package(ngtcp2 CONFIG QUIET)
if(NOT ngtcp2_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NGTCP2 REQUIRED IMPORTED_TARGET libngtcp2)
endif()

# Prefer ossl, then quictls
find_package(ngtcp2_crypto_ossl CONFIG QUIET)
find_package(ngtcp2_crypto_quictls CONFIG QUIET)

if(NOT ngtcp2_crypto_ossl_FOUND AND NOT ngtcp2_crypto_quictls_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NGTCP2_CRYPTO_OSSL IMPORTED_TARGET libngtcp2_crypto_ossl)
    if(NOT NGTCP2_CRYPTO_OSSL_FOUND)
        pkg_check_modules(NGTCP2_CRYPTO_QUICTLS IMPORTED_TARGET libngtcp2_crypto_quictls)
    endif()
endif()

if(WIN32)
    # Find zstd (compression) library
    find_package(zstd CONFIG REQUIRED)
endif()

if(NOT TARGET nlohmann_json::nlohmann_json)
    include(FetchContent)

    FetchContent_Declare(nlohmann_json
            GIT_REPOSITORY https://github.com/nlohmann/json.git
            GIT_TAG v3.12.0
    )

    set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# Microserve core library (shared by the server binary and the test suite)
add_library(microserve STATIC)

target_sources(microserve
        PRIVATE
        src/boost_src.cpp
        src/microserve/wire.cpp
        PUBLIC
        FILE_SET CXX_MODULES
        BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src/microserve
        FILES
        src/microserve/config.cppm
        src/microserve/core.cppm
        src/microserve/yaml.cppm
        src/microserve/detail.cppm
        src/microserve/handler.cppm
        src/microserve/http2.cppm
        src/microserve/http3_conn.cppm
        src/microserve/http3_quic.cppm
        src/microserve/http3.cppm
        src/microserve/http11.cppm
        src/microserve/logging.cppm
        src/microserve/proxy.cppm
        src/microserve/process.cppm
        src/microserve/server.cppm
)

target_include_directories(microserve PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(microserve PUBLIC
        Boost::system
        Boost::thread
        Boost::program_options
        nlohmann_json::nlohmann_json
        spdlog::spdlog_header_only
        ${PLATFORM_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
)

if(TARGET nghttp3::nghttp3)
    target_link_libraries(microserve PUBLIC nghttp3::nghttp3)
elseif(TARGET PkgConfig::NGHTTP3)
    target_link_libraries(microserve PUBLIC PkgConfig::NGHTTP3)
endif()

if(TARGET nghttp2::nghttp2)
    target_link_libraries(microserve PUBLIC nghttp2::nghttp2)
elseif(TARGET PkgConfig::NGHTTP2)
    target_link_libraries(microserve PUBLIC PkgConfig::NGHTTP2)
endif()

if(TARGET ngtcp2::ngtcp2)
    target_link_libraries(microserve PUBLIC ngtcp2::ngtcp2)
elseif(TARGET PkgConfig::NGTCP2)
    target_link_libraries(microserve PUBLIC PkgConfig::NGTCP2)
endif()

if(TARGET ngtcp2::ngtcp2_crypto_ossl)
    target_link_libraries(microserve PUBLIC ngtcp2::ngtcp2_crypto_ossl)
    target_compile_definitions(microserve PUBLIC MICROSERVE_NGTCP2_CRYPTO_OSSL=1)
elseif(TARGET PkgConfig::NGTCP2_CRYPTO_OSSL)
    target_link_libraries(microserve PUBLIC PkgConfig::NGTCP2_CRYPTO_OSSL)
    target_compile_definitions(microserve PUBLIC MICROSERVE_NGTCP2_CRYPTO_OSSL=1)
elseif(TARGET ngtcp2::ngtcp2_crypto_quictls)
    target_link_libraries(microserve PUBLIC ngtcp2::ngtcp2_crypto_quictls)
    target_compile_definitions(microserve PUBLIC MICROSERVE_NGTCP2_CRYPTO_QUICTLS=1)
elseif(TARGET PkgConfig::NGTCP2_CRYPTO_QUICTLS)
    target_link_libraries(microserve PUBLIC PkgConfig::NGTCP2_CRYPTO_QUICTLS)
    target_compile_definitions(microserve PUBLIC MICROSERVE_NGTCP2_CRYPTO_QUICTLS=1)
else()
    message(FATAL_ERROR "ngtcp2 crypto backend not found (ossl or quictls)")
endif()

target_compile_definitions(microserve PUBLIC
        BOOST_ASIO_SEPARATE_COMPILATION
        BOOST_BEAST_SEPARATE_COMPILATION
        SPDLOG_HEADER_ONLY
        SPDLOG_USE_STD_FORMAT
)

add_executable(microserver src/main.cpp)

target_link_libraries(microserver PRIVATE microserve)

target_link_options(microserver PRIVATE
        "LINKER:--allow-multiple-definition"   # Boost loc/loc_bb_ on MinGW modules
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/certs")
    # Copy certs/ next to the microserve binary
    add_custom_command(TARGET microserver POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${CMAKE_CURRENT_SOURCE_DIR}/certs"
                "$<TARGET_FILE_DIR:microserver>/certs"
        COMMENT "Copying certs/ to build directory"
    )
endif()

if(MICROSERVE_BUILD_TAILWIND)
    # --- Tailwind CSS build (scan public/*.html -> public/css/website.css) ---
    set(TAILWIND_INPUT  "${CMAKE_CURRENT_SOURCE_DIR}/res/tailwind.input.css")
    set(TAILWIND_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/public/css/website.css")

    if(WIN32)
        set(TAILWIND_BIN "${CMAKE_CURRENT_SOURCE_DIR}/bin/tailwindcss-windows-x64.exe")
    elseif(APPLE)
        set(TAILWIND_BIN "${CMAKE_CURRENT_SOURCE_DIR}/bin/tailwindcss-macos-arm64")
    elseif(UNIX)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
            set(TAILWIND_BIN "${CMAKE_CURRENT_SOURCE_DIR}/bin/tailwindcss-linux-arm64")
        else()
            set(TAILWIND_BIN "${CMAKE_CURRENT_SOURCE_DIR}/bin/tailwindcss-linux-x64")
        endif()
    else()
        message(WARNING "Unsupported OS for Tailwind CLI; skipping Tailwind CSS build")
        set(TAILWIND_BIN "")
    endif()

    if(TAILWIND_BIN AND EXISTS "${TAILWIND_BIN}")
        file(GLOB_RECURSE PUBLIC_HTML_FILES CONFIGURE_DEPENDS
                "${CMAKE_CURRENT_SOURCE_DIR}/public/*.html"
        )

        add_custom_command(
                OUTPUT "${TAILWIND_OUTPUT}"
                COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_SOURCE_DIR}/public/css"
                COMMAND "${TAILWIND_BIN}"
                -i "${TAILWIND_INPUT}"
                -o "${TAILWIND_OUTPUT}"
        #        --minify
                DEPENDS
                "${TAILWIND_INPUT}"
                ${PUBLIC_HTML_FILES}
                "${TAILWIND_BIN}"
                COMMENT "Building Tailwind CSS -> ${TAILWIND_OUTPUT}"
                VERBATIM
        )

        add_custom_target(tailwind_css DEPENDS "${TAILWIND_OUTPUT}")
        add_dependencies(microserver tailwind_css)
    else()
        if(TAILWIND_BIN)
            message(WARNING "TAILWIND_BIN not found at '${TAILWIND_BIN}'; skipping Tailwind CSS build")
        endif()
    endif()
endif()

if(MICROSERVE_BUILD_TESTS)
    enable_testing()

    include(FetchContent)
    if(NOT TARGET Catch2::Catch2WithMain)
        FetchContent_Declare(Catch2
                GIT_REPOSITORY https://github.com/catchorg/Catch2.git
                GIT_TAG v3.16.0
        )
        FetchContent_MakeAvailable(Catch2)
    endif()

    add_subdirectory(test)
endif()

if(MICROSERVE_INSTALL)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/install.cmake)
endif()
