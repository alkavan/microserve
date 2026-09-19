# SPDX-FileCopyrightText: 2025-2026 Igal Alkon
# SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
# SPDX-License-Identifier: BSD-3-Clause

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

add_executable(microserve_tests
        test_config.cpp
        test_detail.cpp
        test_handler.cpp
        test_http2.cpp
        test_http3.cpp
        test_http11.cpp
        test_logging.cpp
        test_main.cpp
        test_process.cpp
        test_proxy.cpp
        test_server.cpp
        test_yaml.cpp
)

target_link_libraries(microserve_tests
        PRIVATE
        microserve
        Catch2::Catch2WithMain
)

file(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}/certs" _microserve_test_certs_dir)
target_compile_definitions(microserve_tests
        PRIVATE
        "MICROSERVE_TEST_CERTS_DIR=\"${_microserve_test_certs_dir}\""
)

target_link_options(microserve_tests PRIVATE
        "LINKER:--allow-multiple-definition"
)

include(Catch)
catch_discover_tests(microserve_tests
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)
