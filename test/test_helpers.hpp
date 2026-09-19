// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <utility>

#ifndef MICROSERVE_TEST_CERTS_DIR
#define MICROSERVE_TEST_CERTS_DIR "certs"
#endif

namespace microserve::test {

void ensure_logger();
unsigned short ephemeral_tcp_port();
unsigned short ephemeral_udp_port();

inline std::string certs_dir()
{
    return MICROSERVE_TEST_CERTS_DIR;
}

inline bool file_exists(const std::string& path)
{
    if (FILE* f = std::fopen(path.c_str(), "rb")) {
        std::fclose(f);
        return true;
    }
    return false;
}

inline std::pair<std::string, std::string> require_tls_files()
{
    const auto dir = certs_dir();
    auto cert = dir + "/server.crt";
    auto key = dir + "/server.key";
    if (!file_exists(cert) || !file_exists(key)) {
        SKIP("test certificates not found under " + dir);
    }
    return {std::move(cert), std::move(key)};
}

inline void sleep_ms(const int ms)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

template <typename IoContext, typename Fn>
void run_with_server_ioc(IoContext& ioc, Fn&& fn)
{
    std::thread worker([&] { ioc.run(); });
    try {
        fn();
    } catch (...) {
        ioc.stop();
        worker.join();
        throw;
    }
    ioc.stop();
    worker.join();
}

} // namespace microserve::test
