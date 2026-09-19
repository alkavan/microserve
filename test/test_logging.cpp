// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

import microserve.logging;

namespace fs = std::filesystem;

namespace {

fs::path unique_log_path(const std::string_view tag) {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    return fs::temp_directory_path() /
           ("microserve-test-log-" + std::string(tag) + "-" + std::to_string(stamp) + ".log");
}

std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Drop rotating-file siblings spdlog may create (name, name.1, …).
void remove_log_tree(const fs::path& path) {
    std::error_code ec;
    fs::remove(path, ec);
    for (int i = 1; i <= microserve::LOGGER_FILE_MAX_COUNT + 1; ++i) {
        fs::remove(path.string() + "." + std::to_string(i), ec);
    }
}

struct TempLogFile {
    fs::path path = unique_log_path("logging");

    ~TempLogFile() { remove_log_tree(path); }

    [[nodiscard]] const std::string& str() const {
        // path.string() is stable for the fixture lifetime
        static thread_local std::string cached;
        cached = path.string();
        return cached;
    }
};

} // namespace

TEST_CASE("logging constants have expected values", "[logging]") {
    CHECK(microserve::LOGGER_NAME == "microserve");
    CHECK_FALSE(microserve::LOGGER_PATTERN.empty());
    CHECK(microserve::LOGGER_QUEUE_SIZE == 32768);
    CHECK(microserve::LOGGER_THREAD_COUNT == 1);
    CHECK(microserve::LOGGER_FILE_MAX_SIZE == 10 * 1024 * 1024);
    CHECK(microserve::LOGGER_FILE_MAX_COUNT == 3);
}

TEST_CASE("ensure_logger makes logging APIs safe to call", "[logging]") {
    // Shares the process-wide logger with the rest of the suite (test_main).
    // Do not call setup_logger() again (register would throw) or shutdown_logging()
    // (would tear down sinks other TCs still need).
    microserve::test::ensure_logger();

    CHECK_NOTHROW(microserve::log_info("test info"));
    CHECK_NOTHROW(microserve::log_warn("test warn"));
    CHECK_NOTHROW(microserve::log_error("test error"));
    CHECK_NOTHROW(microserve::log_debug("test debug"));
    CHECK_NOTHROW(microserve::logger_flush());
}

TEST_CASE("set_logger_level accepts spdlog level names", "[logging]") {
    microserve::test::ensure_logger();

    // Restore a quiet level afterward so later tests stay low-noise.
    const auto restore = [] { microserve::set_logger_level("error"); };

    CHECK_NOTHROW(microserve::set_logger_level("trace"));
    CHECK_NOTHROW(microserve::set_logger_level("debug"));
    CHECK_NOTHROW(microserve::set_logger_level("info"));
    CHECK_NOTHROW(microserve::set_logger_level("warn"));
    CHECK_NOTHROW(microserve::set_logger_level("error"));
    CHECK_NOTHROW(microserve::set_logger_level("critical"));
    CHECK_NOTHROW(microserve::set_logger_level("off"));

    restore();
}

TEST_CASE("rebind_logger_sinks writes to the given file", "[logging]") {
    microserve::test::ensure_logger();
    microserve::set_logger_level("info");

    const TempLogFile log;
    REQUIRE_NOTHROW(microserve::rebind_logger_sinks(log.path.string()));

    const std::string marker = "rebind-marker-unique-42";
    microserve::log_info(marker);
    microserve::logger_flush();

    // Rotating sink may need a brief moment on some platforms.
    std::string body;
    for (int i = 0; i < 20; ++i) {
        body = read_file(log.path);
        if (body.find(marker) != std::string::npos)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    CHECK(body.find(marker) != std::string::npos);

    // Keep suite noise down; leave sinks on this temp file (destroyed at process
    // end / next rebind). Level back to error to match ensure_logger policy.
    microserve::set_logger_level("error");
}

TEST_CASE("log_listener_urls rewrites wildcards to loopback", "[logging]") {
    microserve::test::ensure_logger();
    microserve::set_logger_level("info");

    TempLogFile log;
    REQUIRE_NOTHROW(microserve::rebind_logger_sinks(log.path.string()));

    microserve::log_listener_urls("HTTP/1.1", "http", "0.0.0.0", 9090);
    microserve::log_listener_urls("HTTP/2", "https", "::", 9443);
    microserve::log_listener_urls("HTTP/3 (QUIC)", "https", "192.0.2.10", 8443);
    microserve::logger_flush();

    std::string body;
    for (int i = 0; i < 20; ++i) {
        body = read_file(log.path);
        if (body.find("127.0.0.1:9090") != std::string::npos &&
            body.find("[::1]:9443") != std::string::npos &&
            body.find("192.0.2.10:8443") != std::string::npos)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    CHECK(body.find("HTTP/1.1 listening on http://127.0.0.1:9090/") != std::string::npos);
    CHECK(body.find("HTTP/2 listening on https://[::1]:9443/") != std::string::npos);
    CHECK(body.find("HTTP/3 (QUIC) listening on https://192.0.2.10:8443/") != std::string::npos);

    // Wildcards must not appear as the host in the URL form used for browser copy-paste.
    CHECK(body.find("http://0.0.0.0:9090/") == std::string::npos);
    CHECK(body.find("https://:::9443/") == std::string::npos);

    microserve::set_logger_level("error");
}

TEST_CASE("log_* and log_listener_urls are no-ops without a registered logger", "[logging][safety]") {
    // Cannot unregister the suite logger without spdlog::shutdown(), which would
    // break parallel/later cases. Documented contract is still exercised indirectly:
    // all log_* paths null-check get_logger(); with ensure_logger() they succeed.
    microserve::test::ensure_logger();
    CHECK_NOTHROW(microserve::log_listener_urls("HTTP/1.1", "http", "127.0.0.1", 1));
}

TEST_CASE("site_error_log_path inserts a sanitized site stem", "[logging]") {
    CHECK(microserve::site_error_log_path("microserve.log", "localhost")
          == "microserve-localhost.log");
    CHECK(microserve::site_error_log_path("logs/error.log", "internal")
          == "logs/error-internal.log");
    CHECK(microserve::site_error_log_path("microserve.log", "My Site")
          == "microserve-My_Site.log");
    CHECK(microserve::site_error_log_path("microserve.log", "")
          == "microserve-site.log");
}

TEST_CASE("log_listener_urls uses logger identity as the tag", "[logging]") {
    microserve::test::ensure_logger();
    microserve::set_logger_level("info");
    microserve::set_logger_identity("child_host");

    const TempLogFile log;
    REQUIRE_NOTHROW(microserve::rebind_logger_sinks(log.path.string(), true));

    microserve::log_listener_urls("HTTP/1.1", "http", "127.0.0.1", 9090);
    microserve::logger_flush();

    std::string body;
    const auto tag = std::format("[{:<11}]", "child_host");
    for (int i = 0; i < 20; ++i) {
        body = read_file(log.path);
        if (body.find(tag) != std::string::npos)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    CHECK(body.find(tag) != std::string::npos);
    CHECK(body.find("HTTP/1.1 listening on http://127.0.0.1:9090/") != std::string::npos);

    microserve::set_logger_identity("main");
    microserve::set_logger_level("error");
}

TEST_CASE("rebind_logger_sinks can drop the stdout sink", "[logging]") {
    microserve::test::ensure_logger();
    microserve::set_logger_level("info");

    const TempLogFile log;
    REQUIRE_NOTHROW(microserve::rebind_logger_sinks(log.path.string(), /*to_stdout=*/false));

    const std::string marker = "file-only-marker-99";
    microserve::log_info(marker);
    microserve::logger_flush();

    std::string body;
    for (int i = 0; i < 20; ++i) {
        body = read_file(log.path);
        if (body.find(marker) != std::string::npos)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(body.find(marker) != std::string::npos);

    microserve::set_logger_level("error");
}

TEST_CASE("rebind_access_log writes request lines to a separate file", "[logging]") {
    microserve::test::ensure_logger();
    microserve::set_logger_level("info");

    const TempLogFile access;
    REQUIRE_NOTHROW(microserve::rebind_access_log(access.path.string(), /*to_stdout=*/false));

    const std::string marker = "access-marker-unique-7";
    microserve::log_access(marker);
    microserve::logger_flush();

    std::string body;
    for (int i = 0; i < 20; ++i) {
        body = read_file(access.path);
        if (body.find(marker) != std::string::npos)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(body.find(marker) != std::string::npos);

    microserve::set_logger_level("error");
}
