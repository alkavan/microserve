#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

import microserve.process;
import microserve.config;
import microserve.logging;

namespace fs = std::filesystem;

namespace {

struct Argv {
    std::vector<std::string> storage;
    std::vector<char*> ptrs;

    explicit Argv(const std::initializer_list<std::string> args) {
        storage.emplace_back("microserve");
        for (const auto& a : args)
            storage.push_back(a);
        ptrs.reserve(storage.size());
        for (auto& s : storage)
            ptrs.push_back(s.data());
    }

    [[nodiscard]] int argc() const { return static_cast<int>(ptrs.size()); }
    char** argv() { return ptrs.data(); }
};

std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

TEST_CASE("make_child_argv adds --child and server-index", "[process]") {
    Argv a{"-c", "microserve.yaml", "--ipv6", "-v"};
    const auto child = microserve::make_child_argv(a.argc(), a.argv(), 1);
    REQUIRE(child.size() >= 3);
    CHECK(child.front() == "microserve");
    CHECK(child[1] == "-c");
    CHECK(child[2] == "microserve.yaml");
    bool saw_child = false;
    bool saw_index = false;
    for (const auto& s : child) {
        if (s == "--child")
            saw_child = true;
        if (s == "--server-index=1")
            saw_index = true;
    }
    CHECK(saw_child);
    CHECK(saw_index);
    CHECK(child.back() == "--server-index=1");
}

TEST_CASE("make_child_argv strips an existing --child/--server-index", "[process]") {
    Argv a{"--child", "--server-index", "0", "-c", "x.yaml"};
    const auto child = microserve::make_child_argv(a.argc(), a.argv(), 2);
    int child_n = 0;
    int index_n = 0;
    for (const auto& s : child) {
        if (s == "--child")
            ++child_n;
        if (s.starts_with("--server-index"))
            ++index_n;
    }
    CHECK(child_n == 1);
    CHECK(index_n == 1);
    CHECK(child.back() == "--server-index=2");
}

TEST_CASE("log_site_listen_map writes listener URLs for a resolved site", "[process][logging]") {
    microserve::test::ensure_logger();
    microserve::set_logger_level("info");
    microserve::set_logger_identity("master");

    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto path = fs::temp_directory_path() /
        ("microserve-test-process-" + std::to_string(stamp) + ".log");
    REQUIRE_NOTHROW(microserve::rebind_logger_sinks(path.string(), true));

    microserve::ResolvedServer site;
    site.server_name = "localhost";
    site.listens.push_back({.addr = "0.0.0.0", .port = 9090, .protocol = microserve::Protocol::Http11});
    site.listens.push_back({.addr = "0.0.0.0", .port = 9090, .protocol = microserve::Protocol::Http2c});

    CHECK_NOTHROW(microserve::log_site_listen_map(site));
    microserve::logger_flush();

    const auto tag = std::format("[{:<11}]", "master");
    std::string body;
    for (int i = 0; i < 20; ++i) {
        body = read_file(path);
        if (body.find(tag) != std::string::npos)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    CHECK(body.find(tag) != std::string::npos);
    CHECK(body.find("HTTP/2 (h2c) + HTTP/1.1 listening on http://127.0.0.1:9090/")
          != std::string::npos);

    std::error_code ec;
    fs::remove(path, ec);
    microserve::set_logger_identity("main");
    microserve::set_logger_level("error");
}
