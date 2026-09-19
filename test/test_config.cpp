// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

import microserve.config;

using microserve::Config;
using microserve::bind_addrs;
using microserve::count_verbosity_args;
using microserve::is_valid_error_log_level;
using microserve::parse_arguments;
using microserve::parse_bind;
using microserve::resolve_bind_addr;
using microserve::resolve_config;
using microserve::Protocol;
using microserve::ListenSpec;
using microserve::BackendConfig;
using microserve::make_cli_server;
using microserve::expand_listen;
using microserve::parse_listen;
using microserve::parse_protocol;
using microserve::proxy_pass_backend_name;
using microserve::FederationRole;
using microserve::FederationMembership;
using microserve::parse_federation_role;
using microserve::parse_federation_membership;
using microserve::federation_node_urn;
using microserve::load_config;
using microserve::load_federation;

namespace {

// Build a mutable argv suitable for Boost.ProgramOptions / count_verbosity_args.
struct Argv {
    std::vector<std::string> storage;
    std::vector<char*> ptrs;

    explicit Argv(const std::initializer_list<std::string> args) {
        storage.emplace_back("microserve"); // argv[0]
        for (const auto& a : args)
            storage.push_back(a);
        ptrs.reserve(storage.size());
        for (auto& s : storage)
            ptrs.push_back(s.data());
    }

    [[nodiscard]] int argc() const { return static_cast<int>(ptrs.size()); }
    char** argv() { return ptrs.data(); }
};

struct TempFile {
    std::string path;

    explicit TempFile(const std::string& contents, std::string name = "microserve_yaml_test.yaml")
        : path(std::move(name))
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << contents;
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    ~TempFile()
    {
        std::remove(path.c_str());
    }
};

} // namespace

TEST_CASE("is_valid_error_log_level accepts known levels", "[config]") {
    CHECK(is_valid_error_log_level("trace"));
    CHECK(is_valid_error_log_level("debug"));
    CHECK(is_valid_error_log_level("info"));
    CHECK(is_valid_error_log_level("warn"));
    CHECK(is_valid_error_log_level("error"));
    CHECK(is_valid_error_log_level("crit"));
}

TEST_CASE("is_valid_error_log_level rejects unknown levels", "[config]") {
    CHECK_FALSE(is_valid_error_log_level(""));
    CHECK_FALSE(is_valid_error_log_level("warning"));
    CHECK_FALSE(is_valid_error_log_level("TRACE"));
    CHECK_FALSE(is_valid_error_log_level("fatal"));
    CHECK_FALSE(is_valid_error_log_level("info "));
}

TEST_CASE("count_verbosity_args counts long and short forms", "[config]") {
    {
        Argv a{};
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 0);
    }
    {
        Argv a{"--verbose"};
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 1);
    }
    {
        Argv a{"--verbose", "--verbose"};
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 2);
    }
    {
        Argv a{"-v"};
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 1);
    }
    {
        Argv a{"-vv"};
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 2);
    }
    {
        Argv a{"-vvv"};
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 3);
    }
    {
        Argv a{"-hv"}; // mixed short cluster
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 1);
    }
    {
        Argv a{"-v", "--verbose", "-vv"};
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 4);
    }
}

TEST_CASE("count_verbosity_args ignores non-verbosity options and stops at --", "[config]") {
    {
        Argv a{"--dir", "./public", "--http-bind", "0.0.0.0:8080"};
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 0);
    }
    {
        Argv a{"-v", "--", "-vv", "--verbose"};
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 1);
    }
    {
        Argv a{"--verbose-not-a-real-flag"}; // other long option
        CHECK(count_verbosity_args(a.argc(), a.argv()) == 0);
    }
}

TEST_CASE("parse_bind splits host:port including IPv6-style last colon", "[config]") {
    {
        auto [host, port] = parse_bind("0.0.0.0:9090");
        CHECK(host == "0.0.0.0");
        CHECK(port == 9090);
    }
    {
        auto [host, port] = parse_bind("127.0.0.1:443");
        CHECK(host == "127.0.0.1");
        CHECK(port == 443);
    }
    {
        auto [host, port] = parse_bind("[::1]:9443");
        CHECK(host == "[::1]");
        CHECK(port == 9443);
    }
    {
        auto [host, port] = parse_bind("localhost:1");
        CHECK(host == "localhost");
        CHECK(port == 1);
    }
}

TEST_CASE("parse_bind throws on missing colon", "[config]") {
    CHECK_THROWS_AS(parse_bind("no-port"), std::runtime_error);
    CHECK_THROWS_AS(parse_bind(""), std::runtime_error);
}

TEST_CASE("resolve_bind_addr keeps port and forces wildcard family", "[config]") {
    {
        auto [addr, port] = resolve_bind_addr("127.0.0.1:9090", false);
        CHECK(addr == "0.0.0.0");
        CHECK(port == 9090);
    }
    {
        auto [addr, port] = resolve_bind_addr("127.0.0.1:9443", true);
        CHECK(addr == "::");
        CHECK(port == 9443);
    }
}

TEST_CASE("bind_addrs force_ipv4_only yields IPv4 only", "[config]") {
    const auto addrs = bind_addrs("1.2.3.4:8080", /*ipv6_flag=*/true, /*no_ipv4=*/false,
                                  /*force_ipv4_only=*/true);
    REQUIRE(addrs.size() == 1);
    CHECK(addrs[0].first == "0.0.0.0");
    CHECK(addrs[0].second == 8080);
}

TEST_CASE("bind_addrs no_ipv4 yields IPv6 only", "[config]") {
    const auto addrs = bind_addrs("1.2.3.4:8080", /*ipv6_flag=*/false, /*no_ipv4=*/true,
                                  /*force_ipv4_only=*/false);
    REQUIRE(addrs.size() == 1);
    CHECK(addrs[0].first == "::");
    CHECK(addrs[0].second == 8080);
}

TEST_CASE("bind_addrs dual-stack when ipv6_flag set", "[config]") {
    const auto addrs = bind_addrs("1.2.3.4:8080", /*ipv6_flag=*/true, /*no_ipv4=*/false,
                                  /*force_ipv4_only=*/false);
    REQUIRE(addrs.size() == 2);
    CHECK(addrs[0].first == "0.0.0.0");
    CHECK(addrs[0].second == 8080);
    CHECK(addrs[1].first == "::");
    CHECK(addrs[1].second == 8080);
}

TEST_CASE("bind_addrs default is IPv4 only", "[config]") {
    const auto addrs = bind_addrs("1.2.3.4:8080", /*ipv6_flag=*/false, /*no_ipv4=*/false,
                                  /*force_ipv4_only=*/false);
    REQUIRE(addrs.size() == 1);
    CHECK(addrs[0].first == "0.0.0.0");
    CHECK(addrs[0].second == 8080);
}

TEST_CASE("parse_arguments applies defaults", "[config]") {
    Argv a{};
    Config config;
    std::string config_file = "should-be-cleared";

    REQUIRE(parse_arguments(a.argc(), a.argv(), config, config_file));

    CHECK(config_file.empty());
    CHECK(config.dir == ".");
    CHECK(config.http_bind == "0.0.0.0:9090");
    CHECK(config.https_bind == "0.0.0.0:9443");
    CHECK(config.http3_bind == "0.0.0.0:9443");
    CHECK_FALSE(config.http11);
    CHECK_FALSE(config.ipv6);
    CHECK_FALSE(config.no_ipv4);
    CHECK(config.cert == "certs/server.crt");
    CHECK(config.key == "certs/server.key");
    CHECK(config.verbosity == 0);
}

TEST_CASE("parse_arguments reads explicit options", "[config]") {
    Argv a{
        "-c", "microserve.yaml",
        "--dir", "./public",
        "--http-bind", "127.0.0.1:8080",
        "--https-bind", "0.0.0.0:8443",
        "--http3-bind", "0.0.0.0:8443",
        "--http11",
        "--ipv6",
        "--no-ipv4",
        "--cert", "tls/cert.pem",
        "--key", "tls/key.pem",
        "-vv",
    };

    Config config;
    std::string config_file;

    REQUIRE(parse_arguments(a.argc(), a.argv(), config, config_file));

    CHECK(config_file == "microserve.yaml");
    CHECK(config.dir == "./public");
    CHECK(config.http_bind == "127.0.0.1:8080");
    CHECK(config.https_bind == "0.0.0.0:8443");
    CHECK(config.http3_bind == "0.0.0.0:8443");
    CHECK(config.http11);
    CHECK(config.ipv6);
    CHECK(config.no_ipv4);
    CHECK(config.cert == "tls/cert.pem");
    CHECK(config.key == "tls/key.pem");
    CHECK(config.verbosity == 2);
}

TEST_CASE("parse_arguments --help returns false", "[config]") {
    Argv a{"--help"};
    Config config;
    std::string config_file;

    // Prints help to stdout; should not throw and should signal "do not run".
    CHECK_FALSE(parse_arguments(a.argc(), a.argv(), config, config_file));
}

TEST_CASE("Config default member values", "[config]") {
    const Config c;

    CHECK(c.verbosity == 0);
    CHECK(c.address == "127.0.0.1");
    CHECK(c.http_bind == "0.0.0.0:9090");
    CHECK(c.https_bind == "0.0.0.0:9443");
    CHECK(c.http3_bind == "0.0.0.0:9443");
    CHECK_FALSE(c.http11);
    CHECK_FALSE(c.ipv6);
    CHECK_FALSE(c.no_ipv4);
    CHECK(c.cert == "certs/server.crt");
    CHECK(c.key == "certs/server.key");
    CHECK(c.dir == "./public");
    CHECK(c.timeouts.connect == std::chrono::seconds{5});
    CHECK(c.timeouts.read == std::chrono::seconds{10});
    CHECK(c.timeouts.write == std::chrono::seconds{10});
    CHECK(c.microserve.error_log == "microserve.log");
    CHECK(c.microserve.error_log_level == "warn");
    CHECK(c.microserve.pid == "microserve.pid");
    CHECK(c.microserve.default_type == "application/octet-stream");
    CHECK(c.servers.empty());
    CHECK_FALSE(c.federation.enabled);
    CHECK(c.federation.role == FederationRole::Standalone);
    CHECK(c.federation.membership == FederationMembership::None);
    CHECK(c.federation.block_unverified);
    CHECK(c.federation.urn_nid == "microserve");
    CHECK_FALSE(c.cli_federation_set);
    CHECK(c.federation_file.empty());
    CHECK_FALSE(c.cli_child);
    CHECK_FALSE(c.cli_server_index_set);
    CHECK(c.cli_server_index == -1);
    CHECK_FALSE(c.cli_log_stdout);
    CHECK_FALSE(c.cli_service);
}

TEST_CASE("parse_protocol accepts names and aliases", "[config]") {
    CHECK(parse_protocol("http11") == Protocol::Http11);
    CHECK(parse_protocol("http1.1") == Protocol::Http11);
    CHECK(parse_protocol("http2c") == Protocol::Http2c);
    CHECK(parse_protocol("h2c") == Protocol::Http2c);
    CHECK(parse_protocol("http2clear") == Protocol::Http2c);
    CHECK(parse_protocol("http2") == Protocol::Http2);
    CHECK(parse_protocol("h2") == Protocol::Http2);
    CHECK(parse_protocol("http3") == Protocol::Http3);
    CHECK(parse_protocol("H3") == Protocol::Http3);
    CHECK_THROWS_AS(parse_protocol("ftp"), std::runtime_error);
}

TEST_CASE("parse_listen accepts port, host:port, and IPv6", "[config]") {
    {
        auto [host, port] = parse_listen("9090");
        CHECK(host.empty());
        CHECK(port == 9090);
    }
    {
        auto [host, port] = parse_listen("127.0.0.1:9191");
        CHECK(host == "127.0.0.1");
        CHECK(port == 9191);
    }
    {
        auto [host, port] = parse_listen("[::1]:9443");
        CHECK(host == "::1");
        CHECK(port == 9443);
    }
}

TEST_CASE("expand_listen keeps explicit addresses even with ipv6", "[config]") {
    const auto v4 = expand_listen("127.0.0.1:9090", true, false);
    REQUIRE(v4.size() == 1);
    CHECK(v4[0].first == "127.0.0.1");
    CHECK(v4[0].second == 9090);

    const auto wild = expand_listen("9090", false, false);
    REQUIRE(wild.size() == 1);
    CHECK(wild[0].first == "0.0.0.0");

    const auto dual = expand_listen("9090", true, false);
    REQUIRE(dual.size() == 2);
    CHECK(dual[0].first == "0.0.0.0");
    CHECK(dual[1].first == "::");
}

TEST_CASE("resolve_config implicit server when none configured", "[config][resolve]") {
    const Config c;
    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    CHECK(r.servers[0].server_name == "localhost");
    REQUIRE(r.servers[0].listens.size() == 1);
    CHECK(r.servers[0].listens[0].addr == "0.0.0.0");
    CHECK(r.servers[0].listens[0].port == 9090);
    CHECK(r.servers[0].listens[0].protocol == Protocol::Http2c);
    CHECK(r.servers[0].backends.empty());
}

TEST_CASE("resolve_config CLI listen ignores YAML servers", "[config][resolve]") {
    Config c;
    c.cli_listen_set = true;
    c.cli_listen = {"127.0.0.1:9191"};
    c.cli_proto_set = true;
    c.cli_proto = {Protocol::Http11};

    Config::ServerConfig yaml;
    yaml.server_name = "from-yaml";
    yaml.listen.push_back(ListenSpec{.bind = "80", .protocols = {}});
    yaml.protocol = {Protocol::Http2};
    c.servers.push_back(yaml);

    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    CHECK(r.servers[0].server_name == "localhost");
    REQUIRE(r.servers[0].listens.size() == 1);
    CHECK(r.servers[0].listens[0].addr == "127.0.0.1");
    CHECK(r.servers[0].listens[0].port == 9191);
    CHECK(r.servers[0].listens[0].protocol == Protocol::Http11);
}

TEST_CASE("resolve_config ipv6 expands wildcards only", "[config][resolve]") {
    Config c;
    c.ipv6 = true;

    Config::ServerConfig pub;
    pub.server_name = "localhost";
    pub.listen.push_back(ListenSpec{.bind = "9090", .protocols = {}});
    pub.protocol = {Protocol::Http11};

    Config::ServerConfig internal;
    internal.server_name = "internal";
    internal.listen.push_back(ListenSpec{.bind = "127.0.0.1:9191", .protocols = {Protocol::Http11}});

    c.servers = {pub, internal};

    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 2);
    REQUIRE(r.servers[0].listens.size() == 2);
    CHECK(r.servers[0].listens[0].addr == "0.0.0.0");
    CHECK(r.servers[0].listens[1].addr == "::");
    REQUIRE(r.servers[1].listens.size() == 1);
    CHECK(r.servers[1].listens[0].addr == "127.0.0.1");
    CHECK(r.servers[1].listens[0].port == 9191);
}

TEST_CASE("resolve_config first site keeps overlapping listen", "[config][resolve]") {
    Config c;
    Config::ServerConfig a;
    a.server_name = "first";
    a.listen.push_back(ListenSpec{.bind = "0.0.0.0:443", .protocols = {Protocol::Http2}});
    a.tls_cert = "a.crt";
    a.tls_key = "a.key";

    Config::ServerConfig b;
    b.server_name = "second";
    b.listen.push_back(ListenSpec{.bind = "127.0.0.1:443", .protocols = {Protocol::Http2}});
    b.tls_cert = "b.crt";
    b.tls_key = "b.key";

    c.servers = {a, b};

    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    CHECK(r.servers[0].server_name == "first");
    REQUIRE_FALSE(r.warnings.empty());
    CHECK(r.warnings.back().find("second") != std::string::npos);
}

TEST_CASE("resolve_config http2 and http3 share a port", "[config][resolve]") {
    Config c;
    Config::ServerConfig s;
    s.server_name = "localhost";
    s.listen.push_back(ListenSpec{.bind = "9443", .protocols = {Protocol::Http2, Protocol::Http3}});
    s.tls_cert = "s.crt";
    s.tls_key = "s.key";
    c.servers.push_back(s);

    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    REQUIRE(r.servers[0].listens.size() == 2);
    CHECK(r.servers[0].listens[0].protocol == Protocol::Http2);
    CHECK(r.servers[0].listens[1].protocol == Protocol::Http3);
    CHECK(r.servers[0].listens[0].port == 9443);
    CHECK(r.servers[0].listens[1].port == 9443);
    CHECK(r.warnings.empty());
}

TEST_CASE("resolve_config drops mixed cleartext and TLS on one TCP socket", "[config][resolve]") {
    Config c;
    Config::ServerConfig s;
    s.server_name = "localhost";
    s.listen.push_back(ListenSpec{.bind = "9090", .protocols = {Protocol::Http11, Protocol::Http2}});
    s.tls_cert = "s.crt";
    s.tls_key = "s.key";
    c.servers.push_back(s);

    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    REQUIRE(r.servers[0].listens.size() == 1);
    CHECK(r.servers[0].listens[0].protocol == Protocol::Http11);
    REQUIRE_FALSE(r.warnings.empty());
}

TEST_CASE("resolve_config copies only backends used by the site", "[config][resolve]") {
    Config c;
    c.backends = {
        BackendConfig{.name = "api", .servers = {"127.0.0.1:9934"}},
        BackendConfig{.name = "other", .servers = {"127.0.0.1:1"}},
    };

    Config::ServerConfig s;
    s.server_name = "localhost";
    s.listen.push_back(ListenSpec{.bind = "9090", .protocols = {Protocol::Http11}});
    s.locations.push_back({.path = "/api", .root = "", .auth = "", .proxy_pass = "http://api"});
    c.servers.push_back(s);

    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    REQUIRE(r.servers[0].backends.size() == 1);
    CHECK(r.servers[0].backends[0].name == "api");
    CHECK(proxy_pass_backend_name("http://api", c.backends) == "api");
    CHECK_FALSE(proxy_pass_backend_name("http://127.0.0.1:9934", c.backends).has_value());
}

TEST_CASE("resolve_config skips site with unknown backend", "[config][resolve]") {
    Config c;
    Config::ServerConfig keep;
    keep.server_name = "ok";
    keep.listen.push_back(ListenSpec{.bind = "9090", .protocols = {Protocol::Http11}});

    Config::ServerConfig bad;
    bad.server_name = "bad";
    bad.listen.push_back(ListenSpec{.bind = "9191", .protocols = {Protocol::Http11}});
    bad.locations.push_back({.path = "/api", .root = "", .auth = "", .proxy_pass = "backend:missing"});

    c.servers = {keep, bad};

    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    CHECK(r.servers[0].server_name == "ok");
    REQUIRE_FALSE(r.warnings.empty());
}

TEST_CASE("parse_arguments --listen sets cli override; --ipv6 does not", "[config]") {
    {
        Argv a{"--listen", "9090", "--proto", "http11"};
        Config config;
        std::string config_file;
        REQUIRE(parse_arguments(a.argc(), a.argv(), config, config_file));
        CHECK(config.cli_overrides_servers());
        CHECK(config.cli_listen_set);
        CHECK(config.cli_proto_set);
        REQUIRE(config.cli_listen.size() == 1);
        CHECK(config.cli_listen[0] == "9090");
    }
    {
        Argv a{"--ipv6"};
        Config config;
        std::string config_file;
        REQUIRE(parse_arguments(a.argc(), a.argv(), config, config_file));
        CHECK_FALSE(config.cli_overrides_servers());
        CHECK(config.ipv6);
    }
    {
        Argv a{"-f", "federation.yaml"};
        Config config;
        std::string config_file;
        REQUIRE(parse_arguments(a.argc(), a.argv(), config, config_file));
        CHECK(config.cli_federation_set);
        CHECK(config.federation_file == "federation.yaml");
        CHECK_FALSE(config.cli_overrides_servers());
        CHECK_FALSE(config.federation.enabled);
    }
    {
        Argv a{"--child", "--server-index", "1"};
        Config config;
        std::string config_file;
        REQUIRE(parse_arguments(a.argc(), a.argv(), config, config_file));
        CHECK(config.cli_child);
        CHECK(config.cli_server_index_set);
        CHECK(config.cli_server_index == 1);
        CHECK_FALSE(config.cli_overrides_servers());
    }
    {
        Argv a{"--log-stdout"};
        Config config;
        std::string config_file;
        REQUIRE(parse_arguments(a.argc(), a.argv(), config, config_file));
        CHECK(config.cli_log_stdout);
        CHECK_FALSE(config.cli_overrides_servers());
    }
    {
        Argv a{"--service"};
        Config config;
        std::string config_file;
        REQUIRE(parse_arguments(a.argc(), a.argv(), config, config_file));
        CHECK(config.cli_service);
        CHECK_FALSE(config.cli_overrides_servers());
    }
}

TEST_CASE("parse_federation_role and membership", "[config][federation]") {
    CHECK(parse_federation_role("standalone") == FederationRole::Standalone);
    CHECK(parse_federation_role("member") == FederationRole::Member);
    CHECK(parse_federation_role("hub") == FederationRole::Hub);
    CHECK(parse_federation_role("federation") == FederationRole::Hub);
    CHECK_THROWS_AS(parse_federation_role("root"), std::runtime_error);

    CHECK(parse_federation_membership("none") == FederationMembership::None);
    CHECK(parse_federation_membership("unverified") == FederationMembership::Unverified);
    CHECK(parse_federation_membership("certified") == FederationMembership::Certified);
    CHECK_THROWS_AS(parse_federation_membership("pending"), std::runtime_error);

    CHECK(federation_node_urn("fed-node-1") == "urn:microserve:node:fed-node-1");
    CHECK(federation_node_urn("fed-node-1", "microserve") == "urn:microserve:node:fed-node-1");
    CHECK(federation_node_urn("fed-node-1", "") == "urn::node:fed-node-1");
    CHECK(federation_node_urn("").empty());
    CHECK(federation_node_urn("", "microserve").empty());
}

TEST_CASE("resolve_config stand-alone federation overlay is a no-op", "[config][federation]") {
    Config c;
    c.federation.enabled = false;
    c.federation.role = FederationRole::Hub;
    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    CHECK_FALSE(r.federation_enabled);
    CHECK_FALSE(r.federation_hub);
    CHECK_FALSE(r.federation_blocked);
}

TEST_CASE("resolve_config hub is a federation node and still serves", "[config][federation]") {
    Config c;
    c.federation.enabled = true;
    c.federation.role = FederationRole::Hub;
    c.federation.membership = FederationMembership::Certified;
    c.federation.node_id = "hub-1";
    c.federation.cert = "fed.crt";
    c.federation.key = "fed.key";
    c.federation.block_unverified = true;

    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    CHECK(r.federation_enabled);
    CHECK(r.federation_hub);
    CHECK_FALSE(r.federation_blocked);
}

TEST_CASE("resolve_config hub without certified membership is not a hub", "[config][federation]") {
    Config c;
    c.federation.enabled = true;
    c.federation.role = FederationRole::Hub;
    c.federation.membership = FederationMembership::None;

    const auto [
        servers,
        warnings,
        federation_enabled,
        federation_hub,
        federation_blocked
    ] = resolve_config(c);

    REQUIRE(servers.size() == 1);
    CHECK(federation_enabled);
    CHECK_FALSE(federation_hub);
    CHECK_FALSE(federation_blocked);
    REQUIRE_FALSE(warnings.empty());
}

TEST_CASE("resolve_config blocks unverified members when hub policy forbids them", "[config][federation]") {
    Config c;
    c.federation.enabled = true;
    c.federation.role = FederationRole::Member;
    c.federation.membership = FederationMembership::Unverified;
    c.federation.block_unverified = true;
    c.federation.allow_unverified = false;

    const auto [
        servers,
        warnings,
        federation_enabled,
        federation_hub,
        federation_blocked
    ] = resolve_config(c);

    CHECK(servers.empty());
    CHECK(federation_enabled);
    CHECK_FALSE(federation_hub);
    CHECK(federation_blocked);
    REQUIRE_FALSE(warnings.empty());
}

TEST_CASE("resolve_config unverified member serves if hub allows it", "[config][federation]") {
    Config c;
    c.federation.enabled = true;
    c.federation.role = FederationRole::Member;
    c.federation.membership = FederationMembership::Unverified;
    c.federation.block_unverified = false;
    c.federation.allow_unverified = true;

    const auto r = resolve_config(c);
    REQUIRE(r.servers.size() == 1);
    CHECK_FALSE(r.federation_blocked);
}

TEST_CASE("resolve_config revoked federation certificate blocks the node", "[config][federation]") {
    Config c;
    c.federation.enabled = true;
    c.federation.role = FederationRole::Member;
    c.federation.membership = FederationMembership::Certified;
    c.federation.node_id = "node-9";
    c.federation.cert = "fed.crt";
    c.federation.key = "fed.key";
    c.federation.revoked = {"node-9"};

    const auto r = resolve_config(c);
    CHECK(r.servers.empty());
    CHECK(r.federation_blocked);
}

TEST_CASE("load_config throws when the file does not exist", "[config]")
{
    REQUIRE_THROWS_AS(load_config("no-such-microserve.yaml"), std::runtime_error);
}

TEST_CASE("load_config reads microserve, timeouts, and servers", "[config]")
{
    microserve::test::ensure_logger();

    TempFile file(
        "microserve:\n"
        "  error_log: logs/error.log\n"
        "  error_log_level: debug\n"
        "  pid: /tmp/microserve.pid\n"
        "  default_type: text/plain\n"
        "timeouts:\n"
        "  connect: 3\n"
        "  read: 11\n"
        "  write: 13\n"
        "servers:\n"
        "  - listen: 8443\n"
        "    server_name: example.test\n"
        "    protocol: http2\n"
        "    tls_cert: certs/server.crt\n"
        "    tls_key: certs/server.key\n"
        "    error_log: logs/site-error.log\n"
        "    access_log: logs/access.log\n"
        "    access_log_format: combined\n"
        "    indexes:\n"
        "      - index.html\n"
        "      - index.htm\n"
        "    locations:\n"
        "      - path: /\n"
        "        root: public\n"
        "        auth: off\n"
        "      - path: /api\n"
        "        proxy_pass: http://127.0.0.1:9000\n");

    const auto cfg = load_config(file.path);

    REQUIRE(cfg.microserve.error_log == "logs/error.log");
    REQUIRE(cfg.microserve.error_log_level == "debug");
    REQUIRE(cfg.microserve.pid == "/tmp/microserve.pid");
    REQUIRE(cfg.microserve.default_type == "text/plain");

    REQUIRE(cfg.timeouts.connect == std::chrono::seconds(3));
    REQUIRE(cfg.timeouts.read == std::chrono::seconds(11));
    REQUIRE(cfg.timeouts.write == std::chrono::seconds(13));

    REQUIRE(cfg.servers.size() == 1);

    const auto& [
        server_name,
        listen,
        protocol,
        tls_cert,
        tls_key,
        indexes,
        locations,
        error_log,
        access_log,
        access_log_format
    ] = cfg.servers[0];

    REQUIRE(listen.size() == 1);
    REQUIRE(listen[0].bind == "8443");
    REQUIRE(listen[0].protocols.empty());
    REQUIRE(server_name == "example.test");
    REQUIRE(protocol.size() == 1);
    REQUIRE(protocol[0] == Protocol::Http2);
    REQUIRE(tls_cert == "certs/server.crt");
    REQUIRE(tls_key == "certs/server.key");
    REQUIRE(error_log == "logs/site-error.log");
    REQUIRE(access_log == "logs/access.log");
    REQUIRE(access_log_format == "combined");
    REQUIRE(indexes.size() == 2);
    REQUIRE(indexes[0] == "index.html");
    REQUIRE(locations.size() == 2);
    REQUIRE(locations[0].path == "/");
    REQUIRE(locations[0].root == "public");
    REQUIRE(locations[0].auth == "off");
    REQUIRE(locations[1].proxy_pass == "http://127.0.0.1:9000");
    REQUIRE(cfg.address == "example.test");
}

TEST_CASE("load_config maps localhost server_name to 127.0.0.1", "[config]")
{
    microserve::test::ensure_logger();

    const TempFile file(
        "servers:\n"
        "  - listen: 80\n"
        "    server_name: localhost\n",
        "microserve_yaml_localhost.yaml");

    const auto cfg = load_config(file.path);
    REQUIRE(cfg.servers.size() == 1);
    REQUIRE(cfg.address == "127.0.0.1");
}

TEST_CASE("load_config falls back when error_log_level is invalid", "[config]")
{
    microserve::test::ensure_logger();

    const TempFile file(
        "microserve:\n"
        "  error_log_level: not-a-level\n",
        "microserve_yaml_bad_level.yaml");

    const auto cfg = load_config(file.path);
    REQUIRE_FALSE(cfg.microserve.error_log_level.empty());
    REQUIRE(cfg.microserve.error_log_level != "not-a-level");
}

TEST_CASE("load_config reads backends and list listen/protocol", "[config]")
{
    microserve::test::ensure_logger();

    TempFile file(
        "microserve:\n"
        "  worker_processes: auto\n"
        "backends:\n"
        "  - name: api\n"
        "    servers:\n"
        "      - 127.0.0.1:9934\n"
        "      - 127.0.0.1:9935\n"
        "servers:\n"
        "  - server_name: localhost\n"
        "    listen:\n"
        "      - 9090\n"
        "      - 9443\n"
        "    protocol:\n"
        "      - http11\n"
        "      - http2\n"
        "      - http3\n"
        "    locations:\n"
        "      - path: /api\n"
        "        proxy_pass: http://api\n",
        "microserve_yaml_lists.yaml");

    const auto cfg = load_config(file.path);

    REQUIRE(cfg.microserve.worker_processes == "auto");
    REQUIRE(cfg.backends.size() == 1);
    REQUIRE(cfg.backends[0].name == "api");
    REQUIRE(cfg.backends[0].servers.size() == 2);
    REQUIRE(cfg.backends[0].servers[0] == "127.0.0.1:9934");
    REQUIRE(cfg.backends[0].servers[1] == "127.0.0.1:9935");

    REQUIRE(cfg.servers.size() == 1);
    const auto& srv = cfg.servers[0];
    REQUIRE(srv.listen.size() == 2);
    REQUIRE(srv.listen[0].bind == "9090");
    REQUIRE(srv.listen[0].protocols.empty());
    REQUIRE(srv.listen[1].bind == "9443");
    REQUIRE(srv.protocol.size() == 3);
    REQUIRE(srv.protocol[0] == Protocol::Http11);
    REQUIRE(srv.protocol[1] == Protocol::Http2);
    REQUIRE(srv.protocol[2] == Protocol::Http3);
    REQUIRE(srv.locations.size() == 1);
    REQUIRE(srv.locations[0].proxy_pass == "http://api");
    REQUIRE(cfg.address == "127.0.0.1");
}

TEST_CASE("load_config reads per-listen bind and protocol objects", "[config]")
{
    microserve::test::ensure_logger();

    TempFile file(
        "servers:\n"
        "  - server_name: internal\n"
        "    listen:\n"
        "      - bind: 127.0.0.1:9191\n"
        "        protocol: http11\n"
        "      - bind: 127.0.0.1:9292\n"
        "        protocol: http2c\n"
        "    locations:\n"
        "      - path: /\n"
        "        root: ../private\n",
        "microserve_yaml_listen_objects.yaml");

    const auto cfg = load_config(file.path);
    REQUIRE(cfg.servers.size() == 1);
    const auto& srv = cfg.servers[0];
    REQUIRE(srv.server_name == "internal");
    REQUIRE(srv.listen.size() == 2);
    REQUIRE(srv.listen[0].bind == "127.0.0.1:9191");
    REQUIRE(srv.listen[0].protocols.size() == 1);
    REQUIRE(srv.listen[0].protocols[0] == Protocol::Http11);
    REQUIRE(srv.listen[1].bind == "127.0.0.1:9292");
    REQUIRE(srv.listen[1].protocols.size() == 1);
    REQUIRE(srv.listen[1].protocols[0] == Protocol::Http2c);
    REQUIRE(srv.protocol.empty());
    REQUIRE(cfg.address == "internal");
}

TEST_CASE("load_config rejects unknown protocol names", "[config][error]")
{
    microserve::test::ensure_logger();

    const TempFile file(
        "servers:\n"
        "  - listen: 80\n"
        "    protocol: ftp\n",
        "microserve_yaml_bad_proto.yaml");

    REQUIRE_THROWS_AS(load_config(file.path), std::runtime_error);
}

TEST_CASE("load_config rejects a backend without a name", "[config][error]")
{
    microserve::test::ensure_logger();

    const TempFile file(
        "backends:\n"
        "  - servers:\n"
        "      - 127.0.0.1:9000\n",
        "microserve_yaml_backend_no_name.yaml");

    REQUIRE_THROWS_AS(load_config(file.path), std::runtime_error);
}

TEST_CASE("load_federation overlays without replacing servers", "[config][federation]")
{
    microserve::test::ensure_logger();

    TempFile site(
        "servers:\n"
        "  - listen: 9090\n"
        "    server_name: localhost\n"
        "    protocol: http11\n",
        "microserve_yaml_fed_site.yaml");

    TempFile fed(
        "federation:\n"
        "  enabled: true\n"
        "  role: hub\n"
        "  membership: certified\n"
        "  node_id: hub-1\n"
        "  node_name: local-hub\n"
        "  urn_nid: microserve\n"
        "  cert: certs/federation.crt\n"
        "  key: certs/federation.key\n"
        "  parent: \"\"\n"
        "  allow_unverified: false\n"
        "  block_unverified: true\n"
        "  peers:\n"
        "    - name: sibling\n"
        "      url: https://sibling.example:9443\n"
        "  revoked:\n"
        "    - old-node\n",
        "microserve_yaml_federation.yaml");

    auto cfg = load_config(site.path);
    REQUIRE(cfg.servers.size() == 1);
    CHECK_FALSE(cfg.federation.enabled);

    load_federation(fed.path, cfg);

    REQUIRE(cfg.servers.size() == 1);
    CHECK(cfg.servers[0].server_name == "localhost");
    CHECK(cfg.federation.enabled);
    CHECK(cfg.federation.role == FederationRole::Hub);
    CHECK(cfg.federation.membership == FederationMembership::Certified);
    CHECK(cfg.federation.node_id == "hub-1");
    CHECK(cfg.federation.urn_nid == "microserve");
    CHECK(cfg.federation.block_unverified);
    REQUIRE(cfg.federation.peers.size() == 1);
    CHECK(cfg.federation.peers[0].url == "https://sibling.example:9443");
    REQUIRE(cfg.federation.revoked.size() == 1);
    CHECK(cfg.federation.revoked[0] == "old-node");
}

TEST_CASE("load_federation default overlay stays stand-alone", "[config][federation]")
{
    microserve::test::ensure_logger();

    const TempFile fed(
        "federation:\n"
        "  enabled: false\n"
        "  role: standalone\n"
        "  membership: none\n",
        "microserve_yaml_federation_off.yaml");

    Config cfg;
    load_federation(fed.path, cfg);
    CHECK_FALSE(cfg.federation.enabled);
    CHECK(cfg.federation.role == FederationRole::Standalone);
    CHECK(cfg.federation.membership == FederationMembership::None);
}

TEST_CASE("load_federation throws when the file or key is missing", "[config][federation][error]")
{
    Config missing;
    REQUIRE_THROWS_AS(load_federation("no-such-federation.yaml", missing),
                      std::runtime_error);

    microserve::test::ensure_logger();
    const TempFile fed("servers:\n  - listen: 80\n", "microserve_yaml_not_federation.yaml");
    Config cfg;
    REQUIRE_THROWS_AS(load_federation(fed.path, cfg), std::runtime_error);
}
