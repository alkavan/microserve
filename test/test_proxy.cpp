// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include <catch2/catch_test_macros.hpp>

import microserve.config;
import microserve.proxy;

TEST_CASE("parse_proxy_pass splits scheme host port and uri", "[proxy]") {
    {
        const auto t = microserve::parse_proxy_pass("http://127.0.0.1:9191");
        CHECK(t.scheme == "http");
        CHECK(t.host == "127.0.0.1");
        CHECK(t.port == 9191);
        CHECK_FALSE(t.has_uri);
        CHECK(t.backend_name.empty());
    }
    {
        const auto t = microserve::parse_proxy_pass("http://127.0.0.1:9191/");
        CHECK(t.host == "127.0.0.1");
        CHECK(t.port == 9191);
        CHECK(t.has_uri);
        CHECK(t.uri == "/");
    }
    {
        const auto t = microserve::parse_proxy_pass("http://api/");
        CHECK(t.host == "api");
        CHECK(t.has_uri);
        CHECK(t.uri == "/");
    }
    {
        const auto t = microserve::parse_proxy_pass("backend:api");
        CHECK(t.backend_name == "api");
        CHECK_FALSE(t.has_uri);
    }
    {
        const auto t = microserve::parse_proxy_pass("backend://api/v1");
        CHECK(t.backend_name == "api");
        CHECK(t.has_uri);
        CHECK(t.uri == "/v1");
    }
    {
        const auto t = microserve::parse_proxy_pass("h2c://127.0.0.1:9292/");
        CHECK(t.scheme == "h2c");
        CHECK(t.host == "127.0.0.1");
        CHECK(t.port == 9292);
        CHECK(t.has_uri);
        CHECK(t.uri == "/");
    }
}

TEST_CASE("rewrite_proxy_target follows nginx prefix replacement", "[proxy]") {
    microserve::ProxyTarget pass_through;
    CHECK(microserve::rewrite_proxy_target("/api", "/api/foo", pass_through) == "/api/foo");
    CHECK(microserve::rewrite_proxy_target("/api", "/api?x=1", pass_through) == "/api?x=1");

    microserve::ProxyTarget strip;
    strip.has_uri = true;
    strip.uri = "/";
    CHECK(microserve::rewrite_proxy_target("/api", "/api", strip) == "/");
    CHECK(microserve::rewrite_proxy_target("/api", "/api/", strip) == "/");
    CHECK(microserve::rewrite_proxy_target("/api", "/api/foo", strip) == "/foo");
    CHECK(microserve::rewrite_proxy_target("/api", "/api/foo?q=1", strip) == "/foo?q=1");
}

TEST_CASE("resolve_proxy_upstream uses the first backend server", "[proxy]") {
    const std::vector<microserve::BackendConfig> backends{
        {.name = "api", .servers = {"127.0.0.1:9191", "127.0.0.1:9292"}},
    };
    microserve::ProxyTarget t;
    t.backend_name = "api";
    std::string host;
    unsigned short port = 0;
    REQUIRE(microserve::resolve_proxy_upstream(t, backends, host, port));
    CHECK(host == "127.0.0.1");
    CHECK(port == 9191);

    t.backend_name = "missing";
    CHECK_FALSE(microserve::resolve_proxy_upstream(t, backends, host, port));
}