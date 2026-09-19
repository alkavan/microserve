// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

import microserve.core;
import microserve.detail;

TEST_CASE("is_hop_by_hop_header matches RFC 9113 names", "[detail][headers]")
{
    REQUIRE(microserve::detail::is_hop_by_hop_header("connection"));
    REQUIRE(microserve::detail::is_hop_by_hop_header("keep-alive"));
    REQUIRE(microserve::detail::is_hop_by_hop_header("proxy-connection"));
    REQUIRE(microserve::detail::is_hop_by_hop_header("transfer-encoding"));
    REQUIRE(microserve::detail::is_hop_by_hop_header("upgrade"));
    REQUIRE(microserve::detail::is_hop_by_hop_header("http2-settings"));

    REQUIRE_FALSE(microserve::detail::is_hop_by_hop_header("content-type"));
    REQUIRE_FALSE(microserve::detail::is_hop_by_hop_header("content-length"));
    REQUIRE_FALSE(microserve::detail::is_hop_by_hop_header("host"));
    REQUIRE_FALSE(microserve::detail::is_hop_by_hop_header("alt-svc"));
    REQUIRE_FALSE(microserve::detail::is_hop_by_hop_header("Connection"));
    REQUIRE_FALSE(microserve::detail::is_hop_by_hop_header(""));
}

TEST_CASE("append_response_headers lowercases names and drops hop-by-hop fields",
          "[detail][headers]")
{
    microserve::Response res;
    res.set("Content-Type", "text/plain");
    res.set("X-Request-Id", "abc");
    res.set("Connection", "close");
    res.set("Keep-Alive", "timeout=5");
    res.set("Transfer-Encoding", "chunked");
    res.set("Upgrade", "h2c");
    res.set("Proxy-Connection", "keep-alive");
    res.set("HTTP2-Settings", "dummy");
    res.set("Alt-Svc", "h3=\":443\"; ma=86400");

    std::vector<std::string> storage;
    microserve::detail::append_response_headers(res, storage);

    REQUIRE(storage.size() % 2 == 0);

    bool saw_content_type = false;
    bool saw_request_id = false;
    bool saw_alt_svc = false;
    for (std::size_t i = 0; i + 1 < storage.size(); i += 2) {
        const auto& name = storage[i];
        const auto& value = storage[i + 1];
        REQUIRE_FALSE(name.empty());
        REQUIRE(name[0] != ':');
        REQUIRE_FALSE(microserve::detail::is_hop_by_hop_header(name));
        for (char c : name) {
            REQUIRE(c == static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }

        if (name == "content-type") {
            saw_content_type = true;
            REQUIRE(value == "text/plain");
        } else if (name == "x-request-id") {
            saw_request_id = true;
            REQUIRE(value == "abc");
        } else if (name == "alt-svc") {
            saw_alt_svc = true;
            REQUIRE(value.find("h3=") != std::string::npos);
        }
    }

    REQUIRE(saw_content_type);
    REQUIRE(saw_request_id);
    REQUIRE(saw_alt_svc);
}

TEST_CASE("kH2Preface is the RFC 9113 connection preface", "[detail][h2]")
{
    REQUIRE(microserve::detail::kH2Preface == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    REQUIRE(microserve::detail::kH2Preface.size() == 24);
}

TEST_CASE("open_and_bind sets reuse_address on a UDP socket", "[detail][bind]")
{
    microserve::net::io_context ioc;
    microserve::udp::socket sock(ioc);
    const microserve::udp::endpoint ep(microserve::net::ip::make_address("127.0.0.1"), 0);

    microserve::detail::open_and_bind(sock, ep);
    REQUIRE(sock.is_open());

    microserve::net::socket_base::reuse_address reuse;
    sock.get_option(reuse);
    REQUIRE(reuse.value());

    const auto bound = sock.local_endpoint();
    REQUIRE(bound.address().to_string() == "127.0.0.1");
    REQUIRE(bound.port() != 0);
}

TEST_CASE("open_bind_listen accepts a TCP connection", "[detail][bind]")
{
    microserve::net::io_context ioc;
    microserve::tcp::acceptor acc(ioc);
    const microserve::tcp::endpoint ep(microserve::net::ip::make_address("127.0.0.1"), 0);
    microserve::detail::open_bind_listen(acc, ep);
    REQUIRE(acc.is_open());

    const auto port = acc.local_endpoint().port();
    REQUIRE(port != 0);

    microserve::tcp::socket client(ioc);
    client.connect(microserve::tcp::endpoint(
        microserve::net::ip::make_address("127.0.0.1"), port));

    microserve::error_code ec;
    auto peer = acc.accept(ec);
    REQUIRE_FALSE(ec);
    REQUIRE(peer.is_open());
}

TEST_CASE("load_tls_certificate throws when the certificate is missing", "[detail][tls]")
{
    microserve::test::ensure_logger();

    microserve::net::ssl::context ctx(microserve::net::ssl::context::tls_server);
    REQUIRE_THROWS_AS(
        microserve::detail::load_tls_certificate(ctx, "no-such-cert.pem", "no-such-key.pem",
                                                 "https"),
        std::runtime_error);
}

TEST_CASE("load_tls_certificate throws when the private key is missing", "[detail][tls]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    (void)key;

    microserve::net::ssl::context ctx(microserve::net::ssl::context::tls_server);
    REQUIRE_THROWS_AS(
        microserve::detail::load_tls_certificate(ctx, cert, "no-such-key.pem", "https"),
        std::runtime_error);
}

TEST_CASE("load_tls_certificate accepts matching PEM files", "[detail][tls]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();

    microserve::net::ssl::context ctx(microserve::net::ssl::context::tls_server);
    REQUIRE_NOTHROW(microserve::detail::load_tls_certificate(ctx, cert, key, "https"));
    REQUIRE(ctx.native_handle() != nullptr);
}
