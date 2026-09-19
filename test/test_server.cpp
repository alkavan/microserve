// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <utility>

import microserve.core;
import microserve.server;

namespace {

using Protocol = microserve::Server::Protocol;

std::string read_until_close(microserve::tcp::socket& sock)
{
    std::string out;
    char buf[2048];
    microserve::error_code ec;
    for (;;) {
        const auto n = sock.read_some(microserve::net::buffer(buf), ec);
        if (n > 0) {
            out.append(buf, n);
        }
        if (ec || n == 0) {
            break;
        }
    }
    return out;
}

std::string http11_get(unsigned short port, std::string_view path = "/")
{
    microserve::net::io_context ioc;
    microserve::tcp::socket sock(ioc);
    sock.connect(microserve::tcp::endpoint(
        microserve::net::ip::make_address("127.0.0.1"), port));

    const auto req = "GET " + std::string(path) +
                     " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    sock.send(microserve::net::buffer(req));
    return read_until_close(sock);
}

bool tcp_port_in_use(unsigned short port)
{
    microserve::net::io_context ioc;
    microserve::tcp::acceptor probe(ioc);
    microserve::error_code ec;
    probe.open(microserve::tcp::v4(), ec);
    if (ec) {
        return false;
    }
    probe.bind(microserve::tcp::endpoint(microserve::net::ip::make_address("127.0.0.1"), port),
               ec);
    return static_cast<bool>(ec);
}

} // namespace

TEST_CASE("protocol_from_string maps aliases and unknown values", "[server][protocol]")
{
    REQUIRE(microserve::Server::protocol_from_string("http3") == Protocol::Http3);
    REQUIRE(microserve::Server::protocol_from_string("h3") == Protocol::Http3);
    REQUIRE(microserve::Server::protocol_from_string("quic") == Protocol::Http3);

    REQUIRE(microserve::Server::protocol_from_string("https") == Protocol::Http2);
    REQUIRE(microserve::Server::protocol_from_string("http2") == Protocol::Http2);
    REQUIRE(microserve::Server::protocol_from_string("h2") == Protocol::Http2);

    REQUIRE(microserve::Server::protocol_from_string("h2c") == Protocol::Http2ClearText);

    REQUIRE(microserve::Server::protocol_from_string("http") == Protocol::Http1);
    REQUIRE(microserve::Server::protocol_from_string("http1") == Protocol::Http1);
    REQUIRE(microserve::Server::protocol_from_string("http/1.1") == Protocol::Http1);
    REQUIRE(microserve::Server::protocol_from_string("") == Protocol::Http1);
    REQUIRE(microserve::Server::protocol_from_string("HTTP3") == Protocol::Http1);
    REQUIRE(microserve::Server::protocol_from_string("HTTP2") == Protocol::Http1);
    REQUIRE(microserve::Server::protocol_from_string("H2C") == Protocol::Http1);
}

TEST_CASE("Server defaults to HTTP/1.1 and does not require TLS files", "[server][http1]")
{
    microserve::test::ensure_logger();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Server server(ioc, "127.0.0.1", port);
    server.set_handler([](const auto&, auto& res) {
        res.body() = "default-h11";
        res.prepare_payload();
    });
    server.start();

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        response = http11_get(port, "/");
        server.stop();
    });

    REQUIRE(response.find("200") != std::string::npos);
    REQUIRE(response.find("default-h11") != std::string::npos);
}

TEST_CASE("Server HTTP/1.1 handler sees method, target, and host", "[server][http1][handler]")
{
    microserve::test::ensure_logger();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Server server(ioc, "127.0.0.1", port, Protocol::Http1);
    server.set_handler([](const auto& req, auto& res) {
        res.body() = std::string(req.method_string()) + " " + std::string(req.target()) +
                     " host=" + std::string(req[microserve::http::field::host]);
        res.prepare_payload();
    });
    server.start();

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        response = http11_get(port, "/items?x=1");
        server.stop();
    });

    REQUIRE(response.find("GET /items?x=1") != std::string::npos);
    REQUIRE(response.find("host=127.0.0.1") != std::string::npos);
}

TEST_CASE("Server Http1Tls currently serves cleartext HTTP/1.1", "[server][http1tls]")
{
    microserve::test::ensure_logger();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Server server(ioc, "127.0.0.1", port, Protocol::Http1Tls,
                              "unused.crt", "unused.key", 0);
    server.set_handler([](const auto&, auto& res) {
        res.body() = "http1tls-cleartext";
        res.prepare_payload();
    });
    server.start();

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        response = http11_get(port);
        server.stop();
    });

    REQUIRE(response.find("http1tls-cleartext") != std::string::npos);
}

TEST_CASE("Server h2c still accepts HTTP/1.1 requests", "[server][h2c]")
{
    microserve::test::ensure_logger();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Server server(ioc, "127.0.0.1", port, Protocol::Http2ClearText);
    server.set_handler([](const auto&, auto& res) {
        res.body() = "via-server-h2c";
        res.prepare_payload();
    });
    server.start();

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        response = http11_get(port, "/h2c");
        server.stop();
    });

    REQUIRE(response.find("200") != std::string::npos);
    REQUIRE(response.find("via-server-h2c") != std::string::npos);
}

TEST_CASE("Server TLS backends throw when certificate files are missing", "[server][tls]")
{
    microserve::test::ensure_logger();

    microserve::net::io_context ioc;
    REQUIRE_THROWS(microserve::Server(ioc, "127.0.0.1", 0, Protocol::Http2,
                                      "no-such-cert.pem", "no-such-key.pem", 0));
    REQUIRE_THROWS(microserve::Server(ioc, "127.0.0.1", 0, Protocol::Http3,
                                      "no-such-cert.pem", "no-such-key.pem", 0));
}

TEST_CASE("Server HTTP/2 and HTTP/3 construct with valid certificates", "[server][tls][lifecycle]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();

    microserve::net::io_context ioc;

    const auto h2_port = microserve::test::ephemeral_tcp_port();
    microserve::Server h2(ioc, "127.0.0.1", h2_port, Protocol::Http2, cert, key, 0);
    h2.set_handler([](const auto&, auto& res) { res.body() = "h2"; });
    h2.start();
    ioc.poll();
    h2.stop();
    h2.stop();

    const auto h3_port = microserve::test::ephemeral_udp_port();
    microserve::Server h3(ioc, "127.0.0.1", h3_port, Protocol::Http3, cert, key, 0);
    h3.set_handler([](const auto&, auto& res) { res.body() = "h3"; });
    h3.start();
    ioc.poll();
    h3.stop();
}

TEST_CASE("Server stop is idempotent and destructor releases the listen port",
          "[server][lifecycle]")
{
    microserve::test::ensure_logger();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    {
        microserve::Server server(ioc, "127.0.0.1", port, Protocol::Http1);
        server.set_handler([](const auto&, auto&) {});
        server.start();
        ioc.poll();
        REQUIRE(tcp_port_in_use(port));
        server.stop();
        server.stop();
    }

    REQUIRE_FALSE(tcp_port_in_use(port));

    microserve::Server again(ioc, "127.0.0.1", port, Protocol::Http1);
    again.set_handler([](const auto&, auto&) {});
    again.start();
    ioc.poll();
    again.stop();
}

TEST_CASE("Server can run HTTP/1.1 listeners on two ports at once", "[server][multi]")
{
    microserve::test::ensure_logger();

    const auto port_a = microserve::test::ephemeral_tcp_port();
    const auto port_b = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Server a(ioc, "127.0.0.1", port_a, Protocol::Http1);
    microserve::Server b(ioc, "127.0.0.1", port_b, Protocol::Http1);
    a.set_handler([](const auto&, auto& res) {
        res.body() = "A";
        res.prepare_payload();
    });
    b.set_handler([](const auto&, auto& res) {
        res.body() = "B";
        res.prepare_payload();
    });
    a.start();
    b.start();

    std::string ra;
    std::string rb;
    microserve::test::run_with_server_ioc(ioc, [&] {
        ra = http11_get(port_a);
        rb = http11_get(port_b);
        a.stop();
        b.stop();
    });

    REQUIRE(ra.find("A") != std::string::npos);
    REQUIRE(rb.find("B") != std::string::npos);
}
