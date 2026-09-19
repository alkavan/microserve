// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/ssl.h>

#include <string>
#include <string_view>
#include <utility>

import microserve.core;
import microserve.http2;
import microserve.server;

namespace {

constexpr std::string_view kH2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr unsigned char kH2EmptySettings[] = {
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00};

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

std::string http11_get(const unsigned short port, const std::string_view path = "/")
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

struct TlsClient {
    SSL_CTX* ctx{nullptr};
    SSL* ssl{nullptr};

    TlsClient()
    {
        ctx = SSL_CTX_new(TLS_client_method());
        REQUIRE(ctx != nullptr);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        ssl = SSL_new(ctx);
        REQUIRE(ssl != nullptr);
    }

    TlsClient(const TlsClient&) = delete;
    TlsClient& operator=(const TlsClient&) = delete;

    ~TlsClient()
    {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (ctx) {
            SSL_CTX_free(ctx);
        }
    }

    std::string get(microserve::tcp::socket& sock, std::string_view path = "/")
    {
        REQUIRE(SSL_set_fd(ssl, static_cast<int>(sock.native_handle())) == 1);
        SSL_set_tlsext_host_name(ssl, "localhost");
        REQUIRE(SSL_connect(ssl) == 1);

        const auto req = "GET " + std::string(path) +
                         " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        REQUIRE(SSL_write(ssl, req.data(), static_cast<int>(req.size())) > 0);

        std::string out;
        char buf[2048];
        for (;;) {
            if (const int n = SSL_read(ssl, buf, sizeof(buf)); n > 0) {
                out.append(buf, static_cast<std::size_t>(n));
                continue;
            }
            break;
        }
        return out;
    }
};

} // namespace

TEST_CASE("Http2Impl throws when TLS files are missing", "[http2][tls]")
{
    microserve::test::ensure_logger();

    microserve::net::io_context ioc;
    REQUIRE_THROWS(
        microserve::Http2Impl(ioc, "127.0.0.1", 0, "no-such-cert.pem", "no-such-key.pem", 0));
}

TEST_CASE("Http2Impl binds a TLS listener and stops cleanly", "[http2][lifecycle]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Http2Impl server(ioc, "127.0.0.1", port, cert, key, 0);
    server.set_handler([](const auto&, auto& res) {
        res.body() = "ok";
        res.prepare_payload();
    });
    server.start_server();
    ioc.poll();
    server.stop_server();
    server.stop_server();
}

TEST_CASE("Http2ClearTextImpl serves HTTP/1.1", "[http2][h11]")
{
    microserve::test::ensure_logger();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Http2ClearTextImpl server(ioc, "127.0.0.1", port, 0, /*allow_h2c=*/false);
    server.set_handler([](const auto& req, auto& res) {
        res.body() = "h11:" + std::string(req.target());
        res.prepare_payload();
    });
    server.start_server();

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        response = http11_get(port, "/ping");
        server.stop_server();
    });

    REQUIRE(response.find("200") != std::string::npos);
    REQUIRE(response.find("h11:/ping") != std::string::npos);
}

TEST_CASE("Http2ClearTextImpl HTTP/1.1 fallback still works when h2c is enabled",
          "[http2][h2c][h11]")
{
    microserve::test::ensure_logger();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Http2ClearTextImpl server(ioc, "127.0.0.1", port, 0, /*allow_h2c=*/true);
    server.set_handler([](const auto&, auto& res) {
        res.body() = "h2c-fallback";
        res.prepare_payload();
    });
    server.start_server();

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        response = http11_get(port, "/");
        server.stop_server();
    });

    REQUIRE(response.find("200") != std::string::npos);
    REQUIRE(response.find("h2c-fallback") != std::string::npos);
}

TEST_CASE("Http2ClearTextImpl accepts an HTTP/2 connection preface", "[http2][h2c]")
{
    microserve::test::ensure_logger();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Http2ClearTextImpl server(ioc, "127.0.0.1", port, 0, /*allow_h2c=*/true);
    server.set_handler([](const auto&, auto& res) {
        res.body() = "h2c";
        res.prepare_payload();
    });
    server.start_server();

    std::string preface_response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        microserve::net::io_context client_ioc;
        microserve::tcp::socket sock(client_ioc);
        sock.connect(microserve::tcp::endpoint(
            microserve::net::ip::make_address("127.0.0.1"), port));

        std::string wire;
        wire.append(kH2Preface);
        wire.append(reinterpret_cast<const char*>(kH2EmptySettings),
                    sizeof(kH2EmptySettings));
        sock.send(microserve::net::buffer(wire));

        microserve::error_code ec;
        sock.non_blocking(true, ec);
        for (int i = 0; i < 20 && preface_response.empty(); ++i) {
            microserve::test::sleep_ms(50);
            char buf[256]{};
            if (const auto n = sock.read_some(microserve::net::buffer(buf), ec); n > 0) {
                preface_response.assign(buf, n);
            }
        }

        server.stop_server();
    });

    REQUIRE_FALSE(preface_response.empty());
}

TEST_CASE("Http2Impl serves HTTP/1.1 over TLS when ALPN is not h2", "[http2][tls][h11]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_tcp_port();

    microserve::net::io_context ioc;
    microserve::Http2Impl server(ioc, "127.0.0.1", port, cert, key, 0);
    server.set_handler([](const auto& req, auto& res) {
        res.body() = "tls-h11:" + std::string(req.target());
        res.prepare_payload();
    });
    server.start_server();

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        microserve::net::io_context client_ioc;
        microserve::tcp::socket sock(client_ioc);
        sock.connect(microserve::tcp::endpoint(
            microserve::net::ip::make_address("127.0.0.1"), port));

        TlsClient tls;
        response = tls.get(sock, "/secure");
        server.stop_server();
    });

    REQUIRE(response.find("200") != std::string::npos);
    REQUIRE(response.find("tls-h11:/secure") != std::string::npos);
}

TEST_CASE("Server facade constructs HTTP/1.1, h2c, and HTTP/2 listeners", "[http2][server]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();

    microserve::net::io_context ioc;

    const auto h11_port = microserve::test::ephemeral_tcp_port();
    const microserve::Server h11(ioc, "127.0.0.1", h11_port,
                           microserve::Server::Protocol::Http1, cert, key, 0);
    h11.set_handler([](const auto&, auto& res) {
        res.body() = "via-h11";
        res.prepare_payload();
    });
    h11.start();

    const auto h2c_port = microserve::test::ephemeral_tcp_port();
    const microserve::Server h2c(ioc, "127.0.0.1", h2c_port,
                           microserve::Server::Protocol::Http2ClearText, cert, key, 0);
    h2c.set_handler([](const auto&, auto& res) {
        res.body() = "via-h2c";
        res.prepare_payload();
    });
    h2c.start();

    const auto h2_port = microserve::test::ephemeral_tcp_port();
    const microserve::Server h2(ioc, "127.0.0.1", h2_port,
                          microserve::Server::Protocol::Http2, cert, key, 0);
    h2.set_handler([](const auto&, auto& res) {
        res.body() = "via-h2";
        res.prepare_payload();
    });
    h2.start();

    std::string h11_response;
    std::string h2c_response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        h11_response = http11_get(h11_port);
        h2c_response = http11_get(h2c_port);
        h11.stop();
        h2c.stop();
        h2.stop();
    });

    REQUIRE(h11_response.find("via-h11") != std::string::npos);
    REQUIRE(h2c_response.find("via-h2c") != std::string::npos);
}
