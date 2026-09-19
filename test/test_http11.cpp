// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/ssl.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

import microserve.core;
import microserve.config;
import microserve.detail;
import microserve.http11;

namespace {

microserve::Config::TimeoutConfig test_timeouts()
{
    microserve::Config::TimeoutConfig t{};
    t.read = std::chrono::seconds(5);
    t.write = std::chrono::seconds(5);
    return t;
}

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
            const int n = SSL_read(ssl, buf, sizeof(buf));
            if (n > 0) {
                out.append(buf, static_cast<std::size_t>(n));
                continue;
            }
            break;
        }
        return out;
    }
};

} // namespace

TEST_CASE("Http1Session serves a cleartext HTTP/1.1 request", "[http11][h11]")
{
    microserve::test::ensure_logger();

    microserve::net::io_context ioc;
    microserve::tcp::acceptor acc(ioc);
    const microserve::tcp::endpoint ep(microserve::net::ip::make_address("127.0.0.1"), 0);
    microserve::detail::open_bind_listen(acc, ep);
    const auto port = acc.local_endpoint().port();

    auto timeouts = test_timeouts();
    microserve::Handler handler = [](const auto& req, auto& res) {
        res.body() = "h11:" + std::string(req.target());
        res.prepare_payload();
    };

    acc.async_accept([&](const microserve::error_code& ec, microserve::tcp::socket sock) {
        if (ec) {
            return;
        }
        auto session = std::make_shared<microserve::detail::Http1Session>(
            std::move(sock), handler, timeouts, 0, "h11");
        session->start();
    });

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        microserve::net::io_context client_ioc;
        microserve::tcp::socket client(client_ioc);
        client.connect(microserve::tcp::endpoint(
            microserve::net::ip::make_address("127.0.0.1"), port));
        const std::string req =
            "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        client.send(microserve::net::buffer(req));
        response = read_until_close(client);
    });

    REQUIRE(response.find("200") != std::string::npos);
    REQUIRE(response.find("h11:/ping") != std::string::npos);
}

TEST_CASE("Http1Session consumes bytes already read by an h2c probe", "[http11][prefix]")
{
    microserve::test::ensure_logger();

    microserve::net::io_context ioc;
    microserve::tcp::acceptor acc(ioc);
    const microserve::tcp::endpoint ep(microserve::net::ip::make_address("127.0.0.1"), 0);
    microserve::detail::open_bind_listen(acc, ep);
    const auto port = acc.local_endpoint().port();

    auto timeouts = test_timeouts();
    microserve::Handler handler = [](const auto& req, auto& res) {
        res.body() = "prefix:" + std::string(req.target());
        res.prepare_payload();
    };

    acc.async_accept([&](const microserve::error_code& ec, microserve::tcp::socket sock) {
        if (ec) {
            return;
        }
        auto sock_ptr = std::make_shared<microserve::tcp::socket>(std::move(sock));
        auto buf = std::make_shared<std::array<std::uint8_t, 1024>>();
        sock_ptr->async_read_some(
            microserve::net::buffer(*buf),
            [sock_ptr, buf, &handler, &timeouts](const microserve::error_code& read_ec,
                                                 const std::size_t n) {
                if (read_ec || n == 0) {
                    return;
                }
                auto session = std::make_shared<microserve::detail::Http1Session>(
                    std::move(*sock_ptr), buf->data(), n, handler, timeouts, 0, "h11");
                session->start();
            });
    });

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        microserve::net::io_context client_ioc;
        microserve::tcp::socket client(client_ioc);
        client.connect(microserve::tcp::endpoint(
            microserve::net::ip::make_address("127.0.0.1"), port));
        const std::string req =
            "GET /from-probe HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        client.send(microserve::net::buffer(req));
        response = read_until_close(client);
    });

    REQUIRE(response.find("prefix:/from-probe") != std::string::npos);
}

TEST_CASE("H1SecureSession serves HTTP/1.1 over TLS and injects Alt-Svc", "[http11][tls]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();

    microserve::net::io_context ioc;
    microserve::net::ssl::context ctx(microserve::net::ssl::context::tls_server);
    ctx.set_options(microserve::net::ssl::context::default_workarounds |
                    microserve::net::ssl::context::no_sslv2 |
                    microserve::net::ssl::context::single_dh_use);
    microserve::detail::load_tls_certificate(ctx, cert, key, "https");

    microserve::tcp::acceptor acc(ioc);
    const microserve::tcp::endpoint ep(microserve::net::ip::make_address("127.0.0.1"), 0);
    microserve::detail::open_bind_listen(acc, ep);
    const auto port = acc.local_endpoint().port();

    auto timeouts = test_timeouts();
    microserve::Handler handler = [](const auto& req, auto& res) {
        res.body() = "tls-h11:" + std::string(req.target());
        res.prepare_payload();
    };

    acc.async_accept([&](const microserve::error_code& ec, microserve::tcp::socket sock) {
        if (ec) {
            return;
        }
        auto stream = std::make_shared<microserve::ssl_stream_tcp>(std::move(sock), ctx);
        stream->async_handshake(
            microserve::net::ssl::stream_base::server,
            [stream, &handler, &timeouts](const microserve::error_code& hs_ec) {
                if (hs_ec) {
                    return;
                }
                auto session = std::make_shared<microserve::detail::H1SecureSession>(
                    std::move(*stream), handler, timeouts, 0, 443);
                session->start();
            });
    });

    std::string response;
    microserve::test::run_with_server_ioc(ioc, [&] {
        microserve::net::io_context client_ioc;
        microserve::tcp::socket client(client_ioc);
        client.connect(microserve::tcp::endpoint(
            microserve::net::ip::make_address("127.0.0.1"), port));
        TlsClient tls;
        response = tls.get(client, "/secure");
    });

    REQUIRE(response.find("200") != std::string::npos);
    REQUIRE(response.find("tls-h11:/secure") != std::string::npos);
    REQUIRE(response.find("h3=\":443\"") != std::string::npos);
}

TEST_CASE("Http1Session stop closes the accepted socket", "[http11][lifecycle]")
{
    microserve::test::ensure_logger();

    microserve::net::io_context ioc;
    microserve::tcp::acceptor acc(ioc);
    const microserve::tcp::endpoint ep(microserve::net::ip::make_address("127.0.0.1"), 0);
    microserve::detail::open_bind_listen(acc, ep);
    const auto port = acc.local_endpoint().port();

    auto timeouts = test_timeouts();
    microserve::Handler handler = [](const auto&, auto&) {};
    std::shared_ptr<microserve::detail::Http1Session> session;

    acc.async_accept([&](const microserve::error_code& ec, microserve::tcp::socket sock) {
        if (ec) {
            return;
        }
        session = std::make_shared<microserve::detail::Http1Session>(
            std::move(sock), handler, timeouts, 0);
        session->start();
        session->stop();
        session->stop();
    });

    microserve::test::run_with_server_ioc(ioc, [&] {
        microserve::net::io_context client_ioc;
        microserve::tcp::socket client(client_ioc);
        client.connect(microserve::tcp::endpoint(
            microserve::net::ip::make_address("127.0.0.1"), port));
        microserve::test::sleep_ms(50);
    });

    REQUIRE(session);
}
