// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

import microserve.core;
import microserve.logging;
import microserve.server;

namespace microserve::test {

void ensure_logger()
{
    static const bool initialized = [] {
        setup_logger();
        set_logger_level("error");
        return true;
    }();
    (void)initialized;
}

unsigned short ephemeral_tcp_port()
{
    net::io_context ioc;
    tcp::acceptor probe(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto port = probe.local_endpoint().port();
    error_code ec;
    probe.close(ec);
    return port;
}

unsigned short ephemeral_udp_port()
{
    net::io_context ioc;
    udp::socket probe(ioc, udp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto port = probe.local_endpoint().port();
    error_code ec;
    probe.close(ec);
    return port;
}

} // namespace microserve::test

TEST_CASE("microserve test suite is wired correctly", "[smoke]")
{
    REQUIRE(true);
}

TEST_CASE("protocol_from_string recognizes protocol aliases", "[protocol]")
{
    using P = microserve::Server::Protocol;

    REQUIRE(microserve::Server::protocol_from_string("http3") == P::Http3);
    REQUIRE(microserve::Server::protocol_from_string("h3") == P::Http3);
    REQUIRE(microserve::Server::protocol_from_string("quic") == P::Http3);

    REQUIRE(microserve::Server::protocol_from_string("https") == P::Http2);
    REQUIRE(microserve::Server::protocol_from_string("http2") == P::Http2);
    REQUIRE(microserve::Server::protocol_from_string("h2") == P::Http2);
    REQUIRE(microserve::Server::protocol_from_string("h2c") == P::Http2ClearText);

    REQUIRE(microserve::Server::protocol_from_string("http") == P::Http1);
    REQUIRE(microserve::Server::protocol_from_string("HTTP2") == P::Http1);
    REQUIRE(microserve::Server::protocol_from_string("HTTP3") == P::Http1);
}
