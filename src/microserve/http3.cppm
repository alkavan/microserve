// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <array>
#include <format>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "http3_interface.hpp"

export module microserve.http3;

import microserve.core;
import microserve.detail;
import :quic;
import :conn;

/**
 * @brief HTTP/3 server backend over QUIC/UDP.
 *
 * Provides @ref Http3Impl, a `ServerImpl` that binds one UDP socket and
 * multiplexes many QUIC connections. Packet I/O lives in
 * `microserve.http3:quic`; per-connection HTTP/3 state in
 * `microserve.http3:conn` (neither partition is exported).
 */

export namespace microserve {

    /**
     * @brief HTTP/3 listener: one UDP socket, many QUIC connections.
     *
     * Connections are keyed by every active SCID so path/CID migration
     * still resolves the same session.
     */
    class Http3Impl final : public ServerImpl {
        net::io_context& ioc_;
        udp::socket socket_;
        udp::endpoint local_ep_;
        udp::endpoint sender_ep_;
        std::array<uint8_t, http3_detail::kUdpBufSize> recv_buf_{};
        Handler handler_;
        int verbosity_{0};
        bool stopped_{false};

        std::unique_ptr<http3_detail::ServerTls> tls_;
        std::string cert_file_;
        std::string key_file_;

        std::map<std::string, std::shared_ptr<http3_detail::QuicConnection>> connections_;

        http3_detail::ConnOwner owner() {
            return http3_detail::ConnOwner{
                .socket = &socket_,
                .local_ep = &local_ep_,
                .ssl_ctx = tls_ ? tls_->ctx : nullptr,
                .verbosity = verbosity_,
                .stopped = &stopped_,
                .connections = &connections_,
                .make_app =
                    [h = &handler_](http3_detail::QuicConnection& qc)
                        -> std::unique_ptr<http3_detail::QuicApp> {
                        return http3_detail::make_h3_session(qc, h);
                },
            };
        }

        void do_read() {
            socket_.async_receive_from(
                net::buffer(recv_buf_), sender_ep_,
                [this](const error_code& ec, const std::size_t n) {
                    if (stopped_)
                        return;
                    if (!ec && n > 0)
                        http3_detail::handle_packet(owner(), recv_buf_.data(), n, sender_ep_);
                    if (!stopped_)
                        do_read();
                });
        }

    public:
        /**
         * @brief Construct an HTTP/3 listener on @p address and @p port.
         *
         * @param ioc        Asio I/O context that drives the UDP socket and sessions.
         * @param address    Bind address (for example `"0.0.0.0"` or `"::"`).
         * @param port       UDP port to listen on.
         * @param cert_file  Path to the PEM server certificate.
         * @param key_file   Path to the PEM private key.
         * @param verbosity  Log verbosity (`0` is quiet).
         *
         * @throws std::runtime_error if TLS initialization fails.
         */
        Http3Impl(net::io_context& ioc, const std::string& address, const unsigned short port,
                  std::string cert_file = "certs/server.crt",
                  std::string key_file = "certs/server.key",
                  const int verbosity = 0)
            : ioc_(ioc), socket_(ioc), local_ep_(net::ip::make_address(address), port),
              verbosity_(verbosity), cert_file_(std::move(cert_file)), key_file_(std::move(key_file)) {
            tls_ = http3_detail::make_server_tls(cert_file_, key_file_);
            if (!tls_)
                throw std::runtime_error("HTTP/3 TLS initialization failed");

            detail::open_and_bind(socket_, local_ep_);
            local_ep_ = socket_.local_endpoint();
        }

        /**
         * @brief Stop the listener and release QUIC connections and TLS state.
         */
        ~Http3Impl() override {
            stop_server();

            // Safe only once no completions will run (after ioc.run() returned in main,
            // or after main has stopped the io_context and drained handlers).
            connections_.clear();
            tls_.reset();
        }

        /**
         * @brief Install the request handler used by all accepted sessions.
         *
         * Must be called before @ref start_server.
         *
         * @param handler Callback invoked for each incoming request.
         */
        void set_handler(Handler handler) override { handler_ = std::move(handler); }

        /**
         * @brief Start receiving QUIC packets on the configured endpoint.
         */
        void start_server() override { do_read(); }

        /**
         * @brief Stop receiving packets, close the UDP socket, and drop connections.
         */
        void stop_server() override {
            if (stopped_)
                return;
            stopped_ = true;
            error_code ec;
            socket_.cancel(ec);
            socket_.close(ec);
            if (ec) {
                log_warn(std::format("[{:<11}] UDP socket close failed: {}",
                                     "http3", ec.message()));
            }
            connections_.clear();

            log_info(std::format("[{:<11}] listener stopped", "http3"));
        }
    };

} // namespace microserve
