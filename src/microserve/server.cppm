// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <memory>
#include <string>
#include <string_view>
#include <utility>

export module microserve.server;

import microserve.core;
import microserve.http2;
import microserve.http3;

/**
 * @brief Public HTTP server facade for the microserve stack.
 *
 * Selects an HTTP/1.1, HTTP/2, or HTTP/3 backend and exposes a single
 * handler / start / stop API. Backend implementations live in the
 * `http2` / `http3` modules as free `ServerImpl` subclasses (not nested
 * types), which avoids a circular module import.
 */
export namespace microserve {

    /**
     * @brief Public Server facade over protocol-specific backends.
     *
     * Owns a `ServerImpl` chosen from the requested @ref Protocol.
     * The destructor stops the backend if it is still running.
     */
    class Server {
    public:
        /**
         * @brief Transport and application protocol selected at construction.
         */
        enum class Protocol {
            Http1,           ///< Clear-text HTTP/1.1.
            Http2,           ///< HTTP/2 over TLS (ALPN `h2`).
            Http3,           ///< HTTP/3 over QUIC.
            Http2ClearText,  ///< Clear-text HTTP/2 (`h2c`), optionally with HTTP/1.1.
            Http1Tls         ///< HTTP/1.1 over TLS.
        };

        /**
         * @brief Map a protocol name to a @ref Protocol enumerator.
         *
         * Recognised values (case-sensitive):
         * - `"http3"`, `"h3"`, `"quic"` → @ref Protocol::Http3
         * - `"https"`, `"http2"`, `"h2"` → @ref Protocol::Http2
         * - `"h2c"` → @ref Protocol::Http2ClearText
         *
         * Any other string, including `"http"` / `"http1"`, maps to
         * @ref Protocol::Http1.
         *
         * @param s Protocol name, without a trailing port or scheme separator.
         * @return Matching enumerator, or @ref Protocol::Http1 when unknown.
         */
        static Protocol protocol_from_string(const std::string_view s) {
            if (s == "http3" || s == "h3" || s == "quic") return Protocol::Http3;
            if (s == "https" || s == "http2" || s == "h2") return Protocol::Http2;
            if (s == "h2c") return Protocol::Http2ClearText;
            return Protocol::Http1;
        }

        /**
         * @brief Construct a server bound to @p address and @p port.
         *
         * TLS certificate paths are used by the HTTP/2 and HTTP/3 backends.
         * @p allow_h11 applies when @p protocol is @ref Protocol::Http2ClearText.
         *
         * @param ioc        Asio I/O context that drives the acceptor and sessions.
         * @param address    Bind address (for example `"0.0.0.0"` or `"::"`).
         * @param port       TCP/UDP port to listen on.
         * @param protocol   Selected backend; defaults to clear-text HTTP/1.1.
         * @param tls_cert   Path to the PEM server certificate.
         * @param tls_key    Path to the PEM private key.
         * @param verbosity  Backend log verbosity (`0` is quiet).
         * @param allow_h11  When `true`, h2c also accepts HTTP/1.1 requests.
         */
        Server(net::io_context& ioc, const std::string& address, unsigned short port,
               Protocol protocol = Protocol::Http1,
               std::string tls_cert = "certs/server.crt",
               std::string tls_key = "certs/server.key",
               int verbosity = 0,
               bool allow_h11 = true);

        /**
         * @brief Stop the backend if it is still running and release it.
         */
        ~Server();

        /**
         * @brief Install the request handler used by all accepted sessions.
         *
         * Must be called before @ref start. Replacing the handler while the
         * server is running is backend-defined.
         *
         * @param handler Callback invoked for each incoming request.
         */
        void set_handler(Handler handler) const;

        /**
         * @brief Start accepting connections on the configured endpoint.
         */
        void start() const;

        /**
         * @brief Stop accepting connections and shut down active sessions.
         */
        void stop() const;

    private:
        std::unique_ptr<ServerImpl> impl_{};
    };

    inline Server::Server(net::io_context& ioc, const std::string& address,
                          unsigned short port, const Protocol protocol,
                          std::string tls_cert, std::string tls_key,
                          const int verbosity, const bool allow_h11)
        : impl_(protocol == Protocol::Http3
                    ? std::unique_ptr<ServerImpl>(std::make_unique<Http3Impl>(
                          ioc, address, port, std::move(tls_cert), std::move(tls_key),
                          verbosity))
                    : protocol == Protocol::Http2
                          ? std::unique_ptr<ServerImpl>(std::make_unique<Http2Impl>(
                                ioc, address, port, std::move(tls_cert),
                                std::move(tls_key), verbosity))
                          : protocol == Protocol::Http2ClearText
                                ? std::unique_ptr<ServerImpl>(
                                      std::make_unique<Http2ClearTextImpl>(
                                          ioc, address, port, verbosity,
                                          /*allow_h2c=*/true,
                                          /*allow_h11=*/allow_h11))
                                : std::unique_ptr<ServerImpl>(
                                      std::make_unique<Http2ClearTextImpl>(
                                          ioc, address, port, verbosity,
                                          /*allow_h2c=*/false,
                                          /*allow_h11=*/true))) {}

    inline Server::~Server() {
        if (impl_)
            impl_->stop_server();
    }

    inline void Server::set_handler(Handler handler) const {
        impl_->set_handler(std::move(handler));
    }

    inline void Server::start() const { impl_->start_server(); }

    inline void Server::stop() const { impl_->stop_server(); }

} // namespace microserve
