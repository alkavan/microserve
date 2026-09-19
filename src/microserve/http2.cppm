// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

export module microserve.http2;

import microserve.core;
import microserve.config;
import microserve.logging;
import microserve.detail;
import microserve.http11;

/**
 * @brief HTTP/2 TLS and clear-text HTTP/2 / HTTP/1.1 server backends.
 *
 * Provides @ref Http2Impl (HTTPS with ALPN `h2` / `http/1.1`) and
 * @ref Http2ClearTextImpl (prior-knowledge h2c and/or HTTP/1.1).
 * Both are `ServerImpl` subclasses.
 */

/**
 * @brief OpenSSL ALPN result query, re-exported for other modules.
 */
export using ::SSL_get0_alpn_selected;

/**
 * @brief OpenSSL NPN/ALPN protocol selector,re-exported for other modules.
 */
export using ::SSL_select_next_proto;

export inline constexpr int OPENSSL_NPN_NEGOTIATED_U = OPENSSL_NPN_NEGOTIATED;
export inline constexpr int SSL_TLSEXT_ERR_OK_U      = SSL_TLSEXT_ERR_OK;
export inline constexpr int SSL_TLSEXT_ERR_NOACK_U   = SSL_TLSEXT_ERR_NOACK;

export namespace microserve {

    /**
     * @brief TLS HTTP/2 backend with HTTP/1.1 ALPN fallback.
     *
     * Binds a TCP acceptor, loads a PEM certificate and key, and starts
     * an HTTP/2 or HTTP/1.1 session according to the negotiated ALPN
     * protocol.
     */
    class Http2Impl final : public ServerImpl {
        net::io_context& ioc_;
        tcp::acceptor acceptor_;
        net::ssl::context ctx_;
        Handler handler_;
        Config::TimeoutConfig timeout_;
        int verbosity_{0};
        bool stopped_{false};
        unsigned short port_{0};
        unsigned short alt_svc_port_{0};

        /**
         * @brief HTTP/2 session over a TLS stream.
         */
        class H2Session final
            : public detail::H2SessionBase<H2Session, ssl_stream_tcp> {
        public:
            static constexpr std::string_view kTag = "h2";
            static constexpr bool kDiagnoseNonPreface = false;

            /**
             * @brief Take ownership of @p stream and bind the shared handler.
             *
             * @param stream        TLS stream after a successful handshake.
             * @param h             Request handler (non-owning reference).
             * @param t             Idle / header timeouts.
             * @param verbosity     Log verbosity (`0` is quiet).
             * @param alt_svc_port  Port advertised in `Alt-Svc` (`0` to omit).
             */
            H2Session(ssl_stream_tcp stream, Handler& h,
                      Config::TimeoutConfig& t, const int verbosity,
                      const unsigned short alt_svc_port)
                : H2SessionBase(std::move(stream), h, t, verbosity, alt_svc_port) {}
        };

        std::vector<std::weak_ptr<H2Session>> h2_sessions_;
        std::vector<std::weak_ptr<detail::H1SecureSession>> h1_sessions_;

        static int alpn_select(SSL*, const unsigned char** out, unsigned char* out_len,
                               const unsigned char* in, const unsigned int in_len, void*) {
            static constexpr unsigned char h2[] = {2, 'h', '2'};
            static constexpr unsigned char h1[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

            if (SSL_select_next_proto(const_cast<unsigned char**>(out), out_len,h2, sizeof(h2),
                in, in_len) == OPENSSL_NPN_NEGOTIATED_U) {
                return SSL_TLSEXT_ERR_OK_U;
            }

            if (SSL_select_next_proto(const_cast<unsigned char**>(out), out_len, h1, sizeof(h1),
                in, in_len) == OPENSSL_NPN_NEGOTIATED_U) {
                return SSL_TLSEXT_ERR_OK_U;
            }

            return SSL_TLSEXT_ERR_NOACK_U;
        }

        void start_h2(ssl_stream_tcp stream) {
            const auto sess = std::make_shared<H2Session>(
                std::move(stream), handler_, timeout_, verbosity_, alt_svc_port_);
            h2_sessions_.push_back(sess);
            sess->start();
        }

        void start_h1(ssl_stream_tcp stream) {
            const auto sess = std::make_shared<detail::H1SecureSession>(
                std::move(stream), handler_, timeout_, verbosity_, alt_svc_port_);
            h1_sessions_.push_back(sess);
            sess->start();
        }

        void on_handshake(const error_code& hs_ec,
                          const std::shared_ptr<ssl_stream_tcp>& stream) {
            if (hs_ec || stopped_) {
                if (hs_ec && verbosity_ >= 2) {
                    log_debug(std::format("[{:<11}] TLS handshake failed: {}",
                                          "https", hs_ec.message()));
                }
                return;
            }

            const unsigned char* alpn = nullptr;
            unsigned int alpn_len = 0;
            SSL_get0_alpn_selected(stream->native_handle(), &alpn, &alpn_len);
            const std::string_view proto(reinterpret_cast<const char*>(alpn), alpn_len);

            if (verbosity_ >= 2) {
                log_debug(std::format("[{:<11}] ALPN selected: {}",
                                          proto == "h2" ? "https/h2" : "https/h11",
                                          proto.empty() ? "(none)" : std::string(proto)));
            }

            if (proto == "h2")
                start_h2(std::move(*stream));
            else
                start_h1(std::move(*stream));
        }

        void on_accept(const error_code& ec, tcp::socket socket) {
            if (ec) {
                if (ec != net::error::operation_aborted && verbosity_ >= 2) {
                    log_debug(std::format("[{:<11}] accept error: {}",
                                          "https", ec.message()));
                }
            } else if (!stopped_) {
                auto stream = std::make_shared<ssl_stream_tcp>(std::move(socket), ctx_);
                stream->async_handshake(net::ssl::stream_base::server,
                    [this, stream](const error_code& hs_ec) {
                        on_handshake(hs_ec, stream);
                    });
            }
            if (!stopped_ && acceptor_.is_open())
                do_accept();
        }

        void do_accept() {
            acceptor_.async_accept(net::make_strand(ioc_),
                [this](const error_code& ec, tcp::socket socket) {
                    on_accept(ec, std::move(socket));
                });
        }

    public:
        /**
         * @brief Construct an HTTPS listener on @p address and @p port.
         *
         * @param ioc        Asio I/O context that drives the acceptor and sessions.
         * @param address    Bind address (for example `"0.0.0.0"` or `"::"`).
         * @param port       TCP port to listen on.
         * @param cert       Path to the PEM server certificate.
         * @param key        Path to the PEM private key.
         * @param verbosity  Log verbosity (`0` is quiet).
         */
        Http2Impl(net::io_context& ioc, const std::string& address, const unsigned short port,
                  const std::string& cert, const std::string& key, const int verbosity = 0)
            : ioc_(ioc)
              , acceptor_(ioc)
              , ctx_(net::ssl::context::tls_server)
              , verbosity_(verbosity)
              , port_(port)
              , alt_svc_port_(port) {
            ctx_.set_options(net::ssl::context::default_workarounds |
                net::ssl::context::no_sslv2 |
                net::ssl::context::single_dh_use);
            detail::load_tls_certificate(ctx_, cert, key, "https");
            SSL_CTX_set_alpn_select_cb(ctx_.native_handle(), alpn_select, nullptr);

            const tcp::endpoint ep(net::ip::make_address(address), port);
            detail::open_bind_listen(acceptor_, ep);
        }

        /**
         * @brief Install the request handler used by all accepted sessions.
         *
         * Must be called before @ref start_server.
         *
         * @param h Callback invoked for each incoming request.
         */
        void set_handler(Handler h) override { handler_ = std::move(h); }

        /**
         * @brief Start accepting TLS connections on the configured endpoint.
         */
        void start_server() override { do_accept(); }

        /**
         * @brief Stop accepting connections and shut down active sessions.
         */
        void stop_server() override {
            if (stopped_)
                return;
            stopped_ = true;
            error_code ec;
            acceptor_.cancel(ec);
            acceptor_.close(ec);
            for (auto& wp : h2_sessions_)
                if (const auto s = wp.lock()) s->stop();
            h2_sessions_.clear();
            for (auto& wp : h1_sessions_)
                if (const auto s = wp.lock()) s->stop();
            h1_sessions_.clear();
            log_info(std::format("[{:<11}] listener stopped", "https"));
        }
    };

    /**
     * @brief Clear-text HTTP/2 (h2c) and/or HTTP/1.1 backend.
     *
     * Optionally probes the first bytes of each connection for the HTTP/2
     * client preface and dispatches to h2c or HTTP/1.1. Either protocol
     * can be disabled via the constructor flags.
     */
    class Http2ClearTextImpl final : public ServerImpl {
        net::io_context& ioc_;
        tcp::acceptor acceptor_;
        Handler handler_;
        Config::TimeoutConfig timeout_;
        int verbosity_{0};
        bool stopped_{false};
        bool allow_h2c_{false};
        bool allow_h11_{true};

        /**
         * @brief HTTP/2 session over a plain TCP socket (h2c).
         */
        class Session final
            : public detail::H2SessionBase<Session, tcp::socket> {
        public:
            static constexpr std::string_view kTag = "h2c";
            static constexpr bool kDiagnoseNonPreface = false;

            /**
             * @brief Take ownership of @p socket and bind the shared handler.
             *
             * @param socket     Accepted TCP socket.
             * @param h          Request handler (non-owning reference).
             * @param t          Idle / header timeouts.
             * @param verbosity  Log verbosity (`0` is quiet).
             */
            Session(tcp::socket socket, Handler& h, Config::TimeoutConfig& t,
                    const int verbosity)
                : H2SessionBase(std::move(socket), h, t, verbosity) {
            }
        };

        std::vector<std::weak_ptr<Session>> h2_sessions_;
        std::vector<std::weak_ptr<detail::Http1Session>> h1_sessions_;

        static bool is_h2_preface(const uint8_t* data, const std::size_t n) {
            return n >= detail::kH2Preface.size() &&
                std::string_view(reinterpret_cast<const char*>(data),
                                 detail::kH2Preface.size()) == detail::kH2Preface;
        }

        [[nodiscard]] const char* cleartext_tag() const {
            if (allow_h2c_ && allow_h11_)
                return "h2c";
            if (allow_h2c_)
                return "h2c";
            return "http1";
        }

        void start_h1(tcp::socket socket, const uint8_t* prefix, const std::size_t n,
                      const std::string_view tag) {
            std::shared_ptr<detail::Http1Session> sess;
            if (prefix && n > 0) {
                sess = std::make_shared<detail::Http1Session>(
                    std::move(socket), prefix, n, handler_, timeout_, verbosity_, tag);
            } else {
                sess = std::make_shared<detail::Http1Session>(
                    std::move(socket), handler_, timeout_, verbosity_, tag);
            }
            h1_sessions_.push_back(sess);
            sess->start();
        }

        void start_h2(tcp::socket socket, const uint8_t* data, const std::size_t n) {
            const auto sess = std::make_shared<Session>(
                std::move(socket), handler_, timeout_, verbosity_);
            h2_sessions_.push_back(sess);
            sess->start_with_initial(data, n);
        }

        void reject_socket(tcp::socket socket, const std::string_view why) {
            if (verbosity_ >= 2) {
                log_debug(std::format("[{:<11}] {}", cleartext_tag(), why));
            }
            error_code ec;
            socket.shutdown(tcp::socket::shutdown_both, ec);
            socket.close(ec);
        }

        void on_probe_read(const error_code& ec, const std::size_t n,
                           const std::shared_ptr<tcp::socket>& sock,
                           const std::shared_ptr<std::array<uint8_t, 1024>>& buf) {
            if (ec || stopped_) {
                if (ec && ec != net::error::operation_aborted && verbosity_ >= 2) {
                    log_debug(std::format("[{:<11}] probe read error: {}",
                                          cleartext_tag(), ec.message()));
                }
                return;
            }

            if (is_h2_preface(buf->data(), n)) {
                if (allow_h2c_) {
                    start_h2(std::move(*sock), buf->data(), n);
                } else {
                    reject_socket(std::move(*sock),
                        "HTTP/2 preface rejected (http2c not enabled)");
                }
                return;
            }

            if (allow_h11_) {
                if (verbosity_ >= 2) {
                    const auto preview_len = std::min<std::size_t>(n, 32);
                    std::string preview(
                        reinterpret_cast<const char*>(buf->data()), preview_len);
                    for (char& c : preview) {
                        if (c == '\r' || c == '\n' || c < 32 || c > 126)
                            c = '.';
                    }
                    log_debug(std::format(
                        "[{:<11}] non-HTTP/2 start, h11 fallback ({} bytes): \"{}\"",
                        cleartext_tag(), n, preview));
                }
                start_h1(std::move(*sock), buf->data(), n, "h11");
                return;
            }

            reject_socket(std::move(*sock),
                "HTTP/1.1 rejected (http11 not enabled)");
        }

        void probe_and_start(tcp::socket socket) {
            auto sock = std::make_shared<tcp::socket>(std::move(socket));
            auto buf = std::make_shared<std::array<uint8_t, 1024>>();
            sock->async_read_some(net::buffer(*buf),
                [this, sock, buf](const error_code& ec, const std::size_t n) {
                    on_probe_read(ec, n, sock, buf);
                });
        }

        void on_accept(const error_code& ec, tcp::socket socket) {
            if (ec) {
                if (ec != net::error::operation_aborted && verbosity_ >= 2) {
                    log_debug(std::format("[{:<11}] accept error: {}",
                                          cleartext_tag(), ec.message()));
                }
            } else if (!stopped_) {
                if (allow_h2c_)
                    probe_and_start(std::move(socket));
                else if (allow_h11_)
                    start_h1(std::move(socket), nullptr, 0, "h11");
                else
                    reject_socket(std::move(socket), "no cleartext protocol enabled");
            }
            if (!stopped_ && acceptor_.is_open())
                do_accept();
        }

        void do_accept() {
            acceptor_.async_accept(net::make_strand(ioc_),
                [this](const error_code& ec, tcp::socket socket) {
                    on_accept(ec, std::move(socket));
                });
        }

    public:
        /**
         * @brief Construct a clear-text listener on @p address and @p port.
         *
         * @param ioc        Asio I/O context that drives the acceptor and sessions.
         * @param address    Bind address (for example `"0.0.0.0"` or `"::"`).
         * @param port       TCP port to listen on.
         * @param verbosity  Log verbosity (`0` is quiet).
         * @param allow_h2c  When `true`, accept prior-knowledge HTTP/2 (h2c).
         * @param allow_h11  When `true`, accept HTTP/1.1 requests.
         */
        Http2ClearTextImpl(net::io_context& ioc, const std::string& address,
                           const unsigned short port, const int verbosity = 0,
                           const bool allow_h2c = false,
                           const bool allow_h11 = true)
            : ioc_(ioc), acceptor_(ioc), verbosity_(verbosity),
              allow_h2c_(allow_h2c), allow_h11_(allow_h11) {
            const tcp::endpoint ep(net::ip::make_address(address), port);
            detail::open_bind_listen(acceptor_, ep);
        }

        /**
         * @brief Install the request handler used by all accepted sessions.
         *
         * Must be called before @ref start_server.
         *
         * @param h Callback invoked for each incoming request.
         */
        void set_handler(Handler h) override { handler_ = std::move(h); }

        /**
         * @brief Start accepting connections on the configured endpoint.
         */
        void start_server() override { do_accept(); }

        /**
         * @brief Stop accepting connections and shut down active sessions.
         */
        void stop_server() override {
            if (stopped_)
                return;
            stopped_ = true;
            error_code ec;
            acceptor_.cancel(ec);
            acceptor_.close(ec);
            for (auto& wp : h2_sessions_)
                if (const auto s = wp.lock()) s->stop();
            h2_sessions_.clear();
            for (auto& wp : h1_sessions_)
                if (const auto s = wp.lock()) s->stop();
            h1_sessions_.clear();
            log_info(std::format("[{:<11}] listener stopped", cleartext_tag()));
        }
    };

} // namespace microserve
