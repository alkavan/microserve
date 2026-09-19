// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <cstdint>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

export module microserve.http11;

import microserve.core;
import microserve.config;
import microserve.logging;

/**
 * @brief Internal HTTP/1.1 session implementations.
 *
 * Cleartext (`Http1Session`) and TLS (`H1SecureSession`) request/response
 * loops used after protocol detection. Not part of the public API.
 */
export namespace microserve::detail
{
    /**
     * @brief HTTP/1.1 session over a plain TCP socket.
     *
     * Runs a keep-alive request/response loop with Beast `async_read` /
     * `async_write` and the configured read/write timeouts.
     */
    class Http1Session : public std::enable_shared_from_this<Http1Session>
    {
        tcp::socket socket_;
        flat_buffer buffer_;
        Request req_;
        Response res_;
        steady_timer timer_;
        Handler &handler_;
        Config::TimeoutConfig &timeout_;
        int verbosity_;
        std::string_view tag_;

        /**
         * @brief Completion handler for `http::async_read`.
         *
         * Ignores cancellation. Other errors are logged at verbosity >= 2.
         * On success, dispatches the parsed request.
         *
         * @param self Session kept alive until the read completes.
         * @param ec   Read result.
         * @param n    Bytes transferred (unused).
         */
        static void on_read(const std::shared_ptr<Http1Session> &self,
                                const error_code &ec, std::size_t n) {
            if (ec) {
                if (ec == net::error::operation_aborted)
                    return;
                if (self->verbosity_ >= 2) {
                    log_debug(std::format("[{:<11}] read error: {}",
                                          self->tag_, ec.message()));
                }
                return;
            }
            self->handle_request();
        }

        /**
         * @brief Arm the read timeout and start an async HTTP request read.
         */
        void do_read() {
            timer_.expires_after(timeout_.read);
            req_ = {};
            http::async_read(socket_, buffer_, req_,
            [self = shared_from_this()](const error_code &ec, const std::size_t n) {on_read(self, ec, n);});
        }

        /**
         * @brief Invoke the application handler and send the response.
         *
         * Copies HTTP version and keep-alive from the request, then logs
         * the exchange when verbosity >= 1.
         */
        void handle_request() {
            res_ = {};
            res_.version(req_.version());
            res_.keep_alive(req_.keep_alive());
            handler_(req_, res_);
            if (verbosity_ >= 1) {
                if (const auto bytes = res_.body().size(); bytes > 0) {
                    log_info(std::format("[request/{:<3}] {} {} size={} {}",
                                         tag_,
                                         std::string_view(req_.method_string()),
                                         std::string_view(req_.target()),
                                         bytes, res_.result_int()));
                } else {
                    log_info(std::format("[request/{:<3}] {} {} {}",
                                         tag_,
                                         std::string_view(req_.method_string()),
                                         std::string_view(req_.target()),
                                         res_.result_int()));
                }
            }
            do_write();
        }

        /**
         * @brief Completion handler for `http::async_write`.
         *
         * On success, starts another read if keep-alive is set; otherwise
         * closes the session. Write errors are logged at verbosity >= 2.
         *
         * @param self Session kept alive until the write completes.
         * @param ec   Write result.
         * @param n    Bytes transferred (unused).
         */
        static void on_write(const std::shared_ptr<Http1Session> &self,
                                 const error_code &ec, std::size_t n) {
            if (ec) {
                if (self->verbosity_ >= 2) {
                    log_debug(std::format("[{:<11}] write error: {}",
                                          self->tag_, ec.message()));
                }
                return;
            }

            if (self->res_.keep_alive()) {
                self->do_read();
            } else {
                self->stop();
            }
        }

        /**
         * @brief Arm the write timeout and start an async HTTP response write.
         */
        void do_write() {
            timer_.expires_after(timeout_.write);
            http::async_write(socket_, res_,
            [self = shared_from_this()](const error_code &ec, const std::size_t n) {on_write(self, ec, n);});
        }

        public:
        /**
         * @brief Construct a session that reads from a fresh socket.
         *
         * @param socket    Connected TCP socket, moved in.
         * @param handler   Application request handler.
         * @param timeout   Read/write timeout configuration.
         * @param verbosity Logging verbosity (1 = requests, 2 = I/O errors).
         * @param tag       Short protocol tag used in log lines.
         */
        Http1Session(tcp::socket socket, Handler &handler, Config::TimeoutConfig &timeout,
            const int verbosity, const std::string_view tag = "h11")
        : socket_(std::move(socket)), timer_(socket_.get_executor()), handler_(handler), timeout_(timeout),
        verbosity_(verbosity), tag_(tag) {}

        /**
         * @brief Construct a session that already has probe bytes buffered.
         *
         * Used when HTTP/2 cleartext detection consumed a prefix that must
         * be replayed as the start of the HTTP/1.1 request.
         *
         * @param socket    Connected TCP socket, moved in.
         * @param prefix    Bytes already read from the socket, or `nullptr`.
         * @param n         Number of bytes in @p prefix.
         * @param handler   Application request handler.
         * @param timeout   Read/write timeout configuration.
         * @param verbosity Logging verbosity (1 = requests, 2 = I/O errors).
         * @param tag       Short protocol tag used in log lines.
         */
        Http1Session(tcp::socket socket, const uint8_t *prefix, const std::size_t n,
            Handler &handler, Config::TimeoutConfig &timeout,
            const int verbosity, const std::string_view tag = "h11")
        : socket_(std::move(socket)), timer_(socket_.get_executor()), handler_(handler), timeout_(timeout),
        verbosity_(verbosity), tag_(tag) {
            if (prefix && n > 0) {
                const auto copied = net::buffer_copy(buffer_.prepare(n), net::buffer(prefix, n));
                buffer_.commit(copied);
            }
        }

        /**
         * @brief Start the request/response loop.
         */
        void start() { do_read(); }

        /**
         * @brief Cancel outstanding operations and close the socket.
         */
        void stop() {
            error_code ec;
            timer_.cancel();
            socket_.cancel(ec);
            socket_.close(ec);
        }
    };

    /**
     * @brief HTTP/1.1 session over TLS.
     *
     * Same keep-alive loop as @ref Http1Session, with optional `Alt-Svc`
     * advertisement so clients can discover HTTP/3.
     */
    class H1SecureSession : public std::enable_shared_from_this<H1SecureSession>
    {
        ssl_stream_tcp stream_;
        flat_buffer buffer_;
        Request req_;
        Response res_;
        steady_timer timer_;
        Handler &handler_;
        Config::TimeoutConfig &timeout_;
        int verbosity_;
        unsigned short alt_svc_port_{0};

        /**
         * @brief Completion handler for `http::async_read`.
         *
         * Ignores cancellation. Other errors are logged at verbosity >= 2.
         * On success, dispatches the parsed request.
         *
         * @param self Session kept alive until the read completes.
         * @param ec   Read result.
         * @param n    Bytes transferred (unused).
         */
        static void on_read(const std::shared_ptr<H1SecureSession> &self,
                                const error_code &ec, std::size_t n) {
            if (ec) {
                if (ec == net::error::operation_aborted)
                    return;
                if (self->verbosity_ >= 2) {
                    log_debug(std::format("[{:<11}] read error: {}",
                                          "https/h11", ec.message()));
                }
                return;
            }
            self->handle();
        }

        /**
         * @brief Arm the read timeout and start an async HTTP request read.
         */
        void do_read() {
            timer_.expires_after(timeout_.read);
            req_ = {};
            http::async_read(stream_, buffer_, req_,
            [self = shared_from_this()](const error_code &ec, const std::size_t n) {on_read(self, ec, n);});
        }

        /**
         * @brief Invoke the application handler and send the response.
         *
         * Defaults a missing status to 200 and injects `Alt-Svc` when an
         * HTTP/3 port was configured and the handler did not set one.
         */
        void handle() {
            res_ = {};
            res_.version(req_.version());
            res_.keep_alive(req_.keep_alive());
            handler_(req_, res_);
            if (res_.result_int() == 0)
                res_.result(http::status::ok);

            // Ensure Chrome can discover HTTP/3 even on h1 over TLS.
            if (!res_.count(http::field::alt_svc) && alt_svc_port_ != 0) {
                res_.set(http::field::alt_svc,
                         "h3=\":" + std::to_string(alt_svc_port_) + "\"; ma=86400");
            }
            if (verbosity_ >= 1) {
                if (const auto bytes = res_.body().size(); bytes > 0) {
                    log_info(std::format("[request/{:<3}] {} {} size={} {}",
                                         "h11",
                                         std::string_view(req_.method_string()),
                                         std::string_view(req_.target()),
                                         bytes, res_.result_int()));
                } else {
                    log_info(std::format("[request/{:<3}] {} {} {}",
                                         "h11",
                                         std::string_view(req_.method_string()),
                                         std::string_view(req_.target()),
                                         res_.result_int()));
                }
            }
            do_write();
        }

        /**
         * @brief Completion handler for `http::async_write`.
         *
         * On success, starts another read if keep-alive is set; otherwise
         * closes the session. Write errors are logged at verbosity >= 2.
         *
         * @param self Session kept alive until the write completes.
         * @param ec   Write result.
         * @param n    Bytes transferred (unused).
         */
        static void on_write(const std::shared_ptr<H1SecureSession> &self,
                                 const error_code &ec, std::size_t n) {
            if (ec) {
                if (self->verbosity_ >= 2) {
                    log_debug(std::format("[{:<11}] write error: {}",
                                          "https/h11", ec.message()));
                }
                return;
            }
            if (self->res_.keep_alive())
                self->do_read();
            else
                self->stop();
        }

        /**
         * @brief Arm the write timeout and start an async HTTP response write.
         */
        void do_write() {
            timer_.expires_after(timeout_.write);
            http::async_write(stream_, res_,
            [self = shared_from_this()](const error_code &ec, const std::size_t n) {on_write(self, ec, n);});
        }

        public:
        /**
         * @brief Construct a TLS HTTP/1.1 session.
         *
         * @param stream       Connected SSL stream, moved in.
         * @param h            Application request handler.
         * @param t            Read/write timeout configuration.
         * @param verbosity    Logging verbosity (1 = requests, 2 = I/O errors).
         * @param alt_svc_port HTTP/3 port advertised via `Alt-Svc`, or 0 to skip.
         */
        H1SecureSession(ssl_stream_tcp stream, Handler &h, Config::TimeoutConfig &t,
            const int verbosity, const unsigned short alt_svc_port = 0)
        : stream_(std::move(stream)), timer_(stream_.get_executor()), handler_(h), timeout_(t),
        verbosity_(verbosity), alt_svc_port_(alt_svc_port) {}

        /**
         * @brief Start the request/response loop.
         */
        void start() { do_read(); }

        /**
         * @brief Cancel outstanding operations and close the TLS socket.
         */
        void stop() {
            error_code ec;
            timer_.cancel();
            stream_.lowest_layer().cancel(ec);
            stream_.lowest_layer().close(ec);
        }
    };
} // namespace microserve::detail
