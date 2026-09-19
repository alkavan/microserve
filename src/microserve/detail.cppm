// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

// No Boost / nghttp2 / spdlog here — those live only in microserve.core's GMF.
// Re-including them causes GCC "conflicting language linkage" on std entities.

#include <algorithm>
#include <cstdint>
#include <array>
#include <cctype>
#include <cstring>
#include <format>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <openssl/ssl.h>
#include <nghttp2/nghttp2.h>

export module microserve.detail;

import microserve.core;
import microserve.config;
import microserve.logging;

// --- nghttp2 (C API): global names ---
export using ::nghttp2_session;
export using ::nghttp2_session_callbacks;
export using ::nghttp2_frame;
export using ::nghttp2_nv;
export using ::nghttp2_data_provider;
export using ::nghttp2_data_source;
export using ::nghttp2_settings_entry;
export using ::nghttp2_session_callbacks_new;
export using ::nghttp2_session_callbacks_del;
export using ::nghttp2_session_callbacks_set_on_begin_headers_callback;
export using ::nghttp2_session_callbacks_set_on_header_callback;
export using ::nghttp2_session_callbacks_set_on_frame_recv_callback;
export using ::nghttp2_session_callbacks_set_on_data_chunk_recv_callback;
export using ::nghttp2_session_callbacks_set_on_stream_close_callback;
export using ::nghttp2_session_server_new;
export using ::nghttp2_session_del;
export using ::nghttp2_session_mem_recv;
export using ::nghttp2_session_mem_send;
export using ::nghttp2_session_want_read;
export using ::nghttp2_session_want_write;
export using ::nghttp2_submit_response;
export using ::nghttp2_submit_settings;

// nghttp2 macros → module constexpr (macros never cross import boundaries)
export inline constexpr auto NGHTTP2_DATA_U              = static_cast<uint8_t>(NGHTTP2_DATA);
export inline constexpr auto NGHTTP2_HEADERS_U           = static_cast<uint8_t>(NGHTTP2_HEADERS);
export inline constexpr auto NGHTTP2_FLAG_NONE_U         = static_cast<uint8_t>(NGHTTP2_FLAG_NONE);
export inline constexpr auto NGHTTP2_FLAG_END_STREAM_U   = static_cast<uint8_t>(NGHTTP2_FLAG_END_STREAM);
export inline constexpr auto NGHTTP2_FLAG_END_HEADERS_U  = static_cast<uint8_t>(NGHTTP2_FLAG_END_HEADERS);
export inline constexpr auto NGHTTP2_HCAT_REQUEST_U      = static_cast<int>(NGHTTP2_HCAT_REQUEST);
export inline constexpr auto NGHTTP2_DATA_FLAG_EOF_U     = static_cast<uint32_t>(NGHTTP2_DATA_FLAG_EOF);
export inline constexpr auto NGHTTP2_NV_FLAG_NONE_U      = static_cast<uint8_t>(NGHTTP2_NV_FLAG_NONE);
export inline constexpr auto NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS_U =
    static_cast<int>(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);

export namespace microserve::detail {
    // ---------------------------------------------------------------------------
    // Hop-by-hop header filtering (RFC 9113 §8.2.2)
    // ---------------------------------------------------------------------------

    inline bool is_hop_by_hop_header(std::string_view name) {
        // compare lowercase names only (you already tolower before calling)
        return name == "connection"
            || name == "keep-alive"
            || name == "proxy-connection"
            || name == "transfer-encoding"
            || name == "upgrade"
            || name == "http2-settings";
    }

    inline void append_response_headers(const Response& res,
                                        std::vector<std::string>& storage) {
        for (const auto& f : res) {
            std::string name(f.name_string());
            std::ranges::transform(name, name.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            if (name.empty() || name[0] == ':' || is_hop_by_hop_header(name))
                continue;
            storage.emplace_back(std::move(name));
            storage.emplace_back(f.value());
        }
    }

    /**
     * Open @p sock, set SO_REUSEADDR, and IPV6_V6ONLY when @p ep is IPv6.
     *
     * Linux defaults to dual-stack IPv6 (`net.ipv6.bindv6only=0`). Binding
     * `[::]` then also occupies `0.0.0.0` for that protocol, so a later
     * IPv4+IPv6 pair (or the reverse) fails with EADDRINUSE. Windows is
     * already v6-only by default; setting the option there is a no-op.
     */
    template<typename Socket>
    void open_and_bind(Socket &sock, const typename Socket::endpoint_type &ep) {
        sock.open(ep.protocol());
        sock.set_option(net::socket_base::reuse_address(true));
        if (ep.address().is_v6())
            sock.set_option(net::ip::v6_only(true));
        sock.bind(ep);
    }

    template<typename Acceptor>
    void open_bind_listen(Acceptor &acc, const typename Acceptor::endpoint_type &ep) {
        open_and_bind(acc, ep);
        acc.listen(net::socket_base::max_listen_connections);
    }

    /**
     * Load a PEM certificate chain + private key into an Asio TLS context.
     * Logs the same way HTTP/3 does, then throws std::runtime_error.
     */
    inline void load_tls_certificate(net::ssl::context& ctx,
                                     const std::string& cert_file,
                                     const std::string& key_file,
                                     const std::string_view tag = "https") {
        error_code ec;
        ctx.use_certificate_chain_file(cert_file, ec);
        if (ec) {
            log_error(std::format("[{:<11}] failed to load certificate: {}",
                                  tag, cert_file));
            throw std::runtime_error(std::format("{} TLS initialization failed", tag));
        }

        ctx.use_private_key_file(key_file, net::ssl::context::pem, ec);
        if (ec) {
            log_error(std::format("[{:<11}] failed to load private key: {}",
                                  tag, key_file));
            throw std::runtime_error(std::format("{} TLS initialization failed", tag));
        }

        if (SSL_CTX_check_private_key(ctx.native_handle()) != 1) {
            log_error(std::format("[{:<11}] certificate/private key mismatch", tag));
            throw std::runtime_error(std::format("{} TLS initialization failed", tag));
        }
    }

    struct H2StreamState {
        std::string method;
        std::string path;
        std::string authority;
        std::map<std::string, std::string> headers;
        std::string body;
        bool headers_done = false;
    };

    struct H2BodyHolder {
        std::string data;
        size_t offset = 0;
        std::vector<std::string> header_storage;
        std::vector<nghttp2_nv> nva;
    };

    constexpr std::string_view kH2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    template<typename Derived, typename Stream>
    class H2SessionBase : public std::enable_shared_from_this<Derived> {
    protected:
        Stream stream_;
        nghttp2_session *session_{nullptr};
        Handler &handler_;
        Config::TimeoutConfig &timeout_;
        steady_timer timer_{};
        std::array<uint8_t, 64 * 1024> read_buf_{};
        std::map<int32_t, H2StreamState> streams_;
        std::map<int32_t, std::unique_ptr<H2BodyHolder> > bodies_;
        bool preface_logged_{false};
        int verbosity_{0};
        unsigned short alt_svc_port_{0};

        bool writing_{false};
        std::vector<uint8_t> write_buf_;
        std::vector<uint8_t> writing_buf_;

        static int on_begin_headers(nghttp2_session *, const nghttp2_frame *frame, void *user) {
            auto *self = static_cast<Derived *>(user);
            if (frame->hd.type == NGHTTP2_HEADERS_U &&
                frame->headers.cat == NGHTTP2_HCAT_REQUEST_U)
                self->streams_[frame->hd.stream_id] = H2StreamState{};
            return 0;
        }

        static int on_header(nghttp2_session *, const nghttp2_frame *frame,
                             const uint8_t *name, const size_t name_len,
                             const uint8_t *value, const size_t value_len,
                             uint8_t, void *user) {
            auto *self = static_cast<Derived *>(user);
            auto &st = self->streams_[frame->hd.stream_id];
            const std::string_view n(reinterpret_cast<const char *>(name), name_len);
            const std::string_view v(reinterpret_cast<const char *>(value), value_len);
            if (n == ":method") st.method.assign(v);
            else if (n == ":path") st.path.assign(v);
            else if (n == ":authority") st.authority.assign(v);
            else st.headers.emplace(std::string(n), std::string(v));
            return 0;
        }

        static int on_frame_recv(nghttp2_session *, const nghttp2_frame *frame, void *user) {
            auto *self = static_cast<Derived *>(user);
            if (frame->hd.type == NGHTTP2_HEADERS_U &&
                (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS_U)) {
                self->streams_[frame->hd.stream_id].headers_done = true;
                if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM_U) {
                    self->on_request(frame->hd.stream_id);
                }
            }
            if (frame->hd.type == NGHTTP2_DATA_U
                && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM_U)) {
                self->on_request(frame->hd.stream_id);
            }
            return 0;
        }

        static int on_data_chunk(nghttp2_session *, uint8_t, const int32_t stream_id,
                                 const uint8_t *data, const size_t len, void *user) {
            static_cast<Derived *>(user)->streams_[stream_id].body.append(reinterpret_cast<const char *>(data), len);
            return 0;
        }

        static int on_stream_close(nghttp2_session *, const int32_t stream_id, uint32_t, void *user) {
            auto *self = static_cast<Derived *>(user);
            self->streams_.erase(stream_id);
            self->bodies_.erase(stream_id);
            return 0;
        }

        static ssize_t data_source_read(nghttp2_session *, int32_t, uint8_t *buf,
                                        const size_t length, uint32_t *data_flags,
                                        nghttp2_data_source *source, void *) {
            auto *bh = static_cast<H2BodyHolder *>(source->ptr);
            if (bh->offset >= bh->data.size()) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF_U;
                return 0;
            }
            const size_t n = std::min(length, bh->data.size() - bh->offset);
            std::memcpy(buf, bh->data.data() + bh->offset, n);
            bh->offset += n;
            if (bh->offset >= bh->data.size())
                *data_flags |= NGHTTP2_DATA_FLAG_EOF_U;
            return static_cast<ssize_t>(n);
        }

        void on_request(const int32_t stream_id) {
            const auto it = streams_.find(stream_id);
            if (it == streams_.end() || !it->second.headers_done)
                return;
            auto &st = it->second;

            Request req;
            req.method(http::string_to_verb(st.method));
            req.target(st.path.empty() ? "/" : st.path);
            req.version(20);
            for (const auto &[k, v]: st.headers)
                req.set(k, v);
            if (!st.authority.empty())
                req.set(http::field::host, st.authority);
            req.body() = std::move(st.body);
            req.prepare_payload();

            Response res;
            res.version(20);
            handler_(req, res);
            if (res.result_int() == 0)
                res.result(http::status::ok);

            {
                const auto bytes = res.body().size();
                log_access(std::format("[request/{:<3}] {} {}{} {}",
                                         Derived::kTag,
                                         st.method,
                                         std::string(req.target()),
                                         bytes > 0 ? " size=" + std::to_string(bytes) : "",
                                         res.result_int()));
            }

            auto holder = std::make_unique<H2BodyHolder>();
            if (st.method != "HEAD")
                holder->data = res.body();

            holder->header_storage.emplace_back(
                std::to_string(static_cast<unsigned>(res.result_int())));
            append_response_headers(res, holder->header_storage);

            // Optional Alt-Svc (TLS path only; alt_svc_port_ == 0 disables).
            if (alt_svc_port_ != 0) {
                bool has_alt_svc = false;
                for (size_t i = 1; i + 1 < holder->header_storage.size(); i += 2) {
                    if (holder->header_storage[i] == "alt-svc") {
                        has_alt_svc = true;
                        break;
                    }
                }
                if (!has_alt_svc) {
                    holder->header_storage.emplace_back("alt-svc");
                    holder->header_storage.emplace_back(
                        "h3=\":" + std::to_string(alt_svc_port_) + "\"; ma=86400");
                }
            }

            holder->nva.reserve(1 + (holder->header_storage.size() - 1) / 2);
            holder->nva.push_back(nghttp2_nv{
                .name = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status")),
                .value = reinterpret_cast<uint8_t *>(holder->header_storage[0].data()),
                .namelen = 7,
                .valuelen = holder->header_storage[0].size(),
                .flags = NGHTTP2_NV_FLAG_NONE_U
            });
            for (size_t i = 1; i + 1 < holder->header_storage.size(); i += 2) {
                auto &n = holder->header_storage[i];
                auto &v = holder->header_storage[i + 1];
                holder->nva.push_back(nghttp2_nv{
                    .name = reinterpret_cast<uint8_t *>(n.data()),
                    .value = reinterpret_cast<uint8_t *>(v.data()),
                    .namelen = n.size(),
                    .valuelen = v.size(),
                    .flags = NGHTTP2_NV_FLAG_NONE_U
                });
            }

            nghttp2_data_provider prov{};
            const nghttp2_data_provider *prov_ptr = nullptr;
            if (!holder->data.empty()) {
                prov.source.ptr = holder.get();
                prov.read_callback = data_source_read;
                prov_ptr = &prov;
            }

            if (const int rv = nghttp2_submit_response(session_, stream_id,
                                                       holder->nva.data(),
                                                       holder->nva.size(),
                                                       prov_ptr);
                rv != 0) {
                log_error(std::format("[{:<11}] nghttp2_submit_response failed: {}",
                                      Derived::kTag, rv));
                return;
            }

            bodies_[stream_id] = std::move(holder);
            do_write();
        }

        void do_read() {
            timer_.expires_after(timeout_.read);
            stream_.async_read_some(net::buffer(read_buf_),
                                    [self = this->shared_from_this()](const error_code &ec, const std::size_t n) {
                                        if (ec) {
                                            if (ec == net::error::operation_aborted)
                                                return;
                                            // stream_truncated is TLS-only; harmless to test on plain TCP.
                                            if (ec != net::error::eof &&
                                                ec != net::ssl::error::stream_truncated &&
                                                self->verbosity_ >= 2) {
                                                log_debug(std::format("[{:<11}] read error: {}",
                                                                      Derived::kTag, ec.message()));
                                            }
                                            return;
                                        }

                                        if (self->verbosity_ >= 2 && !self->preface_logged_ && n > 0) {
                                            self->preface_logged_ = true;
                                            const bool has_preface =
                                                    n >= kH2Preface.size() &&
                                                    std::string_view(
                                                        reinterpret_cast<const char *>(self->read_buf_.data()),
                                                        kH2Preface.size()) == kH2Preface;
                                            if (has_preface) {
                                                log_debug(std::format(
                                                    "[{:<11}] HTTP/2 connection preface received ({} bytes magic)",
                                                    Derived::kTag, kH2Preface.size()));
                                            } else if (Derived::kDiagnoseNonPreface) {
                                                const auto preview_len = std::min<std::size_t>(n, 32);
                                                std::string preview(
                                                    reinterpret_cast<const char *>(self->read_buf_.data()),
                                                    preview_len);
                                                for (char &c: preview) {
                                                    if (c == '\r' || c == '\n' || c < 32 || c > 126)
                                                        c = '.';
                                                }
                                                log_debug(std::format(
                                                    "[{:<11}] non-HTTP/2 start on h2c ({} bytes): \"{}\"",
                                                    Derived::kTag, n, preview));
                                            }
                                        }

                                        size_t off = 0;
                                        while (off < n) {
                                            const ssize_t rv = nghttp2_session_mem_recv(
                                                self->session_, self->read_buf_.data() + off, n - off);
                                            if (rv < 0) {
                                                log_error(std::format(
                                                    "[{:<11}] nghttp2_session_mem_recv failed: {}",
                                                    Derived::kTag, rv));
                                                return;
                                            }
                                            if (rv == 0)
                                                break;
                                            off += static_cast<size_t>(rv);
                                        }

                                        self->do_write();
                                        if (nghttp2_session_want_read(self->session_) ||
                                            nghttp2_session_want_write(self->session_))
                                            self->do_read();
                                    });
        }

        void do_write() {
            if (!session_)
                return;

            for (;;) {
                const uint8_t *data = nullptr;
                const ssize_t len = nghttp2_session_mem_send(session_, &data);
                if (len < 0) {
                    log_error(std::format("[{:<11}] nghttp2_session_mem_send failed: {}",
                                          Derived::kTag, len));
                    return;
                }
                if (len == 0)
                    break;
                write_buf_.insert(write_buf_.end(), data, data + len);
            }

            if (writing_ || write_buf_.empty())
                return;

            writing_ = true;
            writing_buf_.swap(write_buf_);
            write_buf_.clear();

            timer_.expires_after(timeout_.write);
            net::async_write(stream_, net::buffer(writing_buf_),
                             [self = this->shared_from_this()](const error_code &ec, std::size_t) {
                                 self->writing_ = false;
                                 self->writing_buf_.clear();
                                 if (ec) {
                                     if (ec == net::error::operation_aborted)
                                         return;
                                     if (self->verbosity_ >= 2) {
                                         log_error(std::format("[{:<11}] write failed: {}",
                                                               Derived::kTag, ec.message()));
                                     }
                                     return;
                                 }

                                 self->do_write();

                                 if (!self->writing_ && self->write_buf_.empty() &&
                                     !nghttp2_session_want_write(self->session_) &&
                                     !nghttp2_session_want_read(self->session_)) {
                                     error_code ec2;
                                     beast::get_lowest_layer(self->stream_)
                                             .shutdown(tcp::socket::shutdown_both, ec2);
                                     if (ec2 && ec2 != net::error::not_connected && self->verbosity_ >= 2) {
                                         log_debug(std::format("[{:<11}] TCP shutdown: {}",
                                                               Derived::kTag, ec2.message()));
                                     }
                                 }
                             });
        }

    public:
        H2SessionBase(Stream stream, Handler &h, Config::TimeoutConfig &t,
                      const int verbosity, const unsigned short alt_svc_port = 0)
            : stream_(std::move(stream))
              , handler_(h)
              , timeout_(t)
              , timer_(stream_.get_executor())
              , verbosity_(verbosity)
              , alt_svc_port_(alt_svc_port) {
        }

        ~H2SessionBase() {
            if (session_)
                nghttp2_session_del(session_);
        }

        void start() {
            init_session();
            do_write();
            do_read();
        }

        /// Start after a cleartext probe already read the connection preface (and
        /// possibly more). SETTINGS are submitted, initial bytes are ingested via
        /// mem_recv, then normal read/write loops run.
        void start_with_initial(const uint8_t *data, const std::size_t n) {
            init_session();
            do_write();

            if (data && n > 0) {
                size_t off = 0;
                while (off < n) {
                    const ssize_t rv = nghttp2_session_mem_recv(session_, data + off, n - off);
                    if (rv < 0) {
                        log_error(std::format("[{:<11}] nghttp2_session_mem_recv failed: {}",
                                              Derived::kTag, rv));
                        return;
                    }
                    if (rv == 0)
                        break;
                    off += static_cast<size_t>(rv);
                }
                preface_logged_ = true;
                do_write();
            }

            do_read();
        }

        void stop() {
            error_code ec;
            beast::get_lowest_layer(stream_).cancel(ec);
            beast::get_lowest_layer(stream_).close(ec);
        }

    private:
        void init_session() {
            nghttp2_session_callbacks *cbs = nullptr;
            nghttp2_session_callbacks_new(&cbs);
            nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, on_begin_headers);
            nghttp2_session_callbacks_set_on_header_callback(cbs, on_header);
            nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv);
            nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk);
            nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close);

            nghttp2_session_server_new(&session_, cbs, static_cast<Derived *>(this));
            nghttp2_session_callbacks_del(cbs);

            constexpr nghttp2_settings_entry iv[] = {
                {.settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS_U, .value = 100}
            };
            nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE_U, iv, 1);
        }
    };
} // namespace microserve::detail
