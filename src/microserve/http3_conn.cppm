// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <cstddef>
#include <cstdlib>
#include <format>
#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nghttp3/nghttp3.h>

#include "http3_interface.hpp"

module microserve.http3:conn;

import microserve.core;

/**
 * @brief HTTP/3 application session (nghttp3) for one QUIC connection.
 *
 * Implements @ref QuicApp. Does not touch UDP, CIDs, or SSL_CTX.
 */

namespace microserve::http3_detail {

    /**
     * @brief Response body whose lifetime is tied to the HTTP/3 stream.
     *
     * nghttp3 reads the payload by pointer, so the buffer must outlive writes.
     */
    struct BodyHolder {
        std::string body;  ///< Response payload.
        size_t offset{0};  ///< Bytes already handed to nghttp3.
    };

    /**
     * @brief Per-request HTTP state on a client-initiated bidirectional stream.
     */
    struct StreamState {
        std::string method;                         ///< HTTP method (`:method`).
        std::string path;                           ///< Request target (`:path`).
        std::string authority;                      ///< `:authority` pseudo-header.
        std::map<std::string, std::string> headers; ///< Regular headers.
        std::string body;                           ///< Accumulated DATA payload.
        bool headers_done{false};                   ///< `true` after HEADERS is complete.
        bool handled{false};                        ///< `true` after the request is dispatched.
    };

    /**
     * @brief HTTP/3 session on top of one QUIC connection.
     *
     * Owns nghttp3 plus per-stream request/response state.
     * Never touches UDP, CIDs, or SSL_CTX.
     */
    struct H3Session final : QuicApp {
        QuicTransport& qt;                                    ///< Transport used to open streams and log.
        Handler* handler{nullptr};                            ///< Shared request handler (non-owning).
        nghttp3_conn* h3{nullptr};                            ///< nghttp3 connection, created after handshake.
        std::map<int64_t, StreamState> streams;               ///< Client-initiated request streams.
        std::map<int64_t, std::unique_ptr<BodyHolder>> bodies;///< Response bodies still being written.
        bool h3_ready{false};                                 ///< `true` after control / QPACK streams are bound.

        /**
         * @brief STREAM data received before nghttp3 is ready, replayed after handshake.
         */
        struct BufferedStreamData {
            int64_t stream_id{0};       ///< Stream the bytes belong to.
            std::vector<uint8_t> data;  ///< Payload copy.
            bool fin{false};            ///< `true` if the STREAM FIN flag was set.
        };

        std::vector<BufferedStreamData> pending_stream_data;  ///< Replay queue until @ref init_http3.

        /**
         * @brief Bind this session to @p qt and the shared request @p handler.
         *
         * @param qt      QUIC transport used to open streams and log.
         * @param handler Request handler (non-owning); may be null.
         */
        H3Session(QuicTransport& qt, Handler* handler) : qt(qt), handler(handler) {}

        /**
         * @brief Release response bodies and destroy the nghttp3 connection.
         */
        ~H3Session() override;

        /**
         * @brief Handshake completed; initialise HTTP/3.
         *
         * @return `0` on success, `-1` on failure.
         */
        int on_handshake_completed() override;

        /**
         * @brief Feed STREAM data into nghttp3, or buffer it until HTTP/3 is ready.
         *
         * @param stream_id Stream that received data.
         * @param data      Payload bytes.
         * @param data_len  Payload length.
         * @param fin       Non-zero if this is the final STREAM chunk.
         * @param consumed  Set to the number of bytes accepted from @p data.
         * @return `0` on success, `-1` on failure.
         */
        int on_recv_stream_data(int64_t stream_id, const uint8_t* data, size_t data_len,
                                int fin, size_t& consumed) override;

        /**
         * @brief Record a newly opened stream.
         *
         * @param stream_id Newly opened stream.
         * @return `0`.
         */
        int on_stream_open(int64_t stream_id) override;

        /**
         * @brief Close @p stream_id in nghttp3 and drop local state.
         *
         * @param stream_id      Closed stream.
         * @param app_error_code Application error code, if set.
         * @param app_error_set  `true` when @p app_error_code is valid.
         * @param bidi           `true` for a bidirectional stream.
         * @return `0` on success, `-1` on failure.
         */
        int on_stream_close(int64_t stream_id, uint64_t app_error_code, bool app_error_set,
                            bool bidi) override;

        /**
         * @brief Notify nghttp3 that previously sent STREAM data was acknowledged.
         *
         * @param stream_id Stream whose data was ACKed.
         * @param data_len  Number of acknowledged bytes.
         * @return `0` on success, `-1` on failure.
         */
        int on_acked_stream_data(int64_t stream_id, uint64_t data_len) override;

        /**
         * @brief Forward a new bidirectional remote-stream limit to nghttp3.
         *
         * @param max_streams New maximum number of remote bidi streams.
         */
        void on_extend_max_remote_streams_bidi(uint64_t max_streams) override;

        /**
         * @brief Unblock @p stream_id in nghttp3 after its send window grew.
         *
         * @param stream_id Stream whose send window grew.
         * @return `0` on success, `-1` on failure.
         */
        int on_extend_max_stream_data(int64_t stream_id) override;

        /**
         * @brief Stop reading @p stream_id and drop local state after a reset.
         *
         * @param stream_id Reset stream.
         */
        void on_stream_reset(int64_t stream_id) override;

        /**
         * @brief Fill @p vecs with the next nghttp3 STREAM write, if any.
         *
         * @param stream_id Set to the stream that should be written.
         * @param fin       Set to non-zero if this is the last chunk.
         * @param vecs      Output scatter list.
         * @param size      Capacity of @p vecs.
         * @return Number of vectors filled, `0` if nothing to send, or `-1` on error.
         */
        int poll_stream_write(int64_t& stream_id, int& fin, QuicVec* vecs, size_t size) override;

        /**
         * @brief Advance nghttp3's write offset after @p n bytes were sent.
         *
         * @param stream_id Stream that was written.
         * @param n         Bytes just sent.
         * @return `0` on success, `-1` on failure.
         */
        int add_write_offset(int64_t stream_id, size_t n) override;

        /**
         * @brief Mark @p stream_id blocked on flow control in nghttp3.
         *
         * @param stream_id Stream that cannot send until the window grows.
         */
        void block_stream(int64_t stream_id) override;

        /**
         * @brief Stop sending on @p stream_id (half-close the write side).
         *
         * @param stream_id Stream whose write side is shut down.
         */
        void shutdown_stream_write(int64_t stream_id) override;

        /**
         * @brief Create the nghttp3 server connection and bind control / QPACK streams.
         *
         * Replays any STREAM data buffered before the handshake completed.
         *
         * @return `0` on success, `-1` on failure.
         */
        int init_http3();

        /**
         * @brief Dispatch a completed request on @p stream_id to the handler.
         *
         * @param stream_id Client-initiated stream whose headers (and body) are complete.
         */
        void on_h3_request(int64_t stream_id);

        /**
         * @brief Submit @p res on @p stream_id via nghttp3.
         *
         * @param stream_id Stream to respond on.
         * @param res       Application response (status, headers, body).
         */
        void submit_response(int64_t stream_id, const Response& res);

        /**
         * @brief Current log verbosity (`0` is quiet).
         *
         * @return Verbosity level from the owning transport.
         */
        int verbosity() const { return qt.verbosity(); }

        /**
         * @brief Log an error message via the transport.
         *
         * @param m Message to log.
         */
        void error(const std::string& m) const { qt.log_msg(0, m.c_str()); }

        /**
         * @brief Log an info message via the transport.
         *
         * @param m Message to log.
         */
        void info(const std::string& m) const { qt.log_msg(1, m.c_str()); }

        /**
         * @brief Log a debug message via the transport.
         *
         * @param m Message to log.
         */
        void debug(const std::string& m) const { qt.log_msg(2, m.c_str()); }
    };

    H3Session::~H3Session() {
        bodies.clear();
        if (h3) {
            nghttp3_conn_del(h3);
            h3 = nullptr;
        }
    }

    static int h3_recv_header(nghttp3_conn*, const int64_t stream_id, int32_t,
                              nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t,
                              void* user_data, void*) {
        auto* s = static_cast<H3Session*>(user_data);
        auto& st = s->streams[stream_id];

        const auto [n_base, n_len] = nghttp3_rcbuf_get_buf(name);
        const auto [v_base, v_len] = nghttp3_rcbuf_get_buf(value);
        const std::string_view n(reinterpret_cast<const char*>(n_base), n_len);
        const std::string_view v(reinterpret_cast<const char*>(v_base), v_len);

        if (n == ":method") st.method.assign(v);
        else if (n == ":path") st.path.assign(v);
        else if (n == ":authority") st.authority.assign(v);
        else st.headers.emplace(std::string(n), std::string(v));
        return 0;
    }

    static int h3_end_headers(nghttp3_conn*, const int64_t stream_id, const int fin,
                              void* user_data, void*) {
        auto* s = static_cast<H3Session*>(user_data);
        auto& st = s->streams[stream_id];
        st.headers_done = true;
        if (fin)
            s->on_h3_request(stream_id);
        return 0;
    }

    static int h3_recv_data(nghttp3_conn*, const int64_t stream_id, const uint8_t* data,
                            const size_t data_len, void* user_data, void*) {
        static_cast<H3Session*>(user_data)->streams[stream_id].body.append(
            reinterpret_cast<const char*>(data), data_len);
        return 0;
    }

    static int h3_end_stream(nghttp3_conn*, const int64_t stream_id, void* user_data, void*) {
        static_cast<H3Session*>(user_data)->on_h3_request(stream_id);
        return 0;
    }

    static int h3_acked_stream_data(nghttp3_conn*, int64_t, uint64_t, void*, void*) {
        return 0;
    }

    static int h3_stream_close(nghttp3_conn*, const int64_t stream_id, uint64_t,
                               void* user_data, void*) {
        auto* s = static_cast<H3Session*>(user_data);
        s->bodies.erase(stream_id);
        s->streams.erase(stream_id);
        return 0;
    }

    static int h3_deferred_consume(nghttp3_conn*, const int64_t stream_id, const size_t num_consumed,
                                   void* user_data, void*) {
        const auto* s = static_cast<H3Session*>(user_data);
        if (num_consumed == 0)
            return 0;
        s->qt.extend_max_stream_offset(stream_id, num_consumed);
        s->qt.extend_max_offset(num_consumed);
        return 0;
    }

    int H3Session::on_handshake_completed() {
        return init_http3();
    }

    int H3Session::on_recv_stream_data(const int64_t stream_id, const uint8_t* data,
                                       const size_t data_len, const int fin, size_t& consumed) {
        consumed = 0;

        if (!h3 || !h3_ready) {
            if (data_len > 0 || fin) {
                BufferedStreamData chunk;
                chunk.stream_id = stream_id;
                chunk.fin = fin != 0;
                if (data_len > 0 && data)
                    chunk.data.assign(data, data + data_len);
                pending_stream_data.push_back(std::move(chunk));
            }
            return 0;
        }

        if (data_len == 0 && !fin)
            return 0;

        const nghttp3_ssize num_consumed =
            nghttp3_conn_read_stream(h3, stream_id, data, data_len, fin);
        if (num_consumed < 0) {
            error(std::format(
                "[{:<11}] nghttp3_conn_read_stream stream={} len={} fin={} → {} ({})",
                "http3", stream_id, data_len, fin,
                static_cast<int>(num_consumed),
                nghttp3_strerror(static_cast<int>(num_consumed))));
            return -1;
        }

        if (num_consumed > 0)
            consumed = static_cast<size_t>(num_consumed);
        return 0;
    }

    int H3Session::on_stream_open(const int64_t stream_id) {
        streams.emplace(stream_id, StreamState{});
        return 0;
    }

    int H3Session::on_stream_close(const int64_t stream_id, uint64_t app_error_code,
                                   const bool app_error_set, const bool bidi) {
        if (!app_error_set)
            app_error_code = NGHTTP3_H3_NO_ERROR;

        if (h3) {
            if (const int rv = nghttp3_conn_close_stream(h3, stream_id, app_error_code);
                rv != 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
                error(std::format(
                    "[{:<11}] nghttp3_conn_close_stream stream={} → {} ({})",
                    "http3", stream_id, rv, nghttp3_strerror(rv)));
                if (!bidi) {
                    bodies.erase(stream_id);
                    streams.erase(stream_id);
                    return 0;
                }
                return -1;
            }
        }

        bodies.erase(stream_id);
        streams.erase(stream_id);
        return 0;
    }

    int H3Session::on_acked_stream_data(const int64_t stream_id, const uint64_t data_len) {
        if (!h3 || data_len == 0)
            return 0;
        if (nghttp3_conn_add_ack_offset(h3, stream_id, data_len) != 0) {
            error(std::format("[{:<11}] nghttp3_conn_add_ack_offset failed", "http3"));
            return -1;
        }
        return 0;
    }

    void H3Session::on_extend_max_remote_streams_bidi(const uint64_t max_streams) {
        if (h3)
            nghttp3_conn_set_max_client_streams_bidi(h3, max_streams);
    }

    int H3Session::on_extend_max_stream_data(const int64_t stream_id) {
        if (h3 && nghttp3_conn_unblock_stream(h3, stream_id) != 0)
            return -1;
        return 0;
    }

    void H3Session::on_stream_reset(const int64_t stream_id) {
        if (h3)
            nghttp3_conn_shutdown_stream_read(h3, stream_id);
        bodies.erase(stream_id);
        streams.erase(stream_id);
    }

    int H3Session::poll_stream_write(int64_t& stream_id, int& fin, QuicVec* vecs, const size_t size) {
        if (!h3) {
            stream_id = -1;
            fin = 0;
            return 0;
        }

        nghttp3_vec vec[16];
        const size_t n = size < 16 ? size : 16;
        const nghttp3_ssize ssize = nghttp3_conn_writev_stream(h3, &stream_id, &fin, vec, n);
        if (ssize < 0) {
            error(std::format("[{:<11}] nghttp3_conn_writev_stream: {} ({})",
                              "http3", static_cast<int>(ssize),
                              nghttp3_strerror(static_cast<int>(ssize))));
            return -1;
        }

        for (nghttp3_ssize i = 0; i < ssize; ++i) {
            vecs[i].base = vec[i].base;
            vecs[i].len = vec[i].len;
        }
        return static_cast<int>(ssize);
    }

    int H3Session::add_write_offset(const int64_t stream_id, const size_t n) {
        if (!h3 || n == 0)
            return 0;
        if (const int arv = nghttp3_conn_add_write_offset(h3, stream_id, n); arv != 0) {
            error(std::format("[{:<11}] add_write_offset: {} ({})",
                              "http3", arv, nghttp3_strerror(arv)));
            return -1;
        }
        return 0;
    }

    void H3Session::block_stream(const int64_t stream_id) {
        if (h3)
            nghttp3_conn_block_stream(h3, stream_id);
    }

    void H3Session::shutdown_stream_write(const int64_t stream_id) {
        if (h3)
            nghttp3_conn_shutdown_stream_write(h3, stream_id);
    }

    int H3Session::init_http3() {
        if (h3)
            return 0;

        nghttp3_callbacks h3cb{};
        h3cb.recv_header = h3_recv_header;
        h3cb.end_headers = h3_end_headers;
        h3cb.recv_data = h3_recv_data;
        h3cb.end_stream = h3_end_stream;
        h3cb.acked_stream_data = h3_acked_stream_data;
        h3cb.stream_close = h3_stream_close;
        h3cb.deferred_consume = h3_deferred_consume;

        nghttp3_settings settings;
        nghttp3_settings_default(&settings);
        settings.qpack_max_dtable_capacity = 4096;
        settings.qpack_blocked_streams = 100;

        if (const int rv = nghttp3_conn_server_new(&h3, &h3cb, &settings, nullptr, this); rv != 0) {
            error(std::format("[{:<11}] nghttp3_conn_server_new failed: {} ({})",
                              "http3", rv, nghttp3_strerror(rv)));
            return -1;
        }

        nghttp3_conn_set_max_client_streams_bidi(h3, 100);

        int64_t ctrl_sid = -1;
        if (qt.open_uni_stream(ctrl_sid) != 0) {
            error(std::format("[{:<11}] open control stream failed", "http3"));
            return -1;
        }
        if (const int rv = nghttp3_conn_bind_control_stream(h3, ctrl_sid); rv != 0) {
            error(std::format("[{:<11}] bind control stream failed: {} ({})",
                              "http3", rv, nghttp3_strerror(rv)));
            return -1;
        }

        int64_t qpack_enc = -1;
        int64_t qpack_dec = -1;
        if (qt.open_uni_stream(qpack_enc) != 0 || qt.open_uni_stream(qpack_dec) != 0) {
            error(std::format("[{:<11}] open QPACK streams failed", "http3"));
            return -1;
        }
        if (const int rv = nghttp3_conn_bind_qpack_streams(h3, qpack_enc, qpack_dec); rv != 0) {
            error(std::format("[{:<11}] bind QPACK streams failed: {} ({})",
                              "http3", rv, nghttp3_strerror(rv)));
            return -1;
        }

        h3_ready = true;

        if (verbosity() >= 2) {
            debug(std::format(
                "[{:<11}] HTTP/3 ready (ctrl={}, qenc={}, qdec={}, pending={})",
                "http3", ctrl_sid, qpack_enc, qpack_dec, pending_stream_data.size()));
        }

        for (auto& [stream_id, data, fin] : pending_stream_data) {
            const uint8_t* p = data.empty() ? nullptr : data.data();
            const size_t n = data.size();

            const nghttp3_ssize num_consumed =
                nghttp3_conn_read_stream(h3, stream_id, p, n, fin ? 1 : 0);
            if (num_consumed < 0) {
                error(std::format("[{:<11}] replay read_stream stream={} → {} ({})",
                                  "http3", stream_id,
                                  static_cast<int>(num_consumed),
                                  nghttp3_strerror(static_cast<int>(num_consumed))));
                pending_stream_data.clear();
                return -1;
            }
            if (num_consumed > 0) {
                qt.extend_max_stream_offset(stream_id, static_cast<uint64_t>(num_consumed));
                qt.extend_max_offset(static_cast<uint64_t>(num_consumed));
            }
        }
        pending_stream_data.clear();
        return 0;
    }

    void H3Session::on_h3_request(const int64_t stream_id) {
        const auto it = streams.find(stream_id);
        if (it == streams.end())
            return;

        auto& [
            method,
            path,
            authority,
            headers,
            body,
            headers_done,
            handled
        ] = it->second;
        if (handled || !headers_done)
            return;
        handled = true;

        Request req;
        req.method(http::string_to_verb(method));
        req.target(path.empty() ? "/" : path);
        req.version(11);
        for (const auto& [k, v] : headers)
            req.set(k, v);
        if (!authority.empty())
            req.set(http::field::host, authority);
        req.body() = std::move(body);
        req.prepare_payload();

        Response res;
        res.version(11);
        if (handler && *handler)
            (*handler)(req, res);

        if (verbosity() >= 1) {
            if (const auto bytes = res.body().size(); bytes > 0) {
                info(std::format("[{:<11}] {} {} size={} {}",
                                 "request/h3", method, std::string(req.target()),
                                 bytes, res.result_int()));
            } else {
                info(std::format("[{:<11}] {} {} {}",
                                 "request/h3", method, std::string(req.target()),
                                 res.result_int()));
            }
        }

        submit_response(stream_id, res);
    }

    static nghttp3_ssize body_read_cb(nghttp3_conn*, int64_t, nghttp3_vec* vec,
                                      const size_t vec_count, uint32_t* p_flags,
                                      void*, void* stream_user_data) {
        auto* bh = static_cast<BodyHolder*>(stream_user_data);
        if (!bh || bh->offset >= bh->body.size()) {
            *p_flags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }
        if (vec_count == 0)
            return 0;

        const size_t remaining = bh->body.size() - bh->offset;
        if (remaining == 0) {
            *p_flags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }

        vec[0].base = reinterpret_cast<uint8_t*>(bh->body.data() + bh->offset);
        vec[0].len = remaining;
        bh->offset = bh->body.size();
        *p_flags |= NGHTTP3_DATA_FLAG_EOF;
        return 1;
    }

    void H3Session::submit_response(const int64_t stream_id, const Response& res) {
        auto holder = std::make_unique<BodyHolder>();
        holder->body = res.body();
        BodyHolder* raw = holder.get();

        std::vector<std::string> storage;
        storage.reserve(1 + static_cast<size_t>(std::distance(res.begin(), res.end())) * 2);
        storage.emplace_back(std::to_string(res.result_int() == 0 ? 200u : res.result_int()));
        for (const auto& field : res) {
            storage.emplace_back(field.name_string());
            storage.emplace_back(field.value());
        }

        std::vector<nghttp3_nv> nva;
        nva.reserve(1 + (storage.size() - 1) / 2);
        nva.push_back(nghttp3_nv{
            .name = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
            .value = reinterpret_cast<uint8_t*>(storage[0].data()),
            .namelen = 7,
            .valuelen = storage[0].size(),
            .flags = NGHTTP3_NV_FLAG_NONE,
        });
        for (size_t i = 1; i + 1 < storage.size(); i += 2) {
            auto& n = storage[i];
            auto& v = storage[i + 1];
            nva.push_back(nghttp3_nv{
                .name = reinterpret_cast<uint8_t*>(n.data()),
                .value = reinterpret_cast<uint8_t*>(v.data()),
                .namelen = n.size(),
                .valuelen = v.size(),
                .flags = NGHTTP3_NV_FLAG_NONE,
            });
        }

        nghttp3_data_reader dr{};
        dr.read_data = body_read_cb;

        if (nghttp3_conn_set_stream_user_data(h3, stream_id, raw) != 0) {
            error(std::format("[{:<11}] set_stream_user_data failed", "http3"));
            return;
        }

        const int rv = nghttp3_conn_submit_response(
            h3, stream_id, nva.data(), nva.size(),
            holder->body.empty() ? nullptr : &dr);
        if (rv != 0) {
            nghttp3_conn_set_stream_user_data(h3, stream_id, nullptr);
            error(std::format(
                "[{:<11}] nghttp3_conn_submit_response failed: {} ({})",
                "http3", rv, nghttp3_strerror(rv)));
            return;
        }

        bodies[stream_id] = std::move(holder);
    }

    /**
     * @brief Construct an HTTP/3 session as a @ref QuicApp.
     *
     * @param qt      QUIC transport for the owning connection.
     * @param handler Request handler (non-owning).
     * @return New session implementing @ref QuicApp.
     */
    std::unique_ptr<QuicApp> make_h3_session(QuicTransport& qt, Handler* handler) {
        return std::make_unique<H3Session>(qt, handler);
    }

} // namespace microserve::http3_detail
