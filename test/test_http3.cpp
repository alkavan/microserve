// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>
#include <openssl/ssl.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL) || __has_include(<ngtcp2/ngtcp2_crypto_ossl.h>)
#  include <ngtcp2/ngtcp2_crypto_ossl.h>
#  ifndef MICROSERVE_NGTCP2_CRYPTO_OSSL
#    define MICROSERVE_NGTCP2_CRYPTO_OSSL 1
#  endif
#elif defined(MICROSERVE_NGTCP2_CRYPTO_QUICTLS) || __has_include(<ngtcp2/ngtcp2_crypto_quictls.h>)
#  include <ngtcp2/ngtcp2_crypto_quictls.h>
#  ifndef MICROSERVE_NGTCP2_CRYPTO_QUICTLS
#    define MICROSERVE_NGTCP2_CRYPTO_QUICTLS 1
#  endif
#elif __has_include(<ngtcp2/ngtcp2_crypto_openssl.h>)
#  include <ngtcp2/ngtcp2_crypto_openssl.h>
#  define MICROSERVE_NGTCP2_CRYPTO_OPENSSL 1
#endif

import microserve.core;
import microserve.http3;
import microserve.server;

namespace {

constexpr size_t kCidLen = 8;
constexpr size_t kMaxUdpPayload = 1350;
constexpr int kDriveTimeoutMs = 500;
/** Wait long enough for ngtcp2's initial PTO (≈2×333ms, often ~1s). */
constexpr int kPtoWaitMs = 2000;
constexpr int kLossDriveTimeoutMs = 4000;

ngtcp2_tstamp timestamp()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

std::array<uint8_t, kCidLen> random_cid()
{
    std::array<uint8_t, kCidLen> cid{};
    thread_local std::mt19937_64 rng{std::random_device{}()};
    for (auto& b : cid)
        b = static_cast<uint8_t>(rng());
    return cid;
}

void fill_crypto_callbacks(ngtcp2_callbacks& cb)
{
    cb.client_initial = ngtcp2_crypto_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
}

int configure_client_ssl_ctx(SSL_CTX* ctx)
{
#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL)
    (void)ctx;
    return 0;
#elif defined(MICROSERVE_NGTCP2_CRYPTO_QUICTLS)
    return ngtcp2_crypto_quictls_configure_client_context(ctx);
#elif defined(MICROSERVE_NGTCP2_CRYPTO_OPENSSL)
    return ngtcp2_crypto_openssl_configure_client_context(ctx);
#else
    (void)ctx;
    return -1;
#endif
}

/**
 * Minimal HTTP/3 client for localhost tests (ngtcp2 + nghttp3 + TLS 1.3).
 * One outstanding request at a time.
 */
struct H3Client {
    microserve::net::io_context ioc{};
    microserve::udp::socket socket{nullptr};
    microserve::udp::endpoint local_ep{};
    microserve::udp::endpoint remote_ep{};

    ngtcp2_conn* conn{nullptr};
    nghttp3_conn* h3{nullptr};
    SSL_CTX* ssl_ctx{nullptr};
    SSL* ssl{nullptr};
#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL)
    ngtcp2_crypto_ossl_ctx* ossl_ctx{nullptr};
#endif
    ngtcp2_crypto_conn_ref conn_ref{};

    bool handshake_done{false};
    bool h3_ready{false};
    bool closing{false};
    std::string error;

    int status{0};
    std::string body;
    std::map<std::string, std::string> headers;
    bool response_complete{false};

    std::string method_store;
    std::string path_store;
    std::string extra_name_store;
    std::string extra_value_store;
    std::string req_body;
    size_t req_body_off{0};

    H3Client() : socket(ioc) { conn_ref.get_conn = &H3Client::get_conn; conn_ref.user_data = this; }

    H3Client(const H3Client&) = delete;
    H3Client& operator=(const H3Client&) = delete;

    ~H3Client()
    {
        if (h3)
            nghttp3_conn_del(h3);
        if (conn)
            ngtcp2_conn_del(conn);
#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL)
        if (ossl_ctx)
            ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
#endif
        if (ssl)
            SSL_free(ssl);
        if (ssl_ctx)
            SSL_CTX_free(ssl_ctx);
        microserve::error_code ec;
        socket.close(ec);
    }

    static ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref)
    {
        return static_cast<H3Client*>(ref->user_data)->conn;
    }

    [[nodiscard]] ngtcp2_path make_path() const
    {
        ngtcp2_path path{};
        path.local.addr = const_cast<sockaddr*>(local_ep.data());
        path.local.addrlen = static_cast<ngtcp2_socklen>(local_ep.size());
        path.remote.addr = const_cast<sockaddr*>(remote_ep.data());
        path.remote.addrlen = static_cast<ngtcp2_socklen>(remote_ep.size());
        return path;
    }

    void fail(const std::string& m)
    {
        if (error.empty())
            error = m;
        closing = true;
    }

    static int cb_handshake_completed(ngtcp2_conn*, void* user_data)
    {
        auto* c = static_cast<H3Client*>(user_data);
        c->handshake_done = true;
        return c->init_http3();
    }

    static int cb_recv_stream_data(ngtcp2_conn* qc, const uint32_t flags, const int64_t stream_id, uint64_t,
                                   const uint8_t* data, const size_t data_len, void* user_data, void*)
    {
        auto* c = static_cast<H3Client*>(user_data);
        if (!c->h3 || !c->h3_ready)
            return 0;
        const int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
        const nghttp3_ssize n = nghttp3_conn_read_stream(c->h3, stream_id, data, data_len, fin);
        if (n < 0) {
            c->fail(nghttp3_strerror(static_cast<int>(n)));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (n > 0) {
            ngtcp2_conn_extend_max_stream_offset(qc, stream_id, static_cast<uint64_t>(n));
            ngtcp2_conn_extend_max_offset(qc, static_cast<uint64_t>(n));
        }
        return 0;
    }

    static int cb_stream_close(ngtcp2_conn*, uint32_t, const int64_t stream_id, const uint64_t app_error_code,
                               void* user_data, void*)
    {
        if (const auto* c = static_cast<H3Client*>(user_data); c->h3)
            nghttp3_conn_close_stream(c->h3, stream_id, app_error_code);
        return 0;
    }

    static int cb_stream_open(ngtcp2_conn*, int64_t, void*)
    {
        return 0;
    }

    static int cb_acked_stream_data_offset(ngtcp2_conn*, const int64_t stream_id, uint64_t,
                                           const uint64_t data_len, void* user_data, void*)
    {
        if (const auto* c = static_cast<H3Client*>(user_data); c->h3 && data_len > 0)
            nghttp3_conn_add_ack_offset(c->h3, stream_id, data_len);
        return 0;
    }

    static int cb_extend_max_stream_data(ngtcp2_conn*, const int64_t stream_id, uint64_t, void* user_data,
                                         void*)
    {
        if (const auto* c = static_cast<H3Client*>(user_data); c->h3)
            nghttp3_conn_unblock_stream(c->h3, stream_id);
        return 0;
    }

    static int cb_path_validation(ngtcp2_conn*, uint32_t, const ngtcp2_path*,
                                  const ngtcp2_path*, ngtcp2_path_validation_result, void*)
    {
        return 0;
    }

    static int cb_extend_max_local_streams_bidi(ngtcp2_conn*, uint64_t, void*)
    {
        return 0;
    }

    static void cb_rand(uint8_t* dest, const size_t dest_len, const ngtcp2_rand_ctx*)
    {
        thread_local std::mt19937_64 rng{std::random_device{}()};
        for (size_t i = 0; i < dest_len; ++i)
            dest[i] = static_cast<uint8_t>(rng());
    }

    static int cb_get_new_connection_id(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cid_len,
                                        void*)
    {
        const auto bytes = random_cid();
        if (cid_len > bytes.size())
            cid_len = bytes.size();
        ngtcp2_cid_init(cid, bytes.data(), cid_len);
        thread_local std::mt19937_64 rng{std::random_device{}()};
        for (size_t i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i)
            token[i] = static_cast<uint8_t>(rng());
        return 0;
    }

    static int h3_recv_header(nghttp3_conn*, int64_t, int32_t, nghttp3_rcbuf* name,
                              nghttp3_rcbuf* value, uint8_t, void* user_data, void*)
    {
        auto* c = static_cast<H3Client*>(user_data);
        const auto [n_base, n_len] = nghttp3_rcbuf_get_buf(name);
        const auto [v_base, v_len] = nghttp3_rcbuf_get_buf(value);
        const std::string_view n(reinterpret_cast<const char*>(n_base), n_len);
        const std::string_view v(reinterpret_cast<const char*>(v_base), v_len);
        if (n == ":status") {
            c->status = 0;
            for (const char ch : v)
                c->status = c->status * 10 + (ch - '0');
        } else {
            c->headers.emplace(std::string(n), std::string(v));
        }
        return 0;
    }

    static int h3_end_headers(nghttp3_conn*, int64_t, const int fin, void* user_data, void*)
    {
        if (fin)
            static_cast<H3Client*>(user_data)->response_complete = true;
        return 0;
    }

    static int h3_recv_data(nghttp3_conn*, int64_t, const uint8_t* data, const size_t data_len,
                            void* user_data, void*)
    {
        static_cast<H3Client*>(user_data)->body.append(reinterpret_cast<const char*>(data), data_len);
        return 0;
    }

    static int h3_end_stream(nghttp3_conn*, int64_t, void* user_data, void*)
    {
        static_cast<H3Client*>(user_data)->response_complete = true;
        return 0;
    }

    static int h3_deferred_consume(nghttp3_conn*, const int64_t stream_id, const size_t n, void* user_data, void*)
    {
        if (const auto* c = static_cast<H3Client*>(user_data); c->conn && n > 0) {
            ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, n);
            ngtcp2_conn_extend_max_offset(c->conn, n);
        }
        return 0;
    }

    static nghttp3_ssize body_read_cb(nghttp3_conn*, int64_t, nghttp3_vec* vec, const size_t vec_count,
                                      uint32_t* p_flags, void*, void* sud)
    {
        auto* c = static_cast<H3Client*>(sud);
        if (!c || c->req_body_off >= c->req_body.size()) {
            *p_flags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }
        if (vec_count == 0)
            return 0;
        vec[0].base = reinterpret_cast<uint8_t*>(c->req_body.data() + c->req_body_off);
        vec[0].len = c->req_body.size() - c->req_body_off;
        c->req_body_off = c->req_body.size();
        *p_flags |= NGHTTP3_DATA_FLAG_EOF;
        return 1;
    }

    int init_http3()
    {
        if (h3)
            return 0;

        nghttp3_callbacks cb{};
        cb.recv_header = h3_recv_header;
        cb.end_headers = h3_end_headers;
        cb.recv_data = h3_recv_data;
        cb.end_stream = h3_end_stream;
        cb.deferred_consume = h3_deferred_consume;

        nghttp3_settings settings;
        nghttp3_settings_default(&settings);
        settings.qpack_max_dtable_capacity = 4096;
        settings.qpack_blocked_streams = 100;

        if (nghttp3_conn_client_new(&h3, &cb, &settings, nullptr, this) != 0) {
            fail("nghttp3_conn_client_new failed");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        int64_t ctrl = -1;
        int64_t qenc = -1;
        int64_t qdec = -1;
        if (ngtcp2_conn_open_uni_stream(conn, &ctrl, nullptr) != 0 ||
            nghttp3_conn_bind_control_stream(h3, ctrl) != 0 ||
            ngtcp2_conn_open_uni_stream(conn, &qenc, nullptr) != 0 ||
            ngtcp2_conn_open_uni_stream(conn, &qdec, nullptr) != 0 ||
            nghttp3_conn_bind_qpack_streams(h3, qenc, qdec) != 0) {
            fail("failed to bind HTTP/3 control/QPACK streams");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        h3_ready = true;
        return 0;
    }

    bool setup_tls()
    {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx)
            return false;
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr);
        static constexpr unsigned char alpn[] = {2, 'h', '3'};
        if (SSL_CTX_set_alpn_protos(ssl_ctx, alpn, sizeof(alpn)) != 0)
            return false;
        if (configure_client_ssl_ctx(ssl_ctx) != 0)
            return false;

        ssl = SSL_new(ssl_ctx);
        if (!ssl)
            return false;
        SSL_set_connect_state(ssl);
        SSL_set_app_data(ssl, &conn_ref);
        SSL_set_tlsext_host_name(ssl, "localhost");
        if (SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) != 0)
            return false;

#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL)
        if (ngtcp2_crypto_ossl_ctx_new(&ossl_ctx, ssl) != 0)
            return false;
        ngtcp2_crypto_ossl_ctx_set_ssl(ossl_ctx, ssl);
        if (ngtcp2_crypto_ossl_configure_client_session(ssl) != 0)
            return false;
        ngtcp2_conn_set_tls_native_handle(conn, ossl_ctx);
#elif defined(MICROSERVE_NGTCP2_CRYPTO_QUICTLS)
        if (ngtcp2_crypto_quictls_configure_client_session(ssl) != 0)
            return false;
        ngtcp2_conn_set_tls_native_handle(conn, ssl);
#elif defined(MICROSERVE_NGTCP2_CRYPTO_OPENSSL)
        if (ngtcp2_crypto_openssl_configure_client_session(ssl) != 0)
            return false;
        ngtcp2_conn_set_tls_native_handle(conn, ssl);
#else
        return false;
#endif
        return true;
    }

    bool start(const unsigned short port)
    {
        // UDP has no accept queue: wait until the server thread is in recv.
        microserve::test::sleep_ms(20);

        microserve::error_code ec;
        socket.open(microserve::udp::v4(), ec);
        if (ec) {
            fail("UDP open failed: " + ec.message());
            return false;
        }
        socket.bind(microserve::udp::endpoint(microserve::net::ip::make_address("127.0.0.1"), 0),
                    ec);
        if (ec) {
            fail("UDP bind failed: " + ec.message());
            return false;
        }
        local_ep = socket.local_endpoint();
        remote_ep = microserve::udp::endpoint(microserve::net::ip::make_address("127.0.0.1"), port);

        const auto dcid_bytes = random_cid();
        const auto scid_bytes = random_cid();
        ngtcp2_cid dcid{};
        ngtcp2_cid scid{};
        ngtcp2_cid_init(&dcid, dcid_bytes.data(), dcid_bytes.size());
        ngtcp2_cid_init(&scid, scid_bytes.data(), scid_bytes.size());

        ngtcp2_callbacks callbacks{};
        fill_crypto_callbacks(callbacks);
        callbacks.handshake_completed = cb_handshake_completed;
        callbacks.recv_stream_data = cb_recv_stream_data;
        callbacks.stream_open = cb_stream_open;
        callbacks.stream_close = cb_stream_close;
        callbacks.acked_stream_data_offset = cb_acked_stream_data_offset;
        callbacks.extend_max_stream_data = cb_extend_max_stream_data;
        callbacks.rand = cb_rand;
        callbacks.get_new_connection_id = cb_get_new_connection_id;
        callbacks.path_validation = cb_path_validation;
        callbacks.extend_max_local_streams_bidi = cb_extend_max_local_streams_bidi;

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = timestamp();

        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 32;
        params.initial_max_data = 1 * 1024 * 1024;
        params.initial_max_stream_data_bidi_local = 512 * 1024;
        params.initial_max_stream_data_bidi_remote = 512 * 1024;
        params.initial_max_stream_data_uni = 512 * 1024;
        params.max_idle_timeout = 30 * NGTCP2_SECONDS;

        const ngtcp2_path path = make_path();
        if (ngtcp2_conn_client_new(&conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &callbacks,
                                   &settings, &params, nullptr, this) != 0) {
            fail("ngtcp2_conn_client_new failed");
            return false;
        }
        if (!setup_tls()) {
            fail("client TLS setup failed");
            return false;
        }
        flush();
        return error.empty() && !closing;
    }

    bool connect_to(const unsigned short port)
    {
        if (!start(port))
            return false;
        return drive_until([this] { return handshake_done && h3_ready; }, kDriveTimeoutMs);
    }

    void send_packet(const uint8_t* data, const size_t len)
    {
        microserve::error_code ec;
        socket.send_to(microserve::net::buffer(data, len), remote_ep, 0, ec);
        if (ec)
            fail("UDP send failed: " + ec.message());
    }

    void flush()
    {
        if (!conn || closing)
            return;

        std::array<uint8_t, kMaxUdpPayload> buf{};
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        const ngtcp2_path path = make_path();
        ps.path = path;
        ngtcp2_pkt_info pi{};

        for (;;) {
            if (h3) {
                nghttp3_vec vec[16];
                int64_t stream_id = -1;
                int fin = 0;
                const nghttp3_ssize sveccnt = nghttp3_conn_writev_stream(h3, &stream_id, &fin, vec, 16);
                if (sveccnt < 0) {
                    fail(nghttp3_strerror(static_cast<int>(sveccnt)));
                    return;
                }
                if (sveccnt > 0 || (stream_id >= 0 && fin)) {
                    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
                    if (fin)
                        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                    ngtcp2_vec data[16];
                    size_t data_cnt = 0;
                    for (nghttp3_ssize i = 0; i < sveccnt; ++i) {
                        if (!vec[i].base || vec[i].len == 0)
                            continue;
                        data[data_cnt].base = vec[i].base;
                        data[data_cnt].len = vec[i].len;
                        ++data_cnt;
                    }
                    ngtcp2_ssize ndatalen = -1;
                    const ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
                        conn, &ps.path, &pi, buf.data(), buf.size(), &ndatalen, flags, stream_id,
                        data_cnt ? data : nullptr, data_cnt, timestamp());
                    if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                        nghttp3_conn_block_stream(h3, stream_id);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
                        nghttp3_conn_shutdown_stream_write(h3, stream_id);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_WRITE_MORE || nwrite >= 0) {
                        if (ndatalen > 0)
                            nghttp3_conn_add_write_offset(h3, stream_id, static_cast<size_t>(ndatalen));
                        if (nwrite == NGTCP2_ERR_WRITE_MORE)
                            continue;
                        if (nwrite > 0) {
                            send_packet(buf.data(), static_cast<size_t>(nwrite));
                            continue;
                        }
                        ngtcp2_conn_update_pkt_tx_time(conn, timestamp());
                        break;
                    }
                    fail(ngtcp2_strerror(static_cast<int>(nwrite)));
                    return;
                }
            }

            const ngtcp2_ssize nwrite =
                ngtcp2_conn_write_pkt(conn, &ps.path, &pi, buf.data(), buf.size(), timestamp());
            if (nwrite == NGTCP2_ERR_WRITE_MORE)
                continue;
            if (nwrite < 0) {
                fail(std::string("write_pkt: ") + ngtcp2_strerror(static_cast<int>(nwrite)));
                return;
            }
            if (nwrite == 0)
                break;
            send_packet(buf.data(), static_cast<size_t>(nwrite));
        }

        ngtcp2_conn_update_pkt_tx_time(conn, timestamp());
    }

    void handle_expiry()
    {
        if (!conn || closing)
            return;
        const auto now = timestamp();
        if (ngtcp2_conn_get_expiry(conn) > now)
            return;
        if (const int rv = ngtcp2_conn_handle_expiry(conn, now); rv != 0) {
            if (rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_CLOSING)
                fail(std::string("expiry: ") + ngtcp2_strerror(rv));
        }
    }

    void read_available()
    {
        socket.non_blocking(true);
        for (;;) {
            std::array<uint8_t, 65536> buf{};
            microserve::udp::endpoint src;
            microserve::error_code ec;
            const auto n = socket.receive_from(microserve::net::buffer(buf), src, 0, ec);
            if (ec || n == 0)
                break;
            const ngtcp2_path path = make_path();
            constexpr ngtcp2_pkt_info pi{};
            if (const int rv = ngtcp2_conn_read_pkt(conn, &path, &pi, buf.data(), n, timestamp());
                rv != 0 && rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_CLOSING) {
                fail(std::string("read_pkt: ") + ngtcp2_strerror(rv));
                return;
            }
        }
    }

    template <typename Pred>
    bool drive_until(Pred pred, const int timeout_ms)
    {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        handle_expiry();
        flush();
        while (!pred()) {
            if (!error.empty() || closing)
                return false;
            if (std::chrono::steady_clock::now() >= deadline)
                return false;
            read_available();
            handle_expiry();
            flush();
            if (pred())
                return true;
            microserve::test::sleep_ms(2);
        }
        return true;
    }

    /**
     * Drop queued UDP datagrams without feeding ngtcp2 (simulated loss).
     * @return Number of datagrams discarded.
     */
    size_t discard_available()
    {
        size_t dropped = 0;
        socket.non_blocking(true);
        for (;;) {
            std::array<uint8_t, 65536> buf{};
            microserve::udp::endpoint src;
            microserve::error_code ec;
            if (const auto n = socket.receive_from(
                microserve::net::buffer(buf), src, 0, ec); ec || n == 0) {
                break;
            }
            ++dropped;
        }
        return dropped;
    }

    /**
     * Discard datagrams until at least one is dropped or @p timeout_ms elapses.
     */
    size_t discard_until(const int timeout_ms)
    {
        size_t dropped = 0;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (dropped == 0 && std::chrono::steady_clock::now() < deadline) {
            dropped += discard_available();
            if (dropped == 0)
                microserve::test::sleep_ms(10);
        }
        return dropped;
    }

    bool submit_request(const std::string_view method, const std::string_view path,
                        const std::string_view payload = {},
                        const std::string_view extra_name = {},
                        const std::string_view extra_value = {})
    {
        if (!h3_ready)
            return false;

        status = 0;
        body.clear();
        headers.clear();
        response_complete = false;
        method_store.assign(method);
        path_store.assign(path.empty() ? "/" : path);
        extra_name_store.assign(extra_name);
        extra_value_store.assign(extra_value);
        req_body.assign(payload);
        req_body_off = 0;

        int64_t stream_id = -1;
        if (ngtcp2_conn_open_bidi_stream(conn, &stream_id, nullptr) != 0) {
            fail("open_bidi_stream failed");
            return false;
        }

        std::vector<nghttp3_nv> nva;
        auto add = [&](const char* n, const std::string& v) {
            nva.push_back(nghttp3_nv{
                .name = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(n)),
                .value = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(v.data())),
                .namelen = std::strlen(n),
                .valuelen = v.size(),
                .flags = NGHTTP3_NV_FLAG_NONE,
            });
        };
        static constexpr std::string scheme = "https";
        static constexpr std::string authority = "127.0.0.1";
        add(":method", method_store);
        add(":scheme", scheme);
        add(":authority", authority);
        add(":path", path_store);
        if (!extra_name_store.empty())
            add(extra_name_store.c_str(), extra_value_store);

        nghttp3_data_reader dr{};
        dr.read_data = body_read_cb;
        if (nghttp3_conn_submit_request(h3, stream_id, nva.data(), nva.size(),
                                        req_body.empty() ? nullptr : &dr, this) != 0) {
            fail("submit_request failed");
            return false;
        }
        return true;
    }

    bool request(const std::string_view method, const std::string_view path,
                 const std::string_view payload = {}, const std::string_view extra_name = {},
                 const std::string_view extra_value = {})
    {
        if (!submit_request(method, path, payload, extra_name, extra_value))
            return false;
        return drive_until([this] { return response_complete; }, kDriveTimeoutMs);
    }
};

} // namespace

TEST_CASE("Http3Impl throws when TLS files are missing", "[http3][tls]")
{
    microserve::test::ensure_logger();

    microserve::net::io_context ioc;
    REQUIRE_THROWS_AS(
        microserve::Http3Impl(ioc, "127.0.0.1", 0, "no-such-cert.pem", "no-such-key.pem", 0),
        std::runtime_error);
}

TEST_CASE("Http3Impl binds a UDP listener and stops cleanly", "[http3][lifecycle]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();

    microserve::net::io_context ioc;
    microserve::Http3Impl server(ioc, "127.0.0.1", 0, cert, key, 0);
    server.set_handler([](const auto&, auto& res) { res.body() = "ok"; });
    server.start_server();
    ioc.poll();
    server.stop_server();
    server.stop_server();
}

TEST_CASE("Http3Impl ignores malformed UDP datagrams", "[http3][packets]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_udp_port();

    microserve::net::io_context ioc;
    microserve::Http3Impl server(ioc, "127.0.0.1", port, cert, key, 0);
    server.set_handler([](const auto&, auto& res) { res.body() = "ok"; });
    server.start_server();

    microserve::test::run_with_server_ioc(ioc, [&] {
        microserve::net::io_context client_ioc;
        microserve::udp::socket client(client_ioc, microserve::udp::v4());
        const microserve::udp::endpoint dest(microserve::net::ip::make_address("127.0.0.1"), port);

        const std::vector<std::vector<std::uint8_t>> datagrams{
            {0x00},
            {0x01, 0x02, 0x03, 0x04},
            std::vector<std::uint8_t>(64, 0x00),
            std::vector<std::uint8_t>(1200, 0xaa),
        };
        for (const auto& datagram : datagrams)
            client.send_to(microserve::net::buffer(datagram), dest);

        microserve::test::sleep_ms(50);
        server.stop_server();
    });
}

TEST_CASE("Server::protocol_from_string recognizes HTTP/3 aliases", "[http3][server]")
{
    using P = microserve::Server::Protocol;
    REQUIRE(microserve::Server::protocol_from_string("http3") == P::Http3);
    REQUIRE(microserve::Server::protocol_from_string("h3") == P::Http3);
    REQUIRE(microserve::Server::protocol_from_string("quic") == P::Http3);
}

TEST_CASE("Http3Impl serves GET over HTTP/3", "[http3][get]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_udp_port();

    microserve::net::io_context ioc;
    microserve::Http3Impl server(ioc, "127.0.0.1", port, cert, key, 0);
    server.set_handler([](const auto& req, auto& res) {
        res.result(microserve::http::status::ok);
        res.body() = "h3:" + std::string(req.target());
        res.prepare_payload();
    });
    server.start_server();

    int status = 0;
    std::string body;
    std::string client_error;
    microserve::test::run_with_server_ioc(ioc, [&] {
        if (H3Client client; !client.connect_to(port)) {
            client_error = client.error.empty() ? "handshake timeout" : client.error;
        } else if (!client.request("GET", "/ping")) {
            client_error = client.error.empty() ? "request timeout" : client.error;
        } else {
            status = client.status;
            body = client.body;
        }
        server.stop_server();
    });

    INFO(client_error);
    REQUIRE(client_error.empty());
    REQUIRE(status == 200);
    REQUIRE(body == "h3:/ping");
}

TEST_CASE("Http3Impl serves POST body over HTTP/3", "[http3][post]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_udp_port();

    microserve::net::io_context ioc;
    microserve::Http3Impl server(ioc, "127.0.0.1", port, cert, key, 0);
    server.set_handler([](const auto& req, auto& res) {
        res.result(microserve::http::status::ok);
        res.body() = "echo:" + req.body();
        res.prepare_payload();
    });
    server.start_server();

    int status = 0;
    std::string body;
    std::string client_error;
    microserve::test::run_with_server_ioc(ioc, [&] {
        if (H3Client client; !client.connect_to(port)
            || !client.request("POST", "/echo", "hello-h3")) {
            client_error = client.error.empty() ? "timeout" : client.error;
        } else {
            status = client.status;
            body = client.body;
        }
        server.stop_server();
    });

    INFO(client_error);
    REQUIRE(client_error.empty());
    REQUIRE(status == 200);
    REQUIRE(body == "echo:hello-h3");
}

TEST_CASE("Http3Impl forwards headers and custom status", "[http3][headers]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_udp_port();

    microserve::net::io_context ioc;
    microserve::Http3Impl server(ioc, "127.0.0.1", port, cert, key, 0);
    server.set_handler([](const auto& req, auto& res) {
        if (req["x-test"] != "from-client") {
            res.result(microserve::http::status::bad_request);
            res.body() = "missing-header";
        } else {
            res.result(microserve::http::status::not_found);
            res.set("x-srv", "yes");
            res.body() = "nope";
        }
        res.prepare_payload();
    });
    server.start_server();

    int status = 0;
    std::string body;
    std::string srv_header;
    std::string client_error;
    microserve::test::run_with_server_ioc(ioc, [&] {
        if (H3Client client; !client.connect_to(port) ||
            !client.request("GET", "/missing", {}, "x-test", "from-client")) {
            client_error = client.error.empty() ? "timeout" : client.error;
        } else {
            status = client.status;
            body = client.body;
            if (const auto it = client.headers.find("x-srv"); it != client.headers.end())
                srv_header = it->second;
        }
        server.stop_server();
    });

    INFO(client_error);
    REQUIRE(client_error.empty());
    REQUIRE(status == 404);
    REQUIRE(body == "nope");
    REQUIRE(srv_header == "yes");
}

TEST_CASE("Http3Impl reuses a QUIC connection for a second GET", "[http3][keepalive]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_udp_port();

    microserve::net::io_context ioc;
    microserve::Http3Impl server(ioc, "127.0.0.1", port, cert, key, 0);
    server.set_handler([](const auto& req, auto& res) {
        res.body() = std::string(req.target());
        res.prepare_payload();
    });
    server.start_server();

    std::string first;
    std::string second;
    std::string client_error;
    microserve::test::run_with_server_ioc(ioc, [&] {
        if (H3Client client; !client.connect_to(port)
            || !client.request("GET", "/one")) {
            client_error = client.error.empty() ? "timeout" : client.error;
        } else {
            first = client.body;
            if (!client.request("GET", "/two"))
                client_error = client.error.empty() ? "second timeout" : client.error;
            else
                second = client.body;
        }
        server.stop_server();
    });

    INFO(client_error);
    REQUIRE(client_error.empty());
    REQUIRE(first == "/one");
    REQUIRE(second == "/two");
}

TEST_CASE("Server facade serves HTTP/3 GET", "[http3][server][get]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_udp_port();

    microserve::net::io_context ioc;
    microserve::Server server(ioc, "127.0.0.1", port, microserve::Server::Protocol::Http3, cert, key,
                              0);
    server.set_handler([](const auto&, auto& res) {
        res.body() = "via-h3";
        res.prepare_payload();
    });
    server.start();

    int status = 0;
    std::string body;
    std::string client_error;
    microserve::test::run_with_server_ioc(ioc, [&] {
        if (H3Client client; !client.connect_to(port)
            || !client.request("GET", "/")) {
            client_error = client.error.empty() ? "timeout" : client.error;
        } else {
            status = client.status;
            body = client.body;
        }
        server.stop();
    });

    INFO(client_error);
    REQUIRE(client_error.empty());
    REQUIRE(status == 200);
    REQUIRE(body == "via-h3");
}

TEST_CASE("Http3Impl retransmits handshake after lost packets (server PTO)", "[http3][timer][loss]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_udp_port();

    microserve::net::io_context ioc;
    microserve::Http3Impl server(ioc, "127.0.0.1", port, cert, key, 0);
    server.set_handler([](const auto&, auto& res) {
        res.body() = "recovered";
        res.prepare_payload();
    });
    server.start_server();

    int status = 0;
    std::string body;
    std::string client_error;
    microserve::test::run_with_server_ioc(ioc, [&] {
        H3Client client;
        if (!client.start(port)) {
            client_error = client.error.empty() ? "start failed" : client.error;
            server.stop_server();
            return;
        }

        // Drop the server's first flight. Do not flush or handle client
        // expiry: that would send another packet and let the server TX
        // from read_pkt instead of from its PTO timer.
        if (client.discard_until(kDriveTimeoutMs) == 0) {
            client_error = "no handshake datagrams to drop";
            server.stop_server();
            return;
        }

        microserve::test::sleep_ms(kPtoWaitMs);

        if (!client.drive_until([&] { return client.handshake_done && client.h3_ready; },
                                kLossDriveTimeoutMs)) {
            client_error = client.error.empty() ? "handshake timeout after loss" : client.error;
        } else if (!client.request("GET", "/recovered")) {
            client_error = client.error.empty() ? "request timeout" : client.error;
        } else {
            status = client.status;
            body = client.body;
        }
        server.stop_server();
    });

    INFO(client_error);
    REQUIRE(client_error.empty());
    REQUIRE(status == 200);
    REQUIRE(body == "recovered");
}

TEST_CASE("Http3Impl retransmits HTTP/3 response after lost packets (server PTO)",
          "[http3][timer][loss]")
{
    microserve::test::ensure_logger();
    const auto [cert, key] = microserve::test::require_tls_files();
    const auto port = microserve::test::ephemeral_udp_port();

    microserve::net::io_context ioc;
    microserve::Http3Impl server(ioc, "127.0.0.1", port, cert, key, 0);
    server.set_handler([](const auto&, auto& res) {
        res.result(microserve::http::status::ok);
        res.body() = "lost-then-acked";
        res.prepare_payload();
    });
    server.start_server();

    int status = 0;
    std::string body;
    std::string client_error;
    microserve::test::run_with_server_ioc(ioc, [&] {
        H3Client client;
        if (!client.connect_to(port) || !client.submit_request("GET", "/payload")) {
            client_error = client.error.empty() ? "setup timeout" : client.error;
            server.stop_server();
            return;
        }

        client.flush();
        if (client.discard_until(kDriveTimeoutMs) == 0) {
            client_error = "no response datagrams to drop";
            server.stop_server();
            return;
        }

        microserve::test::sleep_ms(kPtoWaitMs);

        if (!client.drive_until([&] { return client.response_complete; },
                                kLossDriveTimeoutMs)) {
            client_error = client.error.empty() ? "response timeout after loss" : client.error;
        } else {
            status = client.status;
            body = client.body;
        }
        server.stop_server();
    });

    INFO(client_error);
    REQUIRE(client_error.empty());
    REQUIRE(status == 200);
    REQUIRE(body == "lost-then-acked");
}
