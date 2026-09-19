// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/ssl.h>

#include <array>
#include <chrono>
#include <format>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <utility>

#include "http3_interface.hpp"

// Prefer ossl, then quictls, then legacy openssl backend.
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
#else
#  error "No ngtcp2 OpenSSL crypto backend header found (ossl/quictls/openssl)"
#endif

module microserve.http3:quic;

import microserve.core;
import microserve.logging;

namespace microserve::http3_detail {

    constexpr size_t kCidLen = 8;
    constexpr size_t kMaxUdpPayload = 1350;
    constexpr size_t kUdpBufSize = 65536;

    struct QuicConnection;

    /**
     * Non-owning back-refs to the UDP listener. Replaces Http3Impl* so this
     * partition does not need the complete listener type.
     */
    struct ConnOwner {
        udp::socket* socket{nullptr};
        udp::endpoint* local_ep{nullptr};
        SSL_CTX* ssl_ctx{nullptr};
        int verbosity{0};
        bool* stopped{nullptr};
        std::map<std::string, std::shared_ptr<QuicConnection>>* connections{nullptr};
        std::function<std::unique_ptr<QuicApp>(QuicConnection&)> make_app;
    };

    /**
     * @brief One QUIC connection (ngtcp2 + TLS). HTTP/3 lives in @c app.
     *
     * Owned via shared_ptr so async timer waits and the CID map can share it.
     * Destroy order: app (H3) → conn → crypto/ssl.
     */
    struct QuicConnection : std::enable_shared_from_this<QuicConnection>, QuicTransport {
        ConnOwner owner{};
        ngtcp2_conn* conn{nullptr};
        SSL* ssl{nullptr};
#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL)
        ngtcp2_crypto_ossl_ctx* ossl_ctx{nullptr};
#endif
        ngtcp2_crypto_conn_ref conn_ref{};
        ngtcp2_cid scid{};
        udp::endpoint path_remote{};
        net::steady_timer timer;
        bool handshake_confirmed{false};
        bool closing{false};
        std::unique_ptr<QuicApp> app;

        explicit QuicConnection(ConnOwner own, const net::any_io_executor& ex)
            : owner(std::move(own)), timer(ex) {
            conn_ref.get_conn = &QuicConnection::get_conn;
            conn_ref.user_data = this;
        }

        ~QuicConnection() override;

        static ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref) {
            return static_cast<QuicConnection*>(ref->user_data)->conn;
        }

        bool stopped() const {
            return owner.stopped && *owner.stopped;
        }

        int verbosity() const override { return owner.verbosity; }

        void log_msg(const int level, const char* msg) override {
            if (!msg) {
                return;
            }
            if (level <= 0) {
                log_error(msg);
            } else if (level == 1) {
                log_info(msg);
            } else {
                log_debug(msg);
            }
        }

        int open_uni_stream(int64_t& stream_id) override {
            if (!conn) {
                return -1;
            }
            return ngtcp2_conn_open_uni_stream(conn, &stream_id, nullptr) == 0 ? 0 : -1;
        }

        void extend_max_stream_offset(const int64_t stream_id, const uint64_t n) override {
            if (conn && n > 0) {
                ngtcp2_conn_extend_max_stream_offset(conn, stream_id, n);
            }
        }

        void extend_max_offset(const uint64_t n) override {
            if (conn && n > 0) {
                ngtcp2_conn_extend_max_offset(conn, n);
            }
        }

        /**
         * @brief Arm the ngtcp2 expiry timer (loss probe, ACK delay, idle timeout).
         */
        void schedule_timer();
    };

    using Connection = QuicConnection;

    static std::array<uint8_t, kCidLen> random_cid() {
        std::array<uint8_t, kCidLen> cid{};
        thread_local std::mt19937_64 rng{std::random_device{}()};
        for (auto& b : cid) {
            b = static_cast<uint8_t>(rng());
        }
        return cid;
    }

    static ngtcp2_cid make_cid(const uint8_t* data, const size_t len) {
        ngtcp2_cid cid{};
        ngtcp2_cid_init(&cid, data, len);
        return cid;
    }

    /** Wire ngtcp2_crypto AEAD / HP / key-update hooks into @p cb. */
    static void fill_crypto_callbacks(ngtcp2_callbacks& cb) {
        cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        cb.encrypt = ngtcp2_crypto_encrypt_cb;
        cb.decrypt = ngtcp2_crypto_decrypt_cb;
        cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
        cb.update_key = ngtcp2_crypto_update_key_cb;
        cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        cb.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
        cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    }

    static int configure_server_ssl_ctx(SSL_CTX* ctx) {
#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL)
        (void)ctx; // ossl: session setup is sufficient
        return 0;
#elif defined(MICROSERVE_NGTCP2_CRYPTO_QUICTLS)
        return ngtcp2_crypto_quictls_configure_server_context(ctx);
#elif defined(MICROSERVE_NGTCP2_CRYPTO_OPENSSL)
        return ngtcp2_crypto_openssl_configure_server_context(ctx);
#else
        (void)ctx;
        return -1;
#endif
    }

    static int configure_server_ssl_session(SSL* ssl) {
#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL)
        return ngtcp2_crypto_ossl_configure_server_session(ssl);
#elif defined(MICROSERVE_NGTCP2_CRYPTO_QUICTLS)
        return ngtcp2_crypto_quictls_configure_server_session(ssl);
#elif defined(MICROSERVE_NGTCP2_CRYPTO_OPENSSL)
        return ngtcp2_crypto_openssl_configure_server_session(ssl);
#else
        (void)ssl;
        return -1;
#endif
    }

    /** ALPN select: require "h3". */
    static int alpn_select_cb(SSL*, const unsigned char** out, unsigned char* out_len,
                              const unsigned char* in, const unsigned int in_len, void*) {
        for (unsigned int i = 0; i < in_len;) {
            const unsigned int len = in[i];

            if (len == 0 || i + 1 + len > in_len) {
                break;
            }

            if (const unsigned char* proto = in + i + 1; len == 2 && proto[0] == 'h' && proto[1] == '3') {
                *out = proto;
                *out_len = static_cast<unsigned char>(len);
                return SSL_TLSEXT_ERR_OK;
            }

            i += 1 + len;
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    static std::string cid_key(const ngtcp2_cid& cid) {
        return {reinterpret_cast<const char*>(cid.data), cid.datalen};
    }

    static ngtcp2_tstamp timestamp() {
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        return static_cast<ngtcp2_tstamp>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
    }

    static void remove_connection(const std::shared_ptr<QuicConnection>& c);
    static void close_connection(const std::shared_ptr<QuicConnection>& c, uint64_t);
    static void flush_connection(const std::shared_ptr<QuicConnection>& c);
    static bool setup_conn_tls(QuicConnection& c);
    static std::shared_ptr<QuicConnection> create_connection(ConnOwner owner, const ngtcp2_pkt_hd& hd,
                                                             const udp::endpoint& remote);
    static SSL_CTX* create_ssl_ctx(const std::string& cert_file, const std::string& key_file);
    static void free_ssl_ctx(SSL_CTX*& ctx);

    void handle_packet(const ConnOwner& owner, const uint8_t* data, size_t n,
                       const udp::endpoint& remote);

    static void send_packet(QuicConnection& c, const udp::endpoint& ep,
                            const uint8_t* data, const size_t len) {
        if (!c.owner.socket) {
            return;
        }
        error_code ec;
        c.owner.socket->send_to(net::buffer(data, len), ep, 0, ec);
    }

    QuicConnection::~QuicConnection() {
        app.reset();
        if (conn) {
            ngtcp2_conn_del(conn);
            conn = nullptr;
        }
#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL)
        if (ossl_ctx) {
            ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
            ossl_ctx = nullptr;
        }
#endif
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
    }

    void QuicConnection::schedule_timer() {
        if (!conn || closing || stopped()) {
            return;
        }

        const ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn);
        if (expiry == UINT64_MAX) {
            timer.cancel();
            return;
        }

        const ngtcp2_tstamp now = timestamp();
        timer.expires_after(expiry > now
            ? std::chrono::nanoseconds(expiry - now)
            : std::chrono::nanoseconds{0});

        timer.async_wait([self = shared_from_this()](const error_code& ec) {
            if (ec || !self->conn || self->closing || self->stopped()) {
                return;
            }
            if (const int rv = ngtcp2_conn_handle_expiry(self->conn, timestamp()); rv != 0) {
                if (self->verbosity() >= 2) {
                    log_debug(std::format("[{:<11}] ngtcp2_conn_handle_expiry: {}",
                                          "http3", ngtcp2_strerror(rv)));
                }
                close_connection(self, NGTCP2_NO_ERROR);
                return;
            }
            flush_connection(self);
        });
    }

    static int app_fail(const int rv) {
        return rv == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
    }

    // =========================================================================
    // ngtcp2 application callbacks (user_data = QuicConnection*)
    // =========================================================================

    static int cb_handshake_completed(ngtcp2_conn*, void* user_data) {
        auto* c = static_cast<QuicConnection*>(user_data);
        c->handshake_confirmed = true;
        if (c->verbosity() >= 2) {
            log_info(std::format("[{:<11}] QUIC/TLS handshake completed", "http3"));
        }
        // No flush here — still inside read_pkt.
        if (!c->app)
            return NGTCP2_ERR_CALLBACK_FAILURE;
        return app_fail(c->app->on_handshake_completed());
    }

    /**
     * Deliver STREAM payload to the app (HTTP/3), which may buffer until ready.
     * Flow control is extended only after the app reports consumed bytes.
     */
    static int cb_recv_stream_data(ngtcp2_conn* conn, const uint32_t flags, const int64_t stream_id,
                                   uint64_t, const uint8_t* data, const size_t data_len,
                                   void* user_data, void*) {
        const auto* c = static_cast<QuicConnection*>(user_data);
        const int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
        if (!c->app)
            return 0;

        size_t consumed = 0;
        if (c->app->on_recv_stream_data(stream_id, data, data_len, fin, consumed) != 0)
            return NGTCP2_ERR_CALLBACK_FAILURE;

        if (consumed > 0) {
            ngtcp2_conn_extend_max_stream_offset(conn, stream_id, consumed);
            ngtcp2_conn_extend_max_offset(conn, consumed);
        }
        return 0;
    }

    static int cb_stream_open(ngtcp2_conn*, const int64_t stream_id, void* user_data) {
        // Only client bidi streams carry requests.
        if (!ngtcp2_is_bidi_stream(stream_id))
            return 0;
        const auto* c = static_cast<QuicConnection*>(user_data);
        if (!c->app)
            return 0;
        return app_fail(c->app->on_stream_open(stream_id));
    }

    static int cb_stream_close(ngtcp2_conn*, const uint32_t flags, const int64_t stream_id,
                               const uint64_t app_error_code, void* user_data, void*) {
        const auto* c = static_cast<QuicConnection*>(user_data);
        if (!c->app)
            return 0;
        const bool app_error_set = (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0;
        return app_fail(c->app->on_stream_close(stream_id, app_error_code, app_error_set,
                                                ngtcp2_is_bidi_stream(stream_id) != 0));
    }

    static int cb_acked_stream_data_offset(ngtcp2_conn*, const int64_t stream_id, uint64_t,
                                           const uint64_t data_len, void* user_data, void*) {
        const auto* c = static_cast<QuicConnection*>(user_data);
        if (!c->app)
            return 0;
        return app_fail(c->app->on_acked_stream_data(stream_id, data_len));
    }

    static int cb_extend_max_remote_streams_bidi(ngtcp2_conn*, const uint64_t max_streams,
                                                 void* user_data) {
        if (const auto* c = static_cast<QuicConnection*>(user_data); c->app)
            c->app->on_extend_max_remote_streams_bidi(max_streams);
        return 0;
    }

    static int cb_extend_max_local_streams_bidi(ngtcp2_conn*, uint64_t, void*) {
        return 0;
    }

    static int cb_extend_max_stream_data(ngtcp2_conn*, const int64_t stream_id, uint64_t,
                                         void* user_data, void*) {
        const auto* c = static_cast<QuicConnection*>(user_data);
        if (!c->app)
            return 0;
        return app_fail(c->app->on_extend_max_stream_data(stream_id));
    }

    static void cb_rand(uint8_t* dest, const size_t dest_len, const ngtcp2_rand_ctx*) {
        thread_local std::mt19937_64 rng{std::random_device{}()};
        for (size_t i = 0; i < dest_len; ++i)
            dest[i] = static_cast<uint8_t>(rng());
    }

    static int cb_get_new_connection_id(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token,
                                        size_t cid_len, void* user_data) {
        auto* c = static_cast<QuicConnection*>(user_data);
        const auto bytes = random_cid();
        if (cid_len > bytes.size())
            cid_len = bytes.size();
        ngtcp2_cid_init(cid, bytes.data(), cid_len);

        thread_local std::mt19937_64 rng{std::random_device{}()};
        for (size_t i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i)
            token[i] = static_cast<uint8_t>(rng());

        // Index the new SCID so later packets still find this connection.
        if (c && c->owner.connections)
            (*c->owner.connections)[cid_key(*cid)] = c->shared_from_this();
        return 0;
    }

    static int cb_remove_connection_id(ngtcp2_conn*, const ngtcp2_cid* cid, void* user_data) {
        if (const auto* c = static_cast<QuicConnection*>(user_data); c && c->owner.connections && cid) {
            const auto key = cid_key(*cid);
            if (const auto it = c->owner.connections->find(key);
                it != c->owner.connections->end() && it->second.get() == c) {
                c->owner.connections->erase(it);
            }
        }
        return 0;
    }

    static int cb_stream_reset(ngtcp2_conn*, const int64_t stream_id, uint64_t, uint64_t,
                               void* user_data, void*) {
        if (const auto* c = static_cast<QuicConnection*>(user_data); c->app) {
            c->app->on_stream_reset(stream_id);
        }
        return 0;
    }

    static int cb_path_validation(ngtcp2_conn*, uint32_t, const ngtcp2_path*,
                                  const ngtcp2_path*, ngtcp2_path_validation_result, void*) {
        return 0;
    }

    // =====================================================================
    // Connection lifecycle + TX
    // =====================================================================

    void close_connection(const std::shared_ptr<QuicConnection>& c, uint64_t) {
        if (!c || c->closing) {
            return;
        }
        c->closing = true;
        c->timer.cancel();
        remove_connection(c);
    }

    /** Drop all CID map entries for @p c and cancel its timer. */
    void remove_connection(const std::shared_ptr<QuicConnection>& c) {
        if (!c) {
            return;
        }
        c->closing = true;
        c->timer.cancel();
        if (!c->owner.connections) {
            return;
        }
        for (auto it = c->owner.connections->begin(); it != c->owner.connections->end();) {
            if (it->second == c) {
                it = c->owner.connections->erase(it);
            } else {
                ++it;
            }
        }
    }

    /**
     * Drain application STREAM writes, then pure QUIC packets (ACK/crypto).
     *
     * Coupling rules:
     * - NGTCP2_ERR_WRITE_MORE / successful write: add_write_offset only if ndatalen > 0
     * - DATA_BLOCKED → block_stream; SHUT_WR → shutdown_stream_write
     * - Never shutdown_stream_write just because fin && no body (header-only OK)
     * - nwrite == 0 → update_pkt_tx_time and stop (pacing/congestion)
     */
    void flush_connection(const std::shared_ptr<QuicConnection>& c) {
        if (!c || !c->conn || c->stopped() || c->closing) {
            return;
        }

        if (!c->owner.local_ep) {
            return;
        }

        std::array<uint8_t, kMaxUdpPayload> buf{};
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ps.path.local.addr = const_cast<sockaddr*>(c->owner.local_ep->data());
        ps.path.local.addrlen = static_cast<ngtcp2_socklen>(c->owner.local_ep->size());
        ps.path.remote.addr = const_cast<sockaddr*>(c->path_remote.data());
        ps.path.remote.addrlen = static_cast<ngtcp2_socklen>(c->path_remote.size());

        ngtcp2_pkt_info pi{};

        for (;;) {
            if (c->app) {
                QuicVec vec[16];
                int64_t stream_id = -1;
                int fin = 0;

                const int ssize = c->app->poll_stream_write(stream_id, fin, vec, 16);
                if (ssize < 0) {
                    close_connection(c, NGTCP2_NO_ERROR);
                    return;
                }

                if (ssize > 0 || (stream_id >= 0 && fin)) {
                    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
                    if (fin) {
                        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                    }

                    ngtcp2_vec data[16];
                    size_t data_cnt = 0;
                    for (int i = 0; i < ssize; ++i) {
                        if (!vec[i].base || vec[i].len == 0) {
                            continue;
                        }
                        data[data_cnt].base = vec[i].base;
                        data[data_cnt].len = vec[i].len;
                        ++data_cnt;
                    }

                    ngtcp2_ssize data_len = -1;
                    const ngtcp2_ssize write_ssize = ngtcp2_conn_writev_stream(
                        c->conn, &ps.path, &pi, buf.data(), buf.size(), &data_len, flags,
                        stream_id, data_cnt ? data : nullptr, data_cnt, timestamp());

                    if (write_ssize < 0) {
                        if (write_ssize == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
                            write_ssize == NGTCP2_ERR_STREAM_SHUT_WR) {
                            if (write_ssize == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                                c->app->block_stream(stream_id);
                            } else {
                                c->app->shutdown_stream_write(stream_id);
                            }
                            continue;
                        }

                        if (write_ssize == NGTCP2_ERR_WRITE_MORE) {
                            if (data_len > 0) {
                                if (c->app->add_write_offset(stream_id,
                                                             static_cast<size_t>(data_len)) != 0) {
                                    close_connection(c, NGTCP2_NO_ERROR);
                                    return;
                                }
                            }
                            continue;
                        }

                        if (write_ssize != NGTCP2_ERR_WRITE_MORE) {
                            log_error(std::format(
                                "[{:<11}] ngtcp2_conn_writev_stream: {}",
                                "http3", ngtcp2_strerror(static_cast<int>(write_ssize))));
                            close_connection(c, NGTCP2_NO_ERROR);
                            return;
                        }
                    }

                    // nwrite >= 0
                    if (data_len > 0) {
                        if (c->app->add_write_offset(stream_id, static_cast<size_t>(data_len)) != 0) {
                            close_connection(c, NGTCP2_NO_ERROR);
                            return;
                        }
                    }

                    if (write_ssize > 0) {
                        send_packet(*c, c->path_remote, buf.data(), static_cast<size_t>(write_ssize));
                        continue;
                    }

                    // Congestion / pacing.
                    ngtcp2_conn_update_pkt_tx_time(c->conn, timestamp());
                    break;
                }
            }

            // Non-stream packets (ACK, CRYPTO, etc.).
            const ngtcp2_ssize num_write =
                ngtcp2_conn_write_pkt(c->conn, &ps.path, &pi, buf.data(), buf.size(), timestamp());
            if (num_write < 0) {
                if (num_write == NGTCP2_ERR_WRITE_MORE) {
                    continue;
                }
                if (c->verbosity() >= 2) {
                    log_debug(std::format("[{:<11}] ngtcp2_conn_write_pkt: {}", "http3",
                                          ngtcp2_strerror(static_cast<int>(num_write))));
                }
                break;
            }
            if (num_write == 0) {
                break;
            }
            send_packet(*c, c->path_remote, buf.data(), static_cast<size_t>(num_write));
        }

        c->schedule_timer();
    }

    /** Per-connection SSL + ngtcp2_crypto native handle. */
    bool setup_conn_tls(QuicConnection& c) {
        if (!c.owner.ssl_ctx) {
            return false;
        }
        c.ssl = SSL_new(c.owner.ssl_ctx);
        if (!c.ssl) {
            return false;
        }

        SSL_set_accept_state(c.ssl);
        SSL_set_app_data(c.ssl, &c.conn_ref);

#if defined(MICROSERVE_NGTCP2_CRYPTO_OSSL)
        if (ngtcp2_crypto_ossl_ctx_new(&c.ossl_ctx, c.ssl) != 0) {
            return false;
        }
        ngtcp2_crypto_ossl_ctx_set_ssl(c.ossl_ctx, c.ssl);
        if (ngtcp2_crypto_ossl_configure_server_session(c.ssl) != 0) {
            return false;
        }
        ngtcp2_conn_set_tls_native_handle(c.conn, c.ossl_ctx);
#else
        if (configure_server_ssl_session(c.ssl) != 0) {
            return false;
        }
        ngtcp2_conn_set_tls_native_handle(c.conn, c.ssl);
#endif
        return true;
    }

    /**
     * Accept a Client Initial: allocate SCID, transport params, TLS, map entry.
     * @param owner listener back-refs
     * @param hd decoded packet header from ngtcp2_accept
     * @param remote
     */
    std::shared_ptr<QuicConnection> create_connection(ConnOwner owner,
        const ngtcp2_pkt_hd& hd, const udp::endpoint& remote) {

        if (!owner.socket || !owner.local_ep || !owner.connections) {
            return nullptr;
        }

        auto c = std::make_shared<QuicConnection>(owner, owner.socket->get_executor());
        c->path_remote = remote;

        const auto scid_bytes = random_cid();
        const ngtcp2_cid scid = make_cid(scid_bytes.data(), scid_bytes.size());
        c->scid = scid;

        const ngtcp2_cid dcid = hd.scid;
        const ngtcp2_cid ocid = hd.dcid;

        ngtcp2_callbacks callbacks{};
        fill_crypto_callbacks(callbacks);
        callbacks.handshake_completed = cb_handshake_completed;
        callbacks.recv_stream_data = cb_recv_stream_data;
        callbacks.stream_open = cb_stream_open;
        callbacks.stream_close = cb_stream_close;
        callbacks.acked_stream_data_offset = cb_acked_stream_data_offset;
        callbacks.extend_max_local_streams_bidi = cb_extend_max_local_streams_bidi;
        callbacks.extend_max_remote_streams_bidi = cb_extend_max_remote_streams_bidi;
        callbacks.extend_max_stream_data = cb_extend_max_stream_data;
        callbacks.rand = cb_rand;
        callbacks.get_new_connection_id = cb_get_new_connection_id;
        callbacks.remove_connection_id = cb_remove_connection_id;
        callbacks.stream_reset = cb_stream_reset;
        callbacks.path_validation = cb_path_validation;

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = timestamp();

        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 32; // Chrome opens several uni streams
        params.initial_max_data = 1 * 1024 * 1024;
        params.initial_max_stream_data_bidi_local = 512 * 1024;
        params.initial_max_stream_data_bidi_remote = 512 * 1024;
        params.initial_max_stream_data_uni = 512 * 1024;
        params.max_idle_timeout = 30 * NGTCP2_SECONDS;
        params.original_dcid = ocid;
        params.original_dcid_present = 1;
        params.active_connection_id_limit = 8;

        ngtcp2_path path{};
        path.local.addr = const_cast<sockaddr*>(owner.local_ep->data());
        path.local.addrlen = static_cast<ngtcp2_socklen>(owner.local_ep->size());
        path.remote.addr = const_cast<sockaddr*>(remote.data());
        path.remote.addrlen = static_cast<ngtcp2_socklen>(remote.size());

        if (const int rv = ngtcp2_conn_server_new(&c->conn, &dcid, &scid, &path, hd.version,
                                                  &callbacks, &settings, &params, nullptr,
                                                  c.get()); rv != 0) {
            log_error(std::format("[{:<11}] ngtcp2_conn_server_new failed: {}", "http3", rv));
            return nullptr;
        }

        if (!setup_conn_tls(*c)) {
            log_error(std::format("[{:<11}] TLS setup failed for new connection", "http3"));
            return nullptr;
        }

        if (!owner.make_app) {
            log_error(std::format("[{:<11}] missing QUIC application factory", "http3"));
            return nullptr;
        }

        c->app = owner.make_app(*c);
        if (!c->app) {
            log_error(std::format("[{:<11}] failed to create HTTP/3 session", "http3"));
            return nullptr;
        }

        (*owner.connections)[cid_key(scid)] = c;
        c->schedule_timer();
        return c;
    }

    /**
     * Demux by DCID → existing conn, or ngtcp2_accept → new conn.
     * On success: read_pkt then flush_connection.
     */
    void handle_packet(const ConnOwner& owner, const uint8_t* data, const size_t n,
                       const udp::endpoint& remote) {
        if (!owner.local_ep || !owner.connections) {
            return;
        }

        ngtcp2_version_cid vc{};
        if (ngtcp2_pkt_decode_version_cid(&vc, data, n, kCidLen) < 0) {
            return;
        }

        std::shared_ptr<QuicConnection> c;
        if (vc.dcid && vc.dcidlen) {
            const auto key = std::string(reinterpret_cast<const char*>(vc.dcid), vc.dcidlen);
            if (const auto it = owner.connections->find(key); it != owner.connections->end())
                c = it->second;
        }

        if (!c) {
            ngtcp2_pkt_hd hd{};
            if (ngtcp2_accept(&hd, data, n) != 0)
                return; // not a usable Client Initial
            c = create_connection(owner, hd, remote);
            if (!c)
                return;
        }

        if (c->closing)
            return;

        ngtcp2_path path{};
        path.local.addr = owner.local_ep->data();
        path.local.addrlen = static_cast<ngtcp2_socklen>(owner.local_ep->size());
        path.remote.addr = const_cast<sockaddr*>(remote.data());
        path.remote.addrlen = static_cast<ngtcp2_socklen>(remote.size());

        constexpr ngtcp2_pkt_info pi{};
        if (const int rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, data, n, timestamp()); rv != 0) {
            if (owner.verbosity >= 2) {
                log_debug(std::format("[{:<11}] ngtcp2_conn_read_pkt: {}", "http3",
                                      ngtcp2_strerror(rv)));
            }

            if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
                c->closing = true;
                return;
            }
            // We do not mint Retry tokens.
            if (rv == NGTCP2_ERR_RETRY) {
                remove_connection(c);
                return;
            }
            close_connection(c, NGTCP2_NO_ERROR);
            return;
        }

        c->path_remote = remote;
        flush_connection(c);
    }

    SSL_CTX* create_ssl_ctx(const std::string& cert_file, const std::string& key_file) {
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (!ssl_ctx) {
            return nullptr;
        }

        // QUIC mandates TLS 1.3 only.
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

        if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file.c_str()) != 1) {
            log_error(std::format("[{:<11}] failed to load certificate: {}",
                                  "http3", cert_file));
            SSL_CTX_free(ssl_ctx);
            return nullptr;
        }

        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            log_error(std::format("[{:<11}] failed to load private key: {}",
                                  "http3", key_file));
            SSL_CTX_free(ssl_ctx);
            return nullptr;
        }

        if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
            log_error(std::format("[{:<11}] certificate/private key mismatch", "http3"));
            SSL_CTX_free(ssl_ctx);
            return nullptr;
        }

        if (configure_server_ssl_ctx(ssl_ctx) != 0) {
            log_error(std::format(
                "[{:<11}] ngtcp2 crypto configure_server_context failed", "http3"));
            SSL_CTX_free(ssl_ctx);
            return nullptr;
        }

        SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_cb, nullptr);
        return ssl_ctx;
    }

    void free_ssl_ctx(SSL_CTX*& ctx) {
        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
    }

    /** Owns the process-wide (per-listener) SSL_CTX so the primary never names OpenSSL. */
    struct ServerTls {
        SSL_CTX* ctx{nullptr};
        ServerTls() = default;
        explicit ServerTls(SSL_CTX* c) : ctx(c) {}
        ~ServerTls() { free_ssl_ctx(ctx); }
        ServerTls(const ServerTls&) = delete;
        ServerTls& operator=(const ServerTls&) = delete;
    };

    std::unique_ptr<ServerTls> make_server_tls(const std::string& cert_file,
                                               const std::string& key_file) {
        SSL_CTX* ctx = create_ssl_ctx(cert_file, key_file);
        if ( ! ctx) {
            return nullptr;
        }
        return std::make_unique<ServerTls>(ctx);
    }

} // namespace microserve::http3_detail
