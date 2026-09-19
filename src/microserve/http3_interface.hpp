// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <cstddef>
#include <cstdint>

namespace microserve::http3_detail {

    /**
     * @brief STREAM byte view; layout matches `ngtcp2_vec` / `nghttp3_vec`.
     */
    struct QuicVec {
        uint8_t* base{nullptr};  ///< Pointer to the first byte.
        size_t len{0};           ///< Length in bytes.
    };

    /**
     * @brief QUIC operations the HTTP/3 session may call.
     *
     * Lives in a GMF header so `:conn` never imports `:quic` (GCC modules).
     */
    struct QuicTransport {
        virtual ~QuicTransport() = default;
        virtual int open_uni_stream(int64_t& stream_id) = 0;
        virtual void extend_max_stream_offset(int64_t stream_id, uint64_t n) = 0;
        virtual void extend_max_offset(uint64_t n) = 0;
        virtual int verbosity() const = 0;

        /**
         * @brief Emit a log line at @p level.
         *
         * @param level `0` = error, `1` = info, `2` = debug.
         * @param msg   NUL-terminated message.
         */
        virtual void log_msg(int level, const char* msg) = 0;
    };

    /**
     * @brief Application sitting on a QUIC connection (HTTP/3 session).
     *
     * Implemented by the HTTP/3 session; invoked from QUIC callbacks.
     * Return values of `0` mean success; negative values are nghttp3/ngtcp2 errors.
     */
    struct QuicApp {
        virtual ~QuicApp() = default;

        virtual int on_handshake_completed() = 0;
        virtual int on_recv_stream_data(int64_t stream_id, const uint8_t* data, size_t data_len,
                                        int fin, size_t& consumed) = 0;
        virtual int on_stream_open(int64_t stream_id) = 0;
        virtual int on_stream_close(int64_t stream_id, uint64_t app_error_code, bool app_error_set,
                                    bool bidi) = 0;
        virtual int on_acked_stream_data(int64_t stream_id, uint64_t data_len) = 0;
        virtual void on_extend_max_remote_streams_bidi(uint64_t max_streams) = 0;
        virtual int on_extend_max_stream_data(int64_t stream_id) = 0;
        virtual void on_stream_reset(int64_t stream_id) = 0;
        virtual int poll_stream_write(int64_t& stream_id, int& fin, QuicVec* vecs,
                                      size_t size) = 0;
        virtual int add_write_offset(int64_t stream_id, size_t n) = 0;
        virtual void block_stream(int64_t stream_id) = 0;
        virtual void shutdown_stream_write(int64_t stream_id) = 0;
    };

} // namespace microserve::http3_detail
