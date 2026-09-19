// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

// #define BOOST_ASIO_SEPARATE_COMPILATION
// #define BOOST_BEAST_SEPARATE_COMPILATION

#include <utility> // do not remove this! (for compatibility)
#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <filesystem>
#include <functional>
#include <string>
#include <openssl/ssl.h>

export module microserve.core;

namespace error {
    using ::boost::asio::error::operation_aborted;
    using ::boost::asio::error::eof;
    using ::boost::asio::error::not_connected;
    using ::boost::asio::error::not_found;
    using ::boost::asio::error::make_error_code;  // basic_errors + misc_errors + …
}

// Common OpenSSL (ALPN / TLS helpers used by http2/http3)
export using ::SSL_CTX_set_alpn_select_cb;
export using ::SSL;
export using ::SSL_CTX;

// ---------------------------------------------------------------------------
// Public surface of the core module
// ---------------------------------------------------------------------------
export namespace microserve {

    /* Module importers do not see names from #include headers or from a plain
       `using namespace` inside this module. Only entities that are exported
       (or reached via exported using-declarations) are reachable after
       `import`. Re-export each third-party name the public API needs under
       stable microserve::* aliases so consumers never depend on boost::
       qualified lookup. */

    // ---- Asio surface ----
    namespace net {
        using ::boost::asio::socket_base;
        using ::boost::asio::steady_timer;
        using ::boost::asio::buffer;
        using ::boost::asio::buffer_copy;
        using ::boost::asio::write;
        using ::boost::asio::async_write;
        using ::boost::asio::io_context;
        using ::boost::asio::post;
        using ::boost::asio::any_io_executor;
        using ::boost::asio::make_strand;
        using ::boost::asio::signal_set;

        namespace ip {
            using ::boost::asio::ip::v6_only;
            using ::boost::asio::ip::make_address;
            using ::boost::asio::ip::tcp;
            using ::boost::asio::ip::udp;
        }

        namespace error {
            using ::boost::asio::error::operation_aborted;
            using ::boost::asio::error::eof;
            using ::boost::asio::error::not_connected;
        }

        namespace ssl {
            using ::boost::asio::ssl::context;
            using ::boost::asio::ssl::stream;
            using ::boost::asio::ssl::stream_base;
            namespace error {
                using ::boost::asio::ssl::error::stream_truncated;
                using ::boost::asio::ssl::error::make_error_code;  // ADL needs this across import
            }
        }
    }

    // ---- Beast surface ----
    namespace beast {
        using ::boost::beast::flat_buffer;
        using ::boost::beast::get_lowest_layer;
        using ::boost::beast::tcp_stream;
    }

    // ---- HTTP surface (separate from net::async_write) ----
    namespace http {
        using ::boost::beast::http::async_read;
        using ::boost::beast::http::async_write;
        using ::boost::beast::http::read;
        using ::boost::beast::http::write;
        using ::boost::beast::http::string_to_verb;
        using ::boost::beast::http::field;
        using ::boost::beast::http::status;
        using ::boost::beast::http::request;
        using ::boost::beast::http::response;
        using ::boost::beast::http::string_body;
        using ::boost::beast::http::verb;
    }

    namespace fs {
        using ::std::filesystem::path;
        using ::std::filesystem::exists;
        using ::std::filesystem::is_regular_file;
    }

    using tcp = net::ip::tcp;
    using udp = net::ip::udp;
    using error_code = boost::system::error_code;

    using Request  = http::request<http::string_body>;
    using Response = http::response<http::string_body>;
    using Handler  = std::function<void(const Request &, Response &)>;

    using steady_timer   = net::steady_timer;
    using flat_buffer    = beast::flat_buffer;
    using ssl_stream_tcp = net::ssl::stream<tcp::socket>;

    /**
     * Abstract server backend. Free (non-nested) so http2/http3 modules can
     * define concrete implementations without importing microserve.server
     * (avoids a circular module dependency).
     */
    struct ServerImpl {
        virtual ~ServerImpl() = default;
        virtual void set_handler(Handler handler) = 0;
        virtual void start_server() = 0;
        virtual void stop_server() = 0;
    };

    inline bool is_ssl_stream_truncated(const error_code& ec) {
        return ec == boost::asio::ssl::error::stream_truncated;
    }
} // namespace microserve
