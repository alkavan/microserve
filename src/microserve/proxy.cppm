// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <nghttp2/nghttp2.h>

export module microserve.proxy;

import microserve.core;
import microserve.config;
import microserve.logging;

export namespace microserve {

    /**
     * @brief Parsed `proxy_pass` value (nginx-compatible).
     *
     * `has_uri` is true when the directive includes a URI after host[:port]
     * (including a lone `/`). Then the location prefix is replaced by `uri`.
     * Otherwise the original request target is forwarded unchanged.
     */
    struct ProxyTarget {
        std::string scheme = "http";  ///< `http`, `https`, or `h2c`.
        std::string host;             ///< Upstream hostname or IP.
        unsigned short port = 80;     ///< Upstream port (scheme default if omitted).
        std::string uri;              ///< Replacement URI when @c has_uri is true.
        bool has_uri = false;         ///< True if `proxy_pass` included a URI path.
        std::string backend_name;     ///< Named backend when using the `backend:` form.
    };

    /**
     * @brief Parse a `proxy_pass` directive into scheme, host, port, and URI.
     *
     * Accepts `http://`, `https://`, `h2c://`, and `backend:` forms.
     * A URI after the host (including `/`) sets @c has_uri so the location
     * prefix is rewritten.
     *
     * @param proxy_pass Raw `proxy_pass` string from configuration.
     * @return Parsed target; empty or default fields if the value is invalid.
     */
    ProxyTarget parse_proxy_pass(std::string_view proxy_pass);

    /**
     * @brief Rewrite the request target for the upstream.
     *
     * When the target has no URI, the original path and query are forwarded.
     * Otherwise the matched location prefix is replaced by @p target.uri.
     *
     * @param location       Matched location path prefix.
     * @param request_target Original request target (path and query).
     * @param target         Parsed `proxy_pass` value.
     * @return Upstream request target including query string.
     */
    std::string rewrite_proxy_target(std::string_view location,
                                     std::string_view request_target,
                                     const ProxyTarget& target);

    /**
     * @brief Resolve the upstream host and port for a parsed target.
     *
     * Named `backend:` targets use the first server of the matching backend.
     * Direct host targets copy @p target.host and @p target.port.
     *
     * @param target     Parsed `proxy_pass` value.
     * @param backends   Configured named backends.
     * @param[out] host  Resolved upstream host.
     * @param[out] port  Resolved upstream port.
     * @return true if host and port were resolved.
     */
    bool resolve_proxy_upstream(const ProxyTarget& target,
                                const std::vector<BackendConfig>& backends,
                                std::string& host,
                                unsigned short& port);

    /**
     * @brief Reverse-proxy an HTTP request to an upstream.
     *
     * Forwards over HTTP/1.1, or h2c when the scheme is `h2c` or HTTP/1.1
     * fails with a connection error. Hop-by-hop headers are stripped.
     * Writes 502/504 into @p res on failure.
     *
     * @param req            Incoming client request.
     * @param res            Response filled from the upstream (or an error).
     * @param location_path  Matched location prefix used for URI rewrite.
     * @param proxy_pass     Raw `proxy_pass` directive.
     * @param backends       Named backends for `backend:` targets.
     * @param timeouts       Connect/read/write timeouts.
     */
    void proxy_request(const Request& req, Response& res,
                       std::string_view location_path,
                       std::string_view proxy_pass,
                       const std::vector<BackendConfig>& backends,
                       const Config::TimeoutConfig& timeouts);

} // namespace microserve

namespace {

    /**
     * @brief Trim leading and trailing ASCII whitespace.
     */
    std::string trim_sv(const std::string_view s) {
        const auto first = s.find_first_not_of(" \t");
        if (first == std::string_view::npos)
            return {};
        const auto last = s.find_last_not_of(" \t");
        return std::string{s.substr(first, last - first + 1)};
    }

    /**
     * @brief Return a lowercase copy of @p s.
     */
    std::string ascii_lower_sv(const std::string_view s) {
        std::string out{s};
        for (char& c : out)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return out;
    }

    /**
     * @brief Whether @p name is a hop-by-hop header that must not be forwarded.
     */
    bool hop_by_hop(const std::string_view name) {
        return name == "connection"
            || name == "keep-alive"
            || name == "proxy-connection"
            || name == "transfer-encoding"
            || name == "upgrade"
            || name == "te"
            || name == "trailer"
            || name == "proxy-authenticate"
            || name == "proxy-authorization"
            || name == "http2-settings";
    }

    /**
     * @brief Write a gateway error status and plain-text body into @p res.
     */
    void fail_gateway(microserve::Response& res, const microserve::http::status st,
                      const std::string_view body) {
        res.result(st);
        res.set(microserve::http::field::content_type, "text/plain");
        res.set(microserve::http::field::server, "microserve/1.0");
        res.body() = std::string{body};
        res.prepare_payload();
    }

    /**
     * @brief Parse `host`, `host:port`, or `[ipv6]:port` into @p host and @p port.
     *
     * @param spec          Host (and optional port) string.
     * @param[out] host     Parsed hostname or IP.
     * @param[out] port     Parsed port, or @p default_port if omitted.
     * @param default_port  Port used when @p spec has none.
     * @return true if a non-empty host was parsed.
     */
    bool parse_host_port(const std::string_view spec, std::string& host, unsigned short& port,
                         const unsigned short default_port) {
        const auto s = trim_sv(spec);

        if (s.empty()) {
            return false;
        }

        if (s.front() == '[') {
            const auto rb = s.find(']');
            if (rb == std::string::npos)
                return false;
            host = std::string{s.substr(1, rb - 1)};
            if (rb + 1 < s.size() && s[rb + 1] == ':') {
                const int p = std::stoi(std::string{s.substr(rb + 2)});
                if (p < 1 || p > 65535)
                    return false;
                port = static_cast<unsigned short>(p);
            } else {
                port = default_port;
            }
            return !host.empty();
        }

        if (const auto colon = s.rfind(':');
            colon != std::string::npos && s.find(':') == colon) {
            host = std::string{s.substr(0, colon)};
            const int p = std::stoi(std::string{s.substr(colon + 1)});
            if (p < 1 || p > 65535)
                return false;
            port = static_cast<unsigned short>(p);
            return !host.empty();
        }
        host = s;
        port = default_port;
        return !host.empty();
    }

        /**
         * @brief nghttp2 client session state for one h2c upstream request.
         */
        struct H2Client {
            nghttp2_session* session = nullptr;  ///< Client session, or null when closed.
            int status = 0;                      ///< Upstream `:status`, or 0 if none.
            std::string body;                    ///< Accumulated response body.
            std::vector<std::pair<std::string, std::string>> headers;  ///< Non-pseudo response headers.
            std::string request_body;            ///< Client body to send upstream.
            size_t body_off = 0;                 ///< Bytes of @c request_body already sent.
            bool done = false;                   ///< True after the stream closes.
            int32_t stream_id = -1;              ///< Submitted stream id.
        };

        /**
         * @brief nghttp2 DATA source callback; copies the request body.
         */
        ssize_t h2_data_read(nghttp2_session*, int32_t, uint8_t* buf, const size_t length,
                             uint32_t* data_flags, nghttp2_data_source* source, void*) {
            auto* st = static_cast<H2Client*>(source->ptr);

            if (st->body_off >= st->request_body.size()) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                return 0;
            }

            const size_t n = std::min(length, st->request_body.size() - st->body_off);
            std::memcpy(buf, st->request_body.data() + st->body_off, n);
            st->body_off += n;

            if (st->body_off >= st->request_body.size()) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            }

            return static_cast<ssize_t>(n);
        }

        /**
         * @brief nghttp2 header callback; records `:status` and response headers.
         */
        int h2_on_header(nghttp2_session*, const nghttp2_frame*,
                         const uint8_t* name, const size_t name_len,
                         const uint8_t* value, const size_t value_len,
                         uint8_t, void* user) {
            auto* st = static_cast<H2Client*>(user);
            const std::string_view n(reinterpret_cast<const char*>(name), name_len);
            const std::string_view v(reinterpret_cast<const char*>(value), value_len);

            if (n == ":status") {
                st->status = std::stoi(std::string{v});
                return 0;
            }

            if (!n.empty() && n.front() != ':') {
                st->headers.emplace_back(std::string{n}, std::string{v});
            }

            return 0;
        }

        /**
         * @brief nghttp2 DATA callback; appends response body bytes.
         */
        int h2_on_data(nghttp2_session*, uint8_t, int32_t, const uint8_t* data,
                       const size_t len, void* user) {
            auto* st = static_cast<H2Client*>(user);
            st->body.append(reinterpret_cast<const char*>(data), len);
            return 0;
        }

        /**
         * @brief nghttp2 stream-close callback; marks the request complete.
         */
        int h2_on_stream_close(nghttp2_session*, int32_t, uint32_t, void* user) {
            static_cast<H2Client*>(user)->done = true;
            return 0;
        }

        /**
         * @brief Proxy @p req to @p host:@p port over cleartext HTTP/2.
         *
         * @param req              Incoming client request.
         * @param res              Response filled from the upstream.
         * @param host             Upstream host.
         * @param port             Upstream port.
         * @param upstream_target  Rewritten request target.
         * @param timeouts         Connect/read/write timeouts.
         * @return true if a complete upstream response was written to @p res.
         */
        bool proxy_h2c(const microserve::Request& req, microserve::Response& res,
                       const std::string& host, unsigned short port,
                       const std::string& upstream_target,
                       const microserve::Config::TimeoutConfig& timeouts) {
            microserve::net::io_context ioc;
            microserve::tcp::resolver resolver(ioc);
            const auto results = resolver.resolve(host, std::to_string(port));
            microserve::beast::tcp_stream stream(ioc);
            stream.expires_after(timeouts.connect);
            stream.connect(results);

            H2Client st;
            st.request_body = req.body();

            nghttp2_session_callbacks* cbs = nullptr;
            nghttp2_session_callbacks_new(&cbs);
            nghttp2_session_callbacks_set_on_header_callback(cbs, h2_on_header);
            nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, h2_on_data);
            nghttp2_session_callbacks_set_on_stream_close_callback(cbs, h2_on_stream_close);
            nghttp2_session_client_new(&st.session, cbs, &st);
            nghttp2_session_callbacks_del(cbs);

            constexpr nghttp2_settings_entry iv[] = {
                {.settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = 100}
            };
            nghttp2_submit_settings(st.session, NGHTTP2_FLAG_NONE, iv, 1);

            std::vector<std::string> storage;
            auto add_nv = [&](std::string_view n, std::string_view v) {
                storage.emplace_back(n);
                storage.emplace_back(v);
            };

            const auto method = std::string(req.method_string());
            add_nv(":method", method);
            add_nv(":path", upstream_target.empty() ? "/" : upstream_target);
            add_nv(":scheme", "http");
            const auto authority = (port == 80) ? host : host + ":" + std::to_string(port);
            add_nv(":authority", authority);

            for (const auto& f : req) {
                std::string name(f.name_string());
                std::ranges::transform(name, name.begin(), [](const unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (name.empty() || name[0] == ':' || hop_by_hop(name) || name == "host")
                    continue;
                add_nv(name, std::string(f.value()));
            }

            std::vector<nghttp2_nv> nva;
            nva.reserve(storage.size() / 2);
            for (size_t i = 0; i + 1 < storage.size(); i += 2) {
                nva.push_back(nghttp2_nv{
                    .name = reinterpret_cast<uint8_t*>(storage[i].data()),
                    .value = reinterpret_cast<uint8_t*>(storage[i + 1].data()),
                    .namelen = storage[i].size(),
                    .valuelen = storage[i + 1].size(),
                    .flags = NGHTTP2_NV_FLAG_NONE
                });
            }

            nghttp2_data_provider prov{};
            const nghttp2_data_provider* prov_ptr = nullptr;
            if (!st.request_body.empty() && req.method() != microserve::http::verb::head
                && req.method() != microserve::http::verb::get) {
                prov.source.ptr = &st;
                prov.read_callback = h2_data_read;
                prov_ptr = &prov;
            }

            st.stream_id = nghttp2_submit_request(st.session, nullptr, nva.data(), nva.size(),
                                                  prov_ptr, &st);
            if (st.stream_id < 0) {
                nghttp2_session_del(st.session);
                return false;
            }

            std::array<uint8_t, 16 * 1024> rbuf{};
            while (!st.done) {
                for (;;) {
                    const uint8_t* data = nullptr;
                    const ssize_t len = nghttp2_session_mem_send(st.session, &data);
                    if (len < 0) {
                        nghttp2_session_del(st.session);
                        return false;
                    }
                    if (len == 0)
                        break;
                    stream.expires_after(timeouts.write);
                    microserve::net::write(stream, microserve::net::buffer(data, static_cast<size_t>(len)));
                }
                if (st.done)
                    break;
                if (!nghttp2_session_want_read(st.session) && !nghttp2_session_want_write(st.session))
                    break;
                stream.expires_after(timeouts.read);
                const auto n = stream.read_some(microserve::net::buffer(rbuf));
                size_t off = 0;
                while (off < n) {
                    const ssize_t rv = nghttp2_session_mem_recv(st.session, rbuf.data() + off, n - off);
                    if (rv < 0) {
                        nghttp2_session_del(st.session);
                        return false;
                    }
                    if (rv == 0)
                        break;
                    off += static_cast<size_t>(rv);
                }
            }

            nghttp2_session_del(st.session);
            st.session = nullptr;

            if (st.status == 0)
                return false;

            res.result(static_cast<microserve::http::status>(st.status));
            res.version(req.version());
            for (const auto& [n, v] : st.headers) {
                if (hop_by_hop(n))
                    continue;
                res.set(n, v);
            }
            res.body() = std::move(st.body);
            res.prepare_payload();

            microserve::error_code ec;
            stream.socket().shutdown(microserve::tcp::socket::shutdown_both, ec);
            return true;
        }

        /**
         * @brief Whether @p ex looks like a dropped HTTP/1.1 connection (retry as h2c).
         */
        bool connection_failed(const std::exception& ex) {
            const auto msg = ascii_lower_sv(ex.what());
            return msg.find("end of stream") != std::string::npos
                || msg.find("connection reset") != std::string::npos
                || msg.find("broken pipe") != std::string::npos
                || msg.find("not connected") != std::string::npos
                || msg.find("eof") != std::string::npos
                || msg.find("partial message") != std::string::npos;
        }

} // namespace

export namespace microserve {

    ProxyTarget parse_proxy_pass(std::string_view proxy_pass) {
        ProxyTarget out;
        auto p = trim_sv(proxy_pass);
        if (p.empty())
            return out;

        if (p.starts_with("backend:")) {
            auto name = p.substr(8);
            if (name.starts_with("//"))
                name.erase(0, 2);
            if (const auto slash = name.find('/'); slash != std::string::npos) {
                std::string uri;
                uri = name.substr(slash);
                name.resize(slash);
                out.has_uri = true;
                out.uri = uri.empty() ? "/" : uri;
            }
            out.backend_name = trim_sv(name);
            out.scheme = "http";
            out.port = 80;
            return out;
        }

        std::string scheme = "http";
        std::string rest = p;
        if (const auto sep = p.find("://"); sep != std::string::npos) {
            scheme = ascii_lower_sv(p.substr(0, sep));
            rest = p.substr(sep + 3);
        }

        out.scheme = scheme;
        if (scheme != "http" && scheme != "https" && scheme != "h2c")
            return out;
        const unsigned short def_port = (scheme == "https") ? 443 : 80;

        if (const auto at = rest.find('@'); at != std::string::npos)
            rest.erase(0, at + 1);

        std::string hostport;
        std::string uri;
        if (!rest.empty() && rest.front() == '[') {
            const auto rb = rest.find(']');
            if (rb == std::string::npos)
                return out;
            hostport = rest.substr(0, rb + 1);
            if (auto tail = rest.substr(rb + 1);
                !tail.empty() && tail.front() == ':') {
                if (const auto slash = tail.find('/'); slash == std::string::npos) {
                    hostport += tail;
                } else {
                    hostport += tail.substr(0, slash);
                    uri = tail.substr(slash);
                }
            } else if (!tail.empty() && tail.front() == '/') {
                uri = tail;
            }
        } else {
            if (const auto slash = rest.find('/');
                slash == std::string::npos) {
                hostport = rest;
            } else {
                hostport = rest.substr(0, slash);
                uri = rest.substr(slash);
            }
        }

        if (!uri.empty()) {
            out.has_uri = true;
            out.uri = uri;
        }

        parse_host_port(hostport, out.host, out.port, def_port);
        return out;
    }

    std::string rewrite_proxy_target(const std::string_view location,
                                     const std::string_view request_target,
                                     const ProxyTarget& target) {
        std::string path{request_target};
        std::string query;
        if (const auto q = path.find('?'); q != std::string::npos) {
            query = path.substr(q);
            path.resize(q);
        }

        if (!target.has_uri) {
            if (path.empty())
                path = "/";
            return path + query;
        }

        std::string loc{location};
        if (loc.empty()) {
            loc = "/";
        }

        std::string remainder;
        if (path.starts_with(loc)) {
            remainder = path.substr(loc.size());
        } else {
            remainder = path;
        }

        std::string uri = target.uri.empty() ? "/" : target.uri;
        std::string uri_query;
        if (const auto q = uri.find('?'); q != std::string::npos) {
            uri_query = uri.substr(q);
            uri.resize(q);
        }

        if (!uri.empty() && uri.back() == '/' && !remainder.empty() && remainder.front() == '/') {
            remainder.erase(remainder.begin());
        } else if (!uri.empty() && uri.back() != '/'
            && !remainder.empty() && remainder.front() != '/') {
            uri.push_back('/');
        }

        auto out = uri + remainder;
        if (out.empty()) {
            out = "/";
        }
        if (!uri_query.empty()) {
            return out + uri_query;
        }

        return out + query;
    }

    bool resolve_proxy_upstream(const ProxyTarget& target,
                                const std::vector<BackendConfig>& backends,
                                std::string& host,
                                unsigned short& port) {
        if (!target.backend_name.empty()) {
            for (const auto& [_name, _servers] : backends) {
                if (_name != target.backend_name) {
                    continue;
                }

                if (_servers.empty()) {
                    return false;
                }

                return parse_host_port(_servers.front(), host, port, 80);
            }
            return false;
        }
        if (target.host.empty()) {
            return false;
        }
        host = target.host;
        port = target.port;
        return true;
    }

    void proxy_request(const Request& req, Response& res,
                       std::string_view location_path,
                       std::string_view proxy_pass,
                       const std::vector<BackendConfig>& backends,
                       const Config::TimeoutConfig& timeouts) {
        const auto parsed = parse_proxy_pass(proxy_pass);
        if (parsed.scheme != "http" && parsed.scheme != "h2c") {
            log_warn(std::format("[{:<11}] proxy_pass '{}' scheme not supported",
                                 "proxy", std::string{proxy_pass}));
            fail_gateway(res, http::status::bad_gateway, "502 Bad Gateway");
            return;
        }

        auto target = parsed;
        if (target.host.empty() && target.backend_name.empty()) {
            if (const auto named = proxy_pass_backend_name(proxy_pass, backends)) {
                target.backend_name = *named;
            }
        }

        std::string host;
        unsigned short port = 80;
        if ( ! resolve_proxy_upstream(target, backends, host, port)) {
            log_warn(std::format("[{:<11}] cannot resolve proxy_pass '{}'",
                                 "proxy", std::string{proxy_pass}));
            fail_gateway(res, http::status::bad_gateway, "502 Bad Gateway");
            return;
        }

        const auto upstream_target = rewrite_proxy_target(
            location_path, std::string(req.target()), target);

        if (target.scheme == "h2c") {
            try {
                if ( ! proxy_h2c(req, res, host, port, upstream_target, timeouts)) {
                    fail_gateway(res, http::status::bad_gateway, "502 Bad Gateway");
                }
            } catch (const std::exception& ex) {
                log_warn(std::format("[{:<11}] h2c {} -> {}:{}{} : {}",
                                     "proxy", std::string{req.target()}, host, port,
                                     upstream_target, ex.what()));
                fail_gateway(res, http::status::bad_gateway, "502 Bad Gateway");
            }
            return;
        }

        try {
            net::io_context ioc;
            tcp::resolver resolver(ioc);
            const auto results = resolver.resolve(host, std::to_string(port));

            beast::tcp_stream stream(ioc);
            stream.expires_after(timeouts.connect);
            stream.connect(results);

            http::request<http::string_body> out_req;
            out_req.method(req.method());
            out_req.target(upstream_target);
            out_req.version(11);
            out_req.body() = req.body();

            for (const auto& f : req) {
                std::string name(f.name_string());
                std::ranges::transform(name, name.begin(), [](const unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (name.empty() || name[0] == ':' || hop_by_hop(name) || name == "host") {
                    continue;
                }
                out_req.set(name, f.value());
            }

            const auto host_hdr = (port == 80)
                ? host
                : host + ":" + std::to_string(port);
            out_req.set(http::field::host, host_hdr);
            out_req.set(http::field::connection, "close");
            out_req.prepare_payload();

            stream.expires_after(timeouts.write);
            http::write(stream, out_req);

            flat_buffer buffer;
            http::response<http::string_body> in_res;
            stream.expires_after(timeouts.read);
            http::read(stream, buffer, in_res);

            res.result(in_res.result());
            res.version(req.version());
            for (const auto& f : in_res) {
                std::string name(f.name_string());
                std::ranges::transform(name, name.begin(), [](const unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (hop_by_hop(name))
                    continue;
                res.set(name, f.value());
            }
            res.body() = std::move(in_res.body());
            res.prepare_payload();

            error_code ec;
            stream.socket().shutdown(tcp::socket::shutdown_both, ec);
        } catch (const std::exception& ex) {
            if (connection_failed(ex)) {
                try {
                    if (proxy_h2c(req, res, host, port, upstream_target, timeouts)) {
                        return;
                    }
                } catch (const std::exception& h2ex) {
                    log_warn(std::format("[{:<11}] h2c retry {} -> {}:{}{} : {}",
                                         "proxy", std::string{req.target()}, host, port,
                                         upstream_target, h2ex.what()));
                }
            }
            log_warn(std::format("[{:<11}] {} -> {}:{}{} : {}",
                                 "proxy", std::string{req.target()}, host, port,
                                 upstream_target, ex.what()));
            const auto msg = std::string{ex.what()};
            const bool timeout = msg.find("timed out") != std::string::npos
                || msg.find("Timeout") != std::string::npos;
            fail_gateway(res,
                         timeout ? http::status::gateway_timeout
                                 : http::status::bad_gateway,
                         timeout ? "504 Gateway Timeout" : "502 Bad Gateway");
        }
    }

} // namespace microserve
