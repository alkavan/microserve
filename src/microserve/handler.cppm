// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <openssl/sha.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

export module microserve.handler;

import microserve.core;
import microserve.config;
import microserve.memory;
import microserve.proxy;

export namespace microserve {

    /**
     * @brief Decode a Base64 string.
     * @param input Base64-encoded text.
     * @return The decoded bytes as a string.
     */
    inline std::string base64_decode(const std::string_view input) {
        static constexpr unsigned char invalid = 0xff;
        static constexpr unsigned char table[256] = {
            invalid, invalid, invalid, invalid, invalid, invalid, invalid, invalid,
            invalid, invalid, invalid, invalid, invalid, invalid, invalid, invalid,
            invalid, invalid, invalid, invalid, invalid, invalid, invalid, invalid,
            invalid, invalid, invalid, invalid, invalid, invalid, invalid, invalid,
            invalid, invalid, invalid, invalid, invalid, invalid, invalid, invalid,
            invalid, invalid, invalid, 62, invalid, invalid, invalid, 63,
            52, 53, 54, 55, 56, 57, 58, 59,
            60, 61, invalid, invalid, invalid, 64, invalid, invalid,
            invalid, 0, 1, 2, 3, 4, 5, 6,
            7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, invalid, invalid, invalid, invalid, invalid,
            invalid, 26, 27, 28, 29, 30, 31, 32,
            33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51, invalid, invalid, invalid, invalid, invalid
        };

        std::string out;
        int val = 0;
        int valb = -8;
        for (const unsigned char c : input) {
            if (c >= 128)
                break;
            const unsigned char d = table[c];
            if (d == invalid)
                break;
            if (d == 64)
                break; // '=' padding
            val = (val << 6) + d;
            valb += 6;
            if (valb >= 0) {
                out.push_back(static_cast<char>((val >> valb) & 0xff));
                valb -= 8;
            }
        }
        return out;
    }

    /**
     * @brief Encode bytes as a Base64 string.
     * @param data Bytes to encode.
     * @param len Number of bytes in @p data.
     * @return The Base64-encoded text.
     */
    inline std::string base64_encode(const unsigned char* data, const size_t len) {
        static constexpr char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::string out;
        out.reserve(((len + 2) / 3) * 4);

        for (size_t i = 0; i < len; i += 3) {
            const uint32_t b0 = data[i];
            const uint32_t b1 = (i + 1 < len) ? data[i + 1] : 0;
            const uint32_t b2 = (i + 2 < len) ? data[i + 2] : 0;
            const uint32_t v = (b0 << 16) | (b1 << 8) | b2;

            out.push_back(alphabet[(v >> 18) & 0x3f]);
            out.push_back(alphabet[(v >> 12) & 0x3f]);
            out.push_back((i + 1 < len) ? alphabet[(v >> 6) & 0x3f] : '=');
            out.push_back((i + 2 < len) ? alphabet[v & 0x3f] : '=');
        }

        return out;
    }

    /**
     * @brief Whether HTTP Basic authentication is enabled for this auth setting.
     * @param auth Auth mode from the location (`basic` is case-insensitive).
     * @return true if @p auth selects HTTP Basic authentication.
     */
    inline bool is_basic_auth_enabled(const std::string_view auth) {
        return auth == "basic" || auth == "Basic" || auth == "BASIC";
    }

    /**
     * @brief Compare two strings in constant time.
     * @param a First string.
     * @param b Second string.
     * @return true if @p a and @p b are the same length and equal.
     */
    inline bool constant_time_equals(const std::string_view a, const std::string_view b) {
        if (a.size() != b.size())
            return false;
        unsigned char diff = 0;
        for (size_t i = 0; i < a.size(); ++i)
            diff |= static_cast<unsigned char>(a[i] ^ b[i]);
        return diff == 0;
    }

    /**
     * @brief Encode a value in the Apache APR1 hash alphabet.
     * @param value Bits to encode.
     * @param count Number of alphabet characters to emit.
     * @return The encoded text.
     */
    inline std::string apr1_to64(uint32_t value, int count) {
        static constexpr char alphabet[] =
            "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string out;
        while (count-- > 0) {
            out.push_back(alphabet[value & 0x3f]);
            value >>= 6;
        }
        return out;
    }

    /**
     * @brief SHA-512 hash of a password, Base64-encoded.
     * @param password Password bytes to hash.
     * @return Base64 encoding of the SHA-512 digest.
     */
    inline std::string sha512_base64(const std::string_view password) {
        std::array<unsigned char, SHA512_DIGEST_LENGTH> digest{};
        SHA512(reinterpret_cast<const unsigned char*>(password.data()),
               password.size(),
               digest.data());
        return base64_encode(digest.data(), digest.size());
    }

    /**
     * @brief Verify a password against a single htpasswd hash entry.
     * @param password Password supplied by the client.
     * @param stored_hash Hash field from the htpasswd line.
     * @return true if @p password matches @p stored_hash.
     */
    inline bool verify_htpasswd_entry(const std::string_view password,
                                      std::string_view stored_hash) {
        static constexpr std::string_view sha512_prefix = "{SHA512}";
        static constexpr std::string_view plain_prefix = "{PLAIN}";

        if (stored_hash.starts_with(sha512_prefix)) {
            stored_hash.remove_prefix(sha512_prefix.size());
            return constant_time_equals(sha512_base64(password), stored_hash);
        }

        // Development/tests only. Do not use in production configs.
        if (stored_hash.starts_with(plain_prefix)) {
            stored_hash.remove_prefix(plain_prefix.size());
            return constant_time_equals(password, stored_hash);
        }

        return false;
    }

    /**
     * @brief Verify credentials against an htpasswd file.
     * @param path Path to the htpasswd file.
     * @param user Username to look up.
     * @param password Password supplied by the client.
     * @return true if @p user is present and @p password matches its hash.
     */
    inline bool verify_htpasswd_file(const std::string& path,
                                     const std::string_view user,
                                     const std::string_view password) {
        std::ifstream in(path);
        if (!in)
            return false;

        std::string line;
        while (std::getline(in, line)) {
            if (line.empty() || line.front() == '#')
                continue;

            const auto colon = line.find(':');
            if (colon == std::string::npos)
                continue;

            const auto file_user = std::string_view(line).substr(0, colon);
            const auto hash = std::string_view(line).substr(colon + 1);

            if (file_user == user)
                return verify_htpasswd_entry(password, hash);
        }

        return false;
    }

    /**
     * @brief Determines the MIME type of the file based on the file extension.
     *
     * Extracts the file extension from the provided path and returns the
     * corresponding MIME type. Unrecognised extensions fall back to "text/plain".
     *
     * @param path File path whose extension is inspected.
     * @return MIME type string; `"text/plain"` if the extension is unknown.
     */
    inline std::string get_mime_type(const std::string& path) {
        const auto ext = fs::path(path).extension().string();

        if (ext == ".html") return "text/html";
        if (ext == ".css")  return "text/css";
        if (ext == ".js")   return "application/javascript";
        if (ext == ".json") return "application/json";
        if (ext == ".png")  return "image/png";
        if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
        if (ext == ".gif")  return "image/gif";
        if (ext == ".svg")  return "image/svg+xml";
        if (ext == ".ico")  return "image/x-icon";

        return "text/plain";
    }

    /**
     * @brief Fill a successful static-file response.
     * @param file_path Path used only to choose the Content-Type.
     * @param content Response body; moved into @p res.
     * @param res Response to populate.
     */
    inline void set_file_ok(const std::string& file_path, std::string content, Response& res) {
        res.set(http::field::content_type, get_mime_type(file_path));
        res.set(http::field::server, "microserve/1.0");
        res.result(http::status::ok);
        res.body() = std::move(content);
        res.prepare_payload();
    }

    /**
     * @brief Read an entire file as bytes.
     * @param file_path Path of the file to open.
     * @return File contents, or `std::nullopt` if the file cannot be opened.
     */
    inline std::optional<std::string> read_file_bytes(const std::string& file_path) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file)
            return std::nullopt;
        return std::string(std::istreambuf_iterator<char>(file),
                           std::istreambuf_iterator<char>());
    }

    /**
     * @brief Read a regular file and prepare an HTTP 200 response.
     * @param file_path Path of the file to serve.
     * @param res Response to populate on success.
     * @return true on success; false if the path is missing, not a regular
     *         file, or cannot be read.
     */
    inline bool serve_file(const std::string& file_path, Response& res) {
        if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
            return false;
        }

        auto content = read_file_bytes(file_path);
        if (!content)
            return false;

        set_file_ok(file_path, std::move(*content), res);
        return true;
    }

    /**
     * @brief Serves static files and reverse-proxies configured locations.
     *
     * Static bytes are cached only after @ref enable_cache. The pool starts
     * empty and is filled when a file is requested. A stored file is reused
     * until its size or last-write time changes.
     */
    class FileHandler {
    private:
        /**
         * @brief Per-location routing and authentication settings.
         */
        struct Route {
            std::string root;
            std::string proxy_pass;
            std::string auth;
            std::string auth_user;
            std::string auth_password;
            std::string auth_file;
            std::string auth_realm = "microserve";
        };

        /**
         * @brief On-demand static-file pool and its path index.
         *
         * Index pins keep hot files resident. Oldest pins are released when a
         * new file needs room, so the simple strategy can evict those slots.
         */
        struct CacheState {
            /**
             * @brief One cached file: identity used for invalidation, plus its pin.
             */
            struct Entry {
                std::string path;
                std::filesystem::file_time_type mtime{};
                std::uint64_t size = 0;
                cache::Allocation body;
            };

            std::unique_ptr<cache::Cache> pool;
            std::list<Entry> lru; // front is oldest
            std::unordered_map<std::string, std::list<Entry>::iterator> index;
            std::mutex mu;
        };

        std::map<std::string, Route> routes_;
        std::string alt_svc_;
        std::vector<BackendConfig> backends_;
        Config::TimeoutConfig timeouts_{};
        std::shared_ptr<CacheState> cache_;

        /**
         * @brief Copy a cache slot into a response body string.
         * @param slot Pinned cache allocation. An empty slot yields an empty string.
         * @return Bytes currently stored in @p slot.
         */
        [[nodiscard]] static std::string body_from(const cache::Allocation& slot) {
            if (!slot || slot.size() == 0)
                return {};
            return {reinterpret_cast<const char*>(slot.data()), slot.size()};
        }

        static void forget_cached(CacheState& state, const std::string& path);
        [[nodiscard]] static cache::Allocation find_cached(
            CacheState& state,
            const std::string& path,
            std::filesystem::file_time_type mtime,
            std::uint64_t size);
        static void store_cached(CacheState& state,
                          const std::string& path,
                          std::filesystem::file_time_type mtime,
                          std::uint64_t size,
                          std::span<const std::byte> bytes);
        [[nodiscard]] static cache::Allocation insert_cached(CacheState& state,
                                                      std::span<const std::byte> bytes);
        static bool serve_cached(CacheState& state, const std::string& file_path, Response& res);
        bool serve_static(const std::string& file_path, Response& res) const;
        /**
         * @brief Write a 401 Unauthorized response.
         * @param res Response to populate.
         * @param realm Basic-auth realm advertised in WWW-Authenticate.
         */
        static void unauthorized(Response& res, const std::string& realm) {
            res.result(http::status::unauthorized);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::server, "microserve/1.0");
            res.set("WWW-Authenticate", "Basic realm=\"" + realm + R"(", charset="UTF-8")");
            res.body() = "401 Unauthorized";
            res.prepare_payload();
        }

        /**
         * @brief Validate Basic credentials for a route when authentication is enabled.
         * @param req Request whose Authorization header is checked.
         * @param route Location auth settings. Non-basic auth always allows the request.
         * @return true if the request is allowed.
         */
        static bool authorized_basic(const Request& req, const Route& route) {
            if (!is_basic_auth_enabled(route.auth))
                return true;

            const auto it = req.find(http::field::authorization);
            if (it == req.end())
                return false;

            std::string_view value = it->value();
            constexpr std::string_view prefix = "Basic ";
            if (value.size() <= prefix.size() ||
                value.substr(0, prefix.size()) != prefix) {
                return false;
            }

            value.remove_prefix(prefix.size());
            const auto decoded = base64_decode(value);

            const auto colon = decoded.find(':');
            if (colon == std::string::npos)
                return false;

            const auto user = std::string_view(decoded).substr(0, colon);
            const auto password = std::string_view(decoded).substr(colon + 1);

            if (!route.auth_file.empty())
                return verify_htpasswd_file(route.auth_file, user, password);

            if (route.auth_user.empty() || route.auth_password.empty())
                return false;

            const auto expected = route.auth_user + ":" + route.auth_password;
            return constant_time_equals(decoded, expected);
        }

    public:
        /**
         * @brief Set the Alt-Svc header value applied to responses.
         * @param v Header value; empty disables the header.
         */
        void set_alt_svc(std::string v) { alt_svc_ = std::move(v); }

        /**
         * @brief Set upstream backends used for proxy locations.
         * @param backends Named upstream pools referenced by `proxy_pass`.
         */
        void set_backends(std::vector<BackendConfig> backends) {
            backends_ = std::move(backends);
        }

        /**
         * @brief Set proxy timeout configuration.
         * @param timeouts Connect, read, and write timeouts for upstreams.
         */
        void set_timeouts(const Config::TimeoutConfig& timeouts) {
            timeouts_ = timeouts;
        }

        /**
         * @brief Map a URL path prefix to a local directory.
         * @param route URL prefix, including the leading slash.
         * @param directory Filesystem root for files under @p route.
         */
        void add_location(const std::string& route, const std::string& directory) {
            routes_[route].root = directory;
        }

        /**
         * @brief Register a location from server configuration.
         * @param loc Path, root, proxy target, and auth settings to copy.
         */
        void add_location(const Config::ServerConfig::Location& loc) {
            std::string route = loc.path.empty() ? "/" : loc.path;
            if (!route.starts_with('/'))
                route.insert(0, "/");

            auto& r = routes_[route];
            r.root = loc.root;
            r.proxy_pass = loc.proxy_pass;
            r.auth = loc.auth;
            r.auth_user = loc.auth_user;
            r.auth_password = loc.auth_password;
            r.auth_file = loc.auth_file;
            if ( ! loc.auth_realm.empty()) {
                r.auth_realm = loc.auth_realm;
            }
        }

        /**
         * @brief Map a URL path prefix to an upstream proxy target.
         * @param route URL prefix, including the leading slash.
         * @param proxy_pass Upstream URL or backend reference.
         */
        void add_proxy(const std::string& route, std::string proxy_pass) {
            routes_[route].proxy_pass = std::move(proxy_pass);
        }

        /**
         * @brief Turn on the on-demand static-file cache for this handler.
         *
         * Not called when the server has no `cache` key, so the cache stays off.
         * Files are not read ahead of the first request.
         *
         * @param cfg Pool size and strategy from the resolved server.
         * @throws std::runtime_error If the pool size or strategy cannot be applied.
         */
        void enable_cache(const CacheConfig& cfg) {
            if (cfg.pool_size == 0
                || cfg.pool_size > std::numeric_limits<std::size_t>::max()) {
                throw std::runtime_error("cache pool_size is invalid");
            }
            if (cfg.strategy != CacheStrategy::Simple)
                throw std::runtime_error("unsupported cache strategy");

            auto state = std::make_shared<CacheState>();
            state->pool = std::make_unique<cache::Cache>(
                cache::StrategyKind::Simple,
                cache::PoolConfig{
                    .capacity_bytes = static_cast<std::size_t>(cfg.pool_size)});
            cache_ = std::move(state);
        }

        /**
         * @brief Handle an HTTP request by matching a location and serving or proxying it.
         * @param req Incoming request. The target query string is ignored for routing.
         * @param res Response to populate. HEAD clears a successful body.
         */
        void handle_request(const Request& req, Response& res) {
            const auto target = std::string(req.target());
            const auto path = target.substr(0, target.find('?'));

            std::string best_match_route;
            Route best;

            for (const auto& [route, spec] : routes_) {
                if (path.starts_with(route) && route.length() > best_match_route.length()) {
                    best_match_route = route;
                    best = spec;
                }
            }

            if (best_match_route.empty()) {
                res.result(http::status::not_found);
                res.set(http::field::content_type, "text/plain");
                res.body() = "404 Not Found";
                res.prepare_payload();
                return;
            }

            if (!authorized_basic(req, best)) {
                unauthorized(res, best.auth_realm);
                return;
            }

            if (!best.proxy_pass.empty()) {
                proxy_request(req, res, best_match_route, best.proxy_pass,
                              backends_, timeouts_);
                if (!alt_svc_.empty())
                    res.set("Alt-Svc", alt_svc_);
                if (req.method() == http::verb::head)
                    res.body().clear();
                return;
            }

            if (!alt_svc_.empty()) {
                res.set("Alt-Svc", alt_svc_);
            }

            std::string relative_path = path.substr(best_match_route.length());
            if (relative_path.empty() || relative_path == "/") {
                relative_path = "/index.html";
            } else if (!relative_path.starts_with('/')) {
                relative_path.insert(0, "/");
            }

            if (const std::string file_path = best.root + relative_path;
                !serve_static(file_path, res)) {
                res.result(http::status::not_found);
                res.set(http::field::content_type, "text/plain");
                res.body() = "404 Not Found";
                res.prepare_payload();
            }

            if (req.method() == http::verb::head) {
                res.body().clear();
            }
        }
    };

    /**
     * @brief Drop a path from the cache index.
     *
     * Releasing the pin does not free the slot until the strategy evicts it.
     * @param state Cache that owns the index.
     * @param path Absolute file path used as the cache key.
     */
    void FileHandler::forget_cached(CacheState& state, const std::string& path) {
        std::lock_guard lock(state.mu);
        const auto it = state.index.find(path);
        if (it == state.index.end())
            return;
        state.lru.erase(it->second);
        state.index.erase(it);
    }

    /**
     * @brief Look up a file whose size and last-write time still match.
     *
     * A stale entry is removed. A hit is moved to the newest end of the
     * index and touched.
     * @param state Cache that owns the index.
     * @param path Absolute file path used as the cache key.
     * @param mtime Last-write time observed for @p path.
     * @param size File size in bytes observed for @p path.
     * @return A pin on the cached body, or an empty Allocation on a miss.
     */
    cache::Allocation FileHandler::find_cached(CacheState& state,
                                               const std::string& path,
                                               const std::filesystem::file_time_type mtime,
                                               const std::uint64_t size) {
        std::lock_guard lock(state.mu);
        const auto it = state.index.find(path);
        if (it == state.index.end())
            return {};
        if (it->second->mtime != mtime || it->second->size != size) {
            state.lru.erase(it->second);
            state.index.erase(it);
            return {};
        }
        state.lru.splice(state.lru.end(), state.lru, it->second);
        it->second->body.touch();
        return it->second->body;
    }

    /**
     * @brief Insert bytes, releasing oldest index pins until a span fits.
     *
     * The caller must hold @c state.mu. Failure does not discard entries
     * that are still pinned by in-flight responses.
     * @param state Cache whose pool receives the bytes.
     * @param bytes Body to copy into the pool.
     * @return A pin on the new slot, or an empty Allocation if it cannot fit.
     */
    cache::Allocation FileHandler::insert_cached(CacheState& state,
                                                 const std::span<const std::byte> bytes) {
        // Caller holds state.mu. Drop oldest pins until the pool can evict a span.
        if (!state.pool || bytes.size() > state.pool->capacity())
            return {};
        for (;;) {
            if (auto slot = state.pool->insert(bytes))
                return slot;
            if (state.lru.empty())
                return {};
            state.index.erase(state.lru.front().path);
            state.lru.pop_front();
        }
    }

    /**
     * @brief Store a file body if it is not already cached with the same identity.
     *
     * A matching entry is only refreshed in the index. A body larger than
     * the pool, or one that still cannot be inserted, is left uncached.
     * @param state Cache that owns the pool and index.
     * @param path Absolute file path used as the cache key.
     * @param mtime Last-write time stored with the body.
     * @param size File size in bytes stored with the body.
     * @param bytes Body to copy into the pool.
     */
    void FileHandler::store_cached(CacheState& state,
                                   const std::string& path,
                                   const std::filesystem::file_time_type mtime,
                                   const std::uint64_t size,
                                   const std::span<const std::byte> bytes) {
        std::lock_guard lock(state.mu);
        if (const auto it = state.index.find(path); it != state.index.end()) {
            if (it->second->mtime == mtime && it->second->size == size) {
                state.lru.splice(state.lru.end(), state.lru, it->second);
                it->second->body.touch();
                return;
            }
            state.lru.erase(it->second);
            state.index.erase(it);
        }

        auto slot = insert_cached(state, bytes);
        if (!slot)
            return;

        CacheState::Entry entry;
        entry.path = path;
        entry.mtime = mtime;
        entry.size = size;
        entry.body = std::move(slot);
        state.lru.push_back(std::move(entry));
        state.index.emplace(path, std::prev(state.lru.end()));
    }

    /**
     * @brief Serve a regular file through the on-demand cache.
     *
     * A hit is reused only while size and last-write time match. A miss
     * reads the file and stores it when those values are unchanged after
     * the read. A rewrite that preserves both is not detected.
     * @param state Cache to consult and update.
     * @param file_path Absolute path of the file to serve.
     * @param res Response to populate on success.
     * @return true if a 200 response was written; false if the path is
     *         missing, not a regular file, or cannot be read.
     */
    bool FileHandler::serve_cached(CacheState& state,
                                   const std::string& file_path,
                                   Response& res) {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(file_path, ec) || ec) {
            forget_cached(state, file_path);
            return false;
        }

        const auto mtime = std::filesystem::last_write_time(file_path, ec);
        const auto sz = std::filesystem::file_size(file_path, ec);
        if (ec || sz > std::numeric_limits<std::uint64_t>::max()) {
            forget_cached(state, file_path);
            return false;
        }
        const auto size = static_cast<std::uint64_t>(sz);

        if (const auto hit = find_cached(state, file_path, mtime, size)) {
            set_file_ok(file_path, body_from(hit), res);
            return true;
        }

        auto content = read_file_bytes(file_path);
        if (!content)
            return false;

        std::error_code again;
        const auto mtime2 = std::filesystem::last_write_time(file_path, again);
        // Same timestamp and size only. A rewrite that preserves both is not
        // detected; the next request that sees a new mtime refreshes the slot.
        if (const auto sz2 = std::filesystem::file_size(file_path, again);
            !again && mtime2 == mtime && sz2 == size && content->size() == size) {
            const auto* raw = reinterpret_cast<const std::byte*>(content->data());
            store_cached(state, file_path, mtime, size, {raw, content->size()});
        }

        set_file_ok(file_path, std::move(*content), res);
        return true;
    }

    /**
     * @brief Serve a static file, using the cache only when it is enabled.
     * @param file_path Absolute path of the file to serve.
     * @param res Response to populate on success.
     * @return true if a 200 response was written; false if the file cannot
     *         be served.
     */
    bool FileHandler::serve_static(const std::string& file_path, Response& res) const {
        const auto state = cache_;
        if (!state)
            return serve_file(file_path, res);
        return serve_cached(*state, file_path, res);
    }

    /**
     * @brief Registers route:directory pairs on a FileHandler.
     *
     * @param locations  Entries of the form `route:directory`.
     * @param file_server Handler to populate.
     * @return false if any entry has an invalid format; true otherwise.
     */
    bool setup_file_handler(const std::vector<std::string> &locations, FileHandler &file_server) {
        for (const auto &location: locations) {
            const size_t colon_pos = location.find(':');
            if (colon_pos == std::string::npos) {
                std::cerr << "Error: Invalid route format '" << location
                        << "'. Expected format: route:directory\n";
                return false;
            }
            std::string route = location.substr(0, colon_pos);
            std::string directory = location.substr(colon_pos + 1);
            if (route.empty() || directory.empty()) {
                std::cerr << "Error: Route and directory cannot be empty in '" << location << "'\n";
                return false;
            }
            if (!route.starts_with('/'))
                route.insert(0, "/");
            if (!fs::exists(directory))
                std::cerr << "Warning: Directory '" << directory << "' does not exist\n";
            file_server.add_location(route, directory);
        }
        return true;
    }

} // namespace microserve
