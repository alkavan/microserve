// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <openssl/sha.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module microserve.handler;

import microserve.core;
import microserve.config;
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
     */
    inline bool is_basic_auth_enabled(const std::string_view auth) {
        return auth == "basic" || auth == "Basic" || auth == "BASIC";
    }

    /**
     * @brief Compare two strings in constant time.
     * @return true if @p a and @p b are equal.
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
     * @brief Reads a file and prepares an HTTP response with its content.
     *
     * @return true on success, false if the file does not exist or cannot be read.
     */
    inline bool serve_file(const std::string& file_path, Response& res) {
        if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
            return false;
        }

        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            return false;
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());

        res.set(http::field::content_type, get_mime_type(file_path));
        res.set(http::field::server, "microserve/1.0");
        res.result(http::status::ok);
        res.body() = std::move(content);
        res.prepare_payload();

        return true;
    }

    /**
     * @brief Serves static files and reverse-proxies configured locations.
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

        std::map<std::string, Route> routes_;
        std::string alt_svc_;
        std::vector<BackendConfig> backends_;
        Config::TimeoutConfig timeouts_{};
        /**
         * @brief Write a 401 Unauthorized response.
         */
        static void unauthorized(Response& res, const std::string& realm) {
            res.result(http::status::unauthorized);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::server, "microserve/1.0");
            res.set("WWW-Authenticate", "Basic realm=\"" + realm + "\", charset=\"UTF-8\"");
            res.body() = "401 Unauthorized";
            res.prepare_payload();
        }

        /**
         * @brief Validate Basic credentials for a route when authentication is enabled.
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
         */
        void set_alt_svc(std::string v) { alt_svc_ = std::move(v); }

        /**
         * @brief Set upstream backends used for proxy locations.
         */
        void set_backends(std::vector<BackendConfig> backends) {
            backends_ = std::move(backends);
        }

        /**
         * @brief Set proxy timeout configuration.
         */
        void set_timeouts(const Config::TimeoutConfig& timeouts) {
            timeouts_ = timeouts;
        }

        /**
         * @brief Map a URL path prefix to a local directory.
         */
        void add_location(const std::string& route, const std::string& directory) {
            routes_[route].root = directory;
        }

        /**
         * @brief Register a location from server configuration.
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
            if (!loc.auth_realm.empty())
                r.auth_realm = loc.auth_realm;
        }

        /**
         * @brief Map a URL path prefix to an upstream proxy target.
         */
        void add_proxy(const std::string& route, std::string proxy_pass) {
            routes_[route].proxy_pass = std::move(proxy_pass);
        }

        /**
         * @brief Handle an HTTP request by matching a location and serving or proxying it.
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
                !serve_file(file_path, res)) {
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
