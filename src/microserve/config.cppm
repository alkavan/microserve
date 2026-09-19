// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <format>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module microserve.config;

import microserve.yaml;
import microserve.logging;

namespace {

    /**
     * @brief Copy of @p s with leading and trailing space/tab removed.
     */
    std::string trim_copy(const std::string_view s) {
        const auto first = s.find_first_not_of(" \t");
        if (first == std::string_view::npos)
            return {};
        const auto last = s.find_last_not_of(" \t");
        return std::string{s.substr(first, last - first + 1)};
    }

    /**
     * @brief ASCII lowercase copy of @p s.
     */
    std::string ascii_lower(const std::string_view s) {
        std::string out{s};
        for (char& c : out)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return out;
    }

    /**
     * @brief Split @p s on commas and trim each token; empty tokens are dropped.
     */
    std::vector<std::string> split_csv(const std::string_view s) {
        std::vector<std::string> out;
        std::string token;
        std::istringstream in{std::string{s}};
        while (std::getline(in, token, ',')) {
            token = trim_copy(token);
            if (!token.empty())
                out.push_back(std::move(token));
        }
        return out;
    }

    /**
     * @brief True if @p s is non-empty and consists only of decimal digits.
     */
    bool is_digits(std::string_view s) {
        return !s.empty() && std::ranges::all_of(s, [](const unsigned char c) {
            return std::isdigit(c) != 0;
        });
    }

} // namespace

export namespace microserve {

    namespace po {
        using ::boost::program_options::options_description;
        using ::boost::program_options::variables_map;
        using ::boost::program_options::value;
        using ::boost::program_options::bool_switch;
        using ::boost::program_options::store;
        using ::boost::program_options::notify;
        using ::boost::program_options::parse_command_line;
    }

    inline constexpr int DEFAULT_PORT                  = 9090;
    inline constexpr std::string_view DEFAULT_ADDR     = "0.0.0.0";
    inline constexpr std::string_view DEFAULT_HOST     = "localhost";
    inline constexpr std::string_view DEFAULT_LOGLEVEL = "warn";

    /**
     * @brief Application protocol for a listen.
     */
    enum class Protocol {
        Http11, // cleartext HTTP/1.1
        Http2c, // cleartext HTTP/2 (h2c)
        Http2,  // TLS HTTP/2
        Http3   // QUIC / HTTP/3
    };

    /**
     * @brief One listen entry on a server.
     *
     * `bind` is a bare port (`9090`), `host:port`, or `[ipv6]:port`.
     * Empty `protocols` inherits the server-level list.
     */
    struct ListenSpec {
        std::string bind;
        std::vector<Protocol> protocols;
    };

    /**
     * @brief Named upstream pool referenced by `proxy_pass`.
     */
    struct BackendConfig {
        std::string name;
        std::vector<std::string> servers;
    };

    /**
     * @brief Role of this process in a federation.
     */
    enum class FederationRole {
        Standalone, // default: not in a federation
        Member,
        Hub         // federation node; any node may take this role
    };

    /**
     * @brief How this node is enrolled in the federation.
     */
    enum class FederationMembership {
        None,       // not a member (stand-alone, even if a file is loaded)
        Unverified, // joined without a federation certificate
        Certified   // holds a federation certificate (may be revoked)
    };

    /**
     * @brief Another federation node this process knows about.
     */
    struct FederationPeer {
        std::string name;
        std::string url;
    };

    /**
     * @brief Optional overlay from `federation.yaml`.
     *
     * Defaults keep the process stand-alone. Enabling this never replaces
     * YAML `servers`.
     */
    struct FederationConfig {
        bool enabled = false;
        FederationRole role = FederationRole::Standalone;
        FederationMembership membership = FederationMembership::None;

        std::string node_id;
        std::string node_name;
        std::string urn_nid = "microserve";

        std::string cert;
        std::string key;
        std::string ca;
        std::string crl;

        std::string parent;
        std::vector<FederationPeer> peers;

        bool allow_unverified = false;
        bool block_unverified = true;
        std::vector<std::string> revoked;
    };

    /**
     * @brief Parsed `--address`: bind IP and/or `server_name`.
     *
     * Unused fields are empty.
     */
    struct AddressOption {
        std::string bind;        // IP / wildcard; empty if not provided
        std::string server_name; // hostname; empty if not provided
    };

    /**
     * @brief Parsed CLI and YAML configuration (before resolve).
     *
     * Dual-stack flags are global. `--listen` / `--address` / `--proto`
     * ignore YAML `servers` (`cli_overrides_servers()`).
     */
    struct Config {
        int verbosity = 0;

        std::string address = "127.0.0.1";

        // Legacy CLI binds (filled from --http-bind / --https-bind / --http3-bind).
        std::string http_bind = "0.0.0.0:9090";
        std::string https_bind = "0.0.0.0:9443";
        std::string http3_bind = "0.0.0.0:9443";
        bool http11 = false;

        // Dual-stack policy (global; not a YAML-servers override).
        bool ipv6 = false;
        bool no_ipv4 = false;

        std::string cert = "certs/server.crt";
        std::string key = "certs/server.key";
        std::string dir = "./public";

        // Presence of --listen / --address / --proto ignores YAML servers.
        bool cli_listen_set = false;
        bool cli_address_set = false;
        bool cli_proto_set = false;
        std::vector<std::string> cli_listen;
        std::string cli_address;
        std::vector<Protocol> cli_proto;

        std::string federation_file;
        bool cli_federation_set = false;
        FederationConfig federation;

        // Internal: site child process (not shown in --help).
        bool cli_child = false;
        bool cli_server_index_set = false;
        int cli_server_index = -1;

        // Debug: children also write to stdout (default: file only).
        bool cli_log_stdout = false;

        // Do not install the graceful console-stop handler.
        // On Windows the console default still ends this process. Site
        // children have no console, so they are not waited on.
        bool cli_service = false;

        /**
         * @brief Connect/read/write timeouts for upstreams.
         */
        struct TimeoutConfig {
            std::chrono::seconds connect{5};
            std::chrono::seconds read{10};
            std::chrono::seconds write{10};
        } timeouts;

        /**
         * @brief Process-wide settings from the YAML `microserve` block.
         */
        struct {
            std::string worker_processes = "auto";
            std::string error_log = "microserve.log";
            std::string error_log_level = "warn";
            std::string pid = "microserve.pid";
            std::string log_dir;
            std::string default_type = "application/octet-stream";
        } microserve;

        /**
         * @brief One virtual host as declared in YAML or built from CLI.
         */
        struct ServerConfig {
            std::string server_name = "localhost";
            std::vector<ListenSpec> listen;
            std::vector<Protocol> protocol;
            std::string tls_cert = "certs/server.crt";
            std::string tls_key = "certs/server.key";
            std::vector<std::string> indexes;

            /**
             * @brief One location: static root, auth, and/or `proxy_pass`.
             */
            struct Location {
                std::string path;
                std::string root;
                std::string auth;
                std::string auth_user;
                std::string auth_password;
                std::string auth_file;
                std::string auth_realm = "microserve";
                std::string proxy_pass;
            };

            std::vector<Location> locations;

            std::string error_log;
            std::string access_log;
            std::string access_log_format;
        };

        std::vector<BackendConfig> backends;
        std::vector<ServerConfig> servers;

        /**
         * @brief True if CLI listen flags should replace YAML `servers`.
         */
        [[nodiscard]] bool cli_overrides_servers() const {
            return cli_listen_set || cli_address_set || cli_proto_set;
        }
    };

    /**
     * @brief One listen after dual-stack expansion.
     *
     * One protocol per entry. HTTP/1.1 and h2c on the same TCP socket
     * appear as two rows with the same addr/port.
     */
    struct ResolvedListen {
        std::string addr;
        unsigned short port = 0;
        Protocol protocol = Protocol::Http11;
    };

    /**
     * @brief One site after validation, expansion, and first-wins listen claims.
     *
     * `backends` is only the upstreams this site's locations reference.
     */
    struct ResolvedServer {
        std::string server_name = "localhost";
        std::vector<ResolvedListen> listens;
        std::string tls_cert;
        std::string tls_key;
        std::vector<std::string> indexes;
        std::vector<Config::ServerConfig::Location> locations;
        std::string error_log;
        std::string access_log;
        std::string access_log_format;
        std::vector<BackendConfig> backends;
    };
    
    /**
     * @brief Fully resolved configuration for the master process.
     *
     * Expanded sites, non-fatal warnings, and federation status.
     * `federation_blocked` means the process should not join or advertise.
     */
    struct ResolvedConfig {
        std::vector<ResolvedServer> servers;
        std::vector<std::string> warnings;
        bool federation_enabled = false;
        bool federation_hub = false;
        bool federation_blocked = false;
    };

    /**
     * @brief Parse a protocol name (case-insensitive).
     *
     * Accepted aliases:
     *   http11, http1, http1.1, http/1.1
     *   http2c, h2c, http2clear, http2cleartext
     *   http2, h2
     *   http3, h3
     */
    std::optional<Protocol> try_parse_protocol(const std::string_view name) {
        const auto n = ascii_lower(trim_copy(name));
        if (n == "http11" || n == "http1" || n == "http1.1" || n == "http/1.1")
            return Protocol::Http11;
        if (n == "http2c" || n == "h2c" || n == "http2clear" || n == "http2cleartext")
            return Protocol::Http2c;
        if (n == "http2" || n == "h2")
            return Protocol::Http2;
        if (n == "http3" || n == "h3")
            return Protocol::Http3;
        return std::nullopt;
    }

    /**
     * @brief Parse a protocol name (case-insensitive).
     *
     * @throws std::runtime_error If @p name is not a known protocol.
     */
    Protocol parse_protocol(const std::string_view name) {
        if (const auto p = try_parse_protocol(name))
            return *p;
        throw std::runtime_error("unknown protocol: " + std::string{name}
            + " (expected http11, http2, http2c, http3)");
    }

    /**
     * @brief Parse a federation role name, or `std::nullopt` if unknown.
     */
    std::optional<FederationRole> try_parse_federation_role(const std::string_view name) {
        const auto n = ascii_lower(trim_copy(name));
        if (n == "standalone" || n == "stand-alone" || n == "none" || n.empty())
            return FederationRole::Standalone;
        if (n == "member" || n == "node")
            return FederationRole::Member;
        if (n == "hub" || n == "federation" || n == "federated")
            return FederationRole::Hub;
        return std::nullopt;
    }

    /**
     * @brief Parse a federation role name.
     *
     * @throws std::runtime_error If @p name is not standalone, member, or hub.
     */
    FederationRole parse_federation_role(const std::string_view name) {
        if (const auto r = try_parse_federation_role(name))
            return *r;
        throw std::runtime_error("unknown federation role: " + std::string{name}
            + " (expected standalone, member, hub)");
    }

    /**
     * @brief Parse a federation membership name, or `std::nullopt` if unknown.
     */
    std::optional<FederationMembership> try_parse_federation_membership(const std::string_view name) {
        const auto n = ascii_lower(trim_copy(name));
        if (n == "none" || n == "standalone" || n.empty())
            return FederationMembership::None;
        if (n == "unverified" || n == "untrusted" || n == "guest")
            return FederationMembership::Unverified;
        if (n == "certified" || n == "verified" || n == "trusted")
            return FederationMembership::Certified;
        return std::nullopt;
    }

    /**
     * @brief Parse a federation membership name.
     *
     * @throws std::runtime_error If @p name is not none, unverified, or certified.
     */
    FederationMembership parse_federation_membership(const std::string_view name) {
        if (const auto m = try_parse_federation_membership(name))
            return *m;
        throw std::runtime_error("unknown federation membership: " + std::string{name}
            + " (expected none, unverified, certified)");
    }

    /**
     * @brief Canonical name of a federation role.
     */
    constexpr std::string_view federation_role_name(const FederationRole r) {
        switch (r) {
            case FederationRole::Standalone: return "standalone";
            case FederationRole::Member:     return "member";
            case FederationRole::Hub:        return "hub";
        }
        return "unknown";
    }
    
    /**
     * @brief Canonical name of a federation membership.
     */
    constexpr std::string_view federation_membership_name(const FederationMembership m) {
        switch (m) {
            case FederationMembership::None:       return "none";
            case FederationMembership::Unverified: return "unverified";
            case FederationMembership::Certified:  return "certified";
        }
        return "unknown";
    }

    /**
     * @brief Membership SAN URI for a federation node certificate.
     *
     * Format `urn:{urn_nid}:node:{node_id}` (e.g. `urn:microserve:node:fed-node-1`).
     *
     * @param node_id Node identifier; empty yields an empty string.
     * @param urn_nid URN NID, default `"microserve"`.
     * @return SAN URI, or empty if @p node_id is empty.
     */
    inline std::string federation_node_urn(std::string_view node_id,
        const std::string_view urn_nid = "microserve")
    {
        if (node_id.empty())
            return {};
        const auto nid = urn_nid.empty() ? "" : urn_nid;
        return std::format("urn:{}:node:{}", nid, node_id);
    }

    /**
     * @brief Parse a comma-separated list of protocol names.
     *
     * @param csv Protocol names, e.g. `"http11,http2c"`.
     * @return Parsed protocols in order.
     *
     * @throws std::runtime_error If any token is not a known protocol.
     */
    std::vector<Protocol> parse_protocol_list(const std::string_view csv)
    {
        std::vector<Protocol> out;
        for (const auto& tok : split_csv(csv))
            out.push_back(parse_protocol(tok));
        return out;
    }

    /**
     * @brief Canonical name of a protocol (`http11`, `http2c`, `http2`, `http3`).
     */
    constexpr std::string_view protocol_name(const Protocol p) {
        switch (p) {
            case Protocol::Http11: return "http11";
            case Protocol::Http2c: return "http2c";
            case Protocol::Http2:  return "http2";
            case Protocol::Http3:  return "http3";
        }
        return "unknown";
    }

    /**
     * @brief True if the protocol requires TLS (HTTP/2, HTTP/3).
     */
    constexpr bool protocol_requires_tls(const Protocol p) {
        return p == Protocol::Http2 || p == Protocol::Http3;
    }

    /**
     * @brief True if the protocol is cleartext (HTTP/1.1, h2c).
     */
    constexpr bool protocol_is_cleartext(const Protocol p) {
        return p == Protocol::Http11 || p == Protocol::Http2c;
    }

    /**
     * @brief True if the protocol is UDP-based (HTTP/3).
     */
    constexpr bool protocol_is_udp(const Protocol p) {
        return p == Protocol::Http3;
    }

    /**
     * @brief Split `--address` into a bind IP and/or `server_name`.
     *
     * Tokens are comma-separated. IPs become the bind address; hostnames
     * become `server_name`. Last of each kind wins.
     *
     * @param s Option value, e.g. `"127.0.0.1"`, `"example.com"`, or
     *          `"0.0.0.0,example.com"`.
     * @return Bind and/or server name; unused fields are empty.
     */
    AddressOption parse_address_option(const std::string_view s) {
        AddressOption out;
        for (const auto& tok : split_csv(s)) {
            std::string_view v = tok;
            if (v.size() >= 2 && v.front() == '[' && v.back() == ']')
                v = v.substr(1, v.size() - 2);
            if (yaml::is_ip_literal(tok) || yaml::is_ip_literal(v)) {
                out.bind = std::string{v};
            } else {
                out.server_name = tok;
            }
        }
        return out;
    }

    /**
     * @brief Parse a listen bind: bare port, `host:port`, or `[ipv6]:port`.
     *
     * A bare port returns an empty host (unspecified; expanded later by
     * dual-stack policy). Bracketed IPv6 is returned without `[]`.
     *
     * @param s Bind string to parse.
     * @return `(host, port)`; @c host is empty for a bare port.
     *
     * @throws std::runtime_error If @p s is empty, malformed, or the port
     *         is not in `1..65535`.
     */
    std::pair<std::string, unsigned short> parse_listen(const std::string& s) {
        const auto t = trim_copy(s);
        if (t.empty())
            throw std::runtime_error("invalid listen address: empty");

        if (t.front() == '[') {
            const auto rb = t.find(']');
            if (rb == std::string::npos || rb + 1 >= t.size() || t[rb + 1] != ':')
                throw std::runtime_error("invalid IPv6 listen address (expected [addr]:port): " + t);
            const int port = std::stoi(t.substr(rb + 2));
            if (port < 1 || port > 65535)
                throw std::runtime_error("invalid listen port: " + t);
            return {t.substr(1, rb - 1), static_cast<unsigned short>(port)};
        }

        if (t.find(':') == std::string::npos) {
            if (!is_digits(t))
                throw std::runtime_error("invalid listen address (expected port or host:port): " + t);
            const int port = std::stoi(t);
            if (port < 1 || port > 65535)
                throw std::runtime_error("invalid listen port: " + t);
            return {"", static_cast<unsigned short>(port)};
        }

        const auto pos = t.rfind(':');
        const auto host = t.substr(0, pos);
        const auto port_s = t.substr(pos + 1);
        if (host.empty() || !is_digits(port_s))
            throw std::runtime_error("invalid listen address (expected host:port): " + t);
        const int port = std::stoi(port_s);
        if (port < 1 || port > 65535)
            throw std::runtime_error("invalid listen port: " + t);
        return {host, static_cast<unsigned short>(port)};
    }

    /**
     * @brief Format a listen bind as a bare port, `host:port`, or `[ipv6]:port`.
     *
     * @param host Bind address; empty means unspecified (bare port only).
     * @param port Listen port.
     * @return Bind string suitable for @ref parse_listen.
     */
    std::string format_bind(const std::string_view host, const unsigned short port) {
        if (host.empty())
            return std::to_string(port);
        if (yaml::is_ipv6_literal(host) && (host.empty() || host.front() != '[')) {
            std::string out = "[";
            out += host;
            out += "]:";
            out += std::to_string(port);
            return out;
        }
        std::string out{host};
        out += ':';
        out += std::to_string(port);
        return out;
    }

    /**
     * @brief Build the single server implied by CLI listen flags.
     *
     * Used when `--listen`, `--address`, or `--proto` is set; YAML
     * `servers` must be ignored. Omitted flags default to listen `9090`,
     * proto `http2c`, wildcard bind, and `server_name=localhost`.
     *
     * @param config Parsed CLI configuration.
     * @return One server with listen entries and protocols filled in.
     */
    Config::ServerConfig make_cli_server(const Config& config) {
        Config::ServerConfig server;
        server.tls_cert = config.cert;
        server.tls_key = config.key;

        const auto [_bind, _server_name] = config.cli_address_set
                                             ? parse_address_option(config.cli_address)
                                             : AddressOption{};

        server.server_name = _server_name.empty()
            ? std::string{DEFAULT_HOST}
            : _server_name;

        std::vector<Protocol> protos = config.cli_proto;
        if (protos.empty())
            protos.push_back(Protocol::Http2c);
        server.protocol = protos;

        std::vector<std::string> listens = config.cli_listen;
        if (listens.empty())
            listens.emplace_back(std::to_string(DEFAULT_PORT));

        for (const auto& spec_s : listens) {
            ListenSpec spec;
            if (auto [_host, _port] = parse_listen(spec_s); _host.empty() && !_bind.empty())
                spec.bind = format_bind(_bind, _port);
            else
                spec.bind = spec_s;
            spec.protocols = protos;
            server.listen.push_back(std::move(spec));
        }

        if (!_bind.empty())
            server.server_name = _server_name.empty()
                ? std::string{DEFAULT_HOST}
                : _server_name;

        return server;
    }

    /**
     * @brief Checks if the provided error log level is valid.
     *
     * Validates that the error_log_level string is one of the supported
     * log levels: trace, debug, info, warn, error, or crit.
     *
     * @param error_log_level The log level string to validate
     * @return true if the log level is valid, false otherwise
     */
    bool is_valid_error_log_level(const std::string& error_log_level) {
        static const std::vector<std::string> valid_levels = {
            "trace", "debug", "info", "warn", "error", "crit"
        };

        return std::ranges::find(valid_levels, error_log_level) != valid_levels.end();
    }

    /**
     * @brief Counts the number of verbosity flags present in command-line arguments.
     *
     * Long option --verbose is counted once per occurrence.  Short options
     * are scanned for every 'v' character so that -v, -vv, -vvv and mixed
     * clusters such as -hv are each counted correctly.  Option parsing stops
     * at the first bare "--" argument.
     *
     * @param argc Argument count passed to main().
     * @param argv Argument vector passed to main().
     * @return Total number of verbosity indicators found.
     */
    int count_verbosity_args(const int argc, char *argv[]) {
        int n = 0;
        for (int i = 1; i < argc; ++i) {
            const std::string_view a{argv[i]};
            if (a == "--") {
                break;
            }
            if (a == "--verbose") {
                ++n;
                continue;
            }
            if (a.starts_with("--")) {
                continue; // other long options
            }
            if (!a.starts_with('-') || a.size() < 2) {
                continue;
            }
            // short cluster: -v, -vv, -vvv (and mixed like -hv)
            for (size_t j = 1; j < a.size(); ++j) {
                if (a[j] == 'v')
                    ++n;
            }
        }
        return n;
    }

    /**
     * @brief Command-line options for server configuration.
     *
     * @return Boost.ProgramOptions description of allowed flags.
     */
    po::options_description create_options_description() {
        po::options_description desc("Allowed options");
        desc.add_options()
                ("help,h", "produce help message")
                ("config,c", po::value<std::string>()->default_value(""),
                 "optional YAML config (locations, log level, ...)")
                ("federation,f", po::value<std::string>(),
                 "optional federation overlay YAML (default: stand-alone, no overlay)")
                ("dir,d", po::value<std::string>()->default_value("."),
                 "directory to serve when no YAML config is given")
                ("listen", po::value<std::string>(),
                 "comma-separated ports or host:port (ignores YAML servers)")
                ("address", po::value<std::string>(),
                 "bind IP and/or server_name, comma-separated (ignores YAML servers)")
                ("proto", po::value<std::string>(),
                 "comma-separated protocols: http11,http2,http2c,http3 (ignores YAML servers)")
                ("http-bind", po::value<std::string>()->default_value("0.0.0.0:9090"),
                 "deprecated: plain HTTP bind (use --listen / --proto)")
                ("https-bind", po::value<std::string>()->default_value("0.0.0.0:9443"),
                 "deprecated: HTTPS bind (use --listen / --proto)")
                ("http3-bind", po::value<std::string>()->default_value("0.0.0.0:9443"),
                 "deprecated: HTTP/3 bind (use --listen / --proto)")
                ("http11", po::bool_switch()->default_value(false),
                 "deprecated: cleartext HTTP/1.1 only on --http-bind")
                ("ipv6", po::bool_switch()->default_value(false),
                 "also listen on IPv6 for unspecified (wildcard) binds")
                ("no-ipv4", po::bool_switch()->default_value(false),
                 "IPv6-only for unspecified binds")
                ("cert", po::value<std::string>()->default_value("certs/server.crt"),
                 "TLS certificate (PEM)")
                ("key", po::value<std::string>()->default_value("certs/server.key"),
                 "TLS private key (PEM)")
                ("log-stdout", po::bool_switch()->default_value(false),
                 "also write site logs to stdout (debug; children inherit the console)")
                ("service", po::bool_switch()->default_value(false),
                 "service mode: do not handle console Ctrl+C; SIGTERM still stops children first")
                // Registered so Boost accepts -v / -vv / --verbose; count comes from argv.
                ("verbose,v", po::value<std::vector<std::string> >()->zero_tokens()->composing(),
                 "increase verbosity (-v, -vv)");
        return desc;
    }

    /**
     * @brief Prints the command-line options description along with usage examples.
     *
     * @param desc The Boost.ProgramOptions options description to output.
     */
    void print_help(const po::options_description &desc) {
        std::cout << desc << "\n"
                << "Example:\n"
                << "  microserve --dir ./public --ipv6\n"
                << "  microserve -c microserve.yaml --ipv6\n"
                << "  microserve -c microserve.yaml -f federation.yaml\n"
                << "  microserve --listen=9090,9443 --proto=http11,http2 --address=localhost\n"
                << "  microserve --listen=127.0.0.1:9191 --proto=http11\n";
    }

    /**
     * @brief Parses command line arguments into a structured options object.
     *
     * `--listen`, `--address`, and `--proto` have no defaults: presence is
     * detected with `variables_map::contains`. If any of the three is set,
     * YAML `servers` must be ignored (`Config::cli_overrides_servers()`).
     * `--ipv6` / `--no-ipv4` are global and do not trigger that override.
     *
     * @param argc        Number of command line arguments.
     * @param argv        Array of C-style strings containing the arguments.
     * @param config      Server config object
     * @param config_file Location of a YAML configuration file
     * @return Parsed arguments wrapped in a structured container.
     */
    bool parse_arguments(const int argc, char *argv[], Config &config, std::string &config_file) {
        try {
            const auto desc = create_options_description();
            po::options_description hidden;
            hidden.add_options()
                    ("child", po::bool_switch()->default_value(false),
                     "internal: run as an isolated site child")
                    ("server-index", po::value<int>(),
                     "internal: resolved server index for --child");
            po::options_description all;
            all.add(desc).add(hidden);

            po::variables_map vm;
            po::store(po::parse_command_line(argc, argv, all), vm);
            po::notify(vm);

            if (vm.contains("help")) {
                print_help(desc);
                return false;
            }

            config_file = vm["config"].as<std::string>();
            config.dir = vm["dir"].as<std::string>();
            config.http_bind = vm["http-bind"].as<std::string>();
            config.https_bind = vm["https-bind"].as<std::string>();
            config.http3_bind = vm["http3-bind"].as<std::string>();
            config.http11 = vm["http11"].as<bool>();
            config.ipv6 = vm["ipv6"].as<bool>();
            config.no_ipv4 = vm["no-ipv4"].as<bool>();
            config.cert = vm["cert"].as<std::string>();
            config.key = vm["key"].as<std::string>();
            config.verbosity = count_verbosity_args(argc, argv);
            config.cli_log_stdout = vm["log-stdout"].as<bool>();
            config.cli_service = vm["service"].as<bool>();

            if (vm.contains("federation")) {
                config.cli_federation_set = true;
                config.federation_file = vm["federation"].as<std::string>();
                if (trim_copy(config.federation_file).empty())
                    throw std::runtime_error("--federation requires a YAML path");
            }

            config.cli_child = vm["child"].as<bool>();
            if (vm.contains("server-index")) {
                config.cli_server_index_set = true;
                config.cli_server_index = vm["server-index"].as<int>();
                if (config.cli_server_index < 0)
                    throw std::runtime_error("--server-index must be >= 0");
            }

            if (vm.contains("listen")) {
                config.cli_listen_set = true;
                config.cli_listen = split_csv(vm["listen"].as<std::string>());
                if (config.cli_listen.empty())
                    throw std::runtime_error("--listen requires at least one port or host:port");
                for (const auto& item : config.cli_listen)
                    (void)parse_listen(item);
            }
            if (vm.contains("address")) {
                config.cli_address_set = true;
                config.cli_address = vm["address"].as<std::string>();
                const auto [_bind, _server_name] = parse_address_option(config.cli_address);
                if (_bind.empty() && _server_name.empty())
                    throw std::runtime_error("--address requires an IP and/or hostname");
                if (!_bind.empty())
                    config.address = _bind;
                else if (!_server_name.empty())
                    config.address = _server_name;
            }
            if (vm.contains("proto")) {
                config.cli_proto_set = true;
                config.cli_proto = parse_protocol_list(vm["proto"].as<std::string>());
                if (config.cli_proto.empty())
                    throw std::runtime_error("--proto requires at least one protocol");
            }

            return true;
        } catch (const std::exception &ex) {
            std::cerr << "Error parsing arguments: " << ex.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Split a `host:port` bind string on the last `:`.
     *
     * @param s Bind string, e.g. `"0.0.0.0:9090"`.
     * @return Host substring and parsed port.
     *
     * @throws std::runtime_error If @p s contains no `:`.
     * @throws std::invalid_argument / std::out_of_range If the port is not an integer.
     */
    std::pair<std::string, unsigned short> parse_bind(const std::string &s) {
        const auto pos = s.rfind(':');
        if (pos == std::string::npos) {
            throw std::runtime_error("invalid bind address (expected host:port): " + s);
        }
        return {s.substr(0, pos), static_cast<unsigned short>(std::stoi(s.substr(pos + 1)))};
    }

    /**
     * @brief Keep @p addr_str's port and force a wildcard address family.
     *
     * @param addr_str Original bind string (only the port is used).
     * @param ipv6     If true, address is `"::"`; otherwise `"0.0.0.0"`.
     *
     * @return `(wildcard_addr, port)`.
     *
     * @throws std::runtime_error If @p addr_str is not valid `host:port`.
     *
     * @see parse_bind
     * @see bind_addrs
     */
    std::pair<std::string, unsigned short>
    resolve_bind_addr(const std::string &addr_str, const bool ipv6) {
        auto [_, port] = parse_bind(addr_str);
        return {ipv6 ? "::" : "0.0.0.0", port};
    }

    /**
     * @brief Build the list of listen addresses for a bind string.
     *
     * Keeps the port from @p addr_str and selects address families from the
     * CLI dual-stack policy.
     *
     * | Condition                         | Result                |
     * |-----------------------------------|-----------------------|
     * | @p force_ipv4_only is `true`      | IPv4 only (`0.0.0.0`) |
     * | @p no_ipv4 is `true`              | IPv6 only (`::`)      |
     * | @p ipv6_flag is `true`            | IPv4 + IPv6           |
     * | default                           | IPv4 only             |
     *
     * Plain HTTP normally passes @p force_ipv4_only as `true`. When
     * `--no-ipv4` is set, callers should pass `false` so HTTP/1 (or h2c),
     * HTTPS, and HTTP/3 all bind IPv6-only.
     *
     * @param addr_str        Bind string in `host:port` form (host is ignored
     *                        except for its port; family comes from the flags).
     * @param ipv6_flag       When true (and neither force-IPv4 nor no-IPv4),
     *                        also listen on IPv6.
     * @param no_ipv4         When true, listen on IPv6 only (`--no-ipv4`).
     * @param force_ipv4_only When true, listen on IPv4 only (typical default
     *                        for cleartext HTTP unless `--no-ipv4`).
     *
     * @return One or two `(address, port)` pairs suitable for acceptor bind.
     *
     * @throws std::runtime_error If @p addr_str has no `host:port` shape
     *         (via @ref parse_bind / @ref resolve_bind_addr).
     *
     * @see resolve_bind_addr
     * @see parse_bind
     */
    std::vector<std::pair<std::string, unsigned short>>
    bind_addrs(const std::string &addr_str, const bool ipv6_flag, const bool no_ipv4,
               const bool force_ipv4_only) {
        if (force_ipv4_only) {
            return {resolve_bind_addr(addr_str, false)};
        }
        if (no_ipv4) {
            return {resolve_bind_addr(addr_str, true)};
        }

        std::vector<std::pair<std::string, unsigned short> > addrs;
        addrs.push_back(resolve_bind_addr(addr_str, false)); // IPv4
        if (ipv6_flag) {
            addrs.push_back(resolve_bind_addr(addr_str, true)); // IPv6
        }
        return addrs;
    }

    /**
     * @brief Expand a listen bind into concrete `(addr, port)` sockets.
     *
     * Explicit addresses (`127.0.0.1`, `::1`, NIC IPs) are kept as-is.
     * Unspecified binds (bare port or `0.0.0.0`) follow @p ipv6_flag /
     * @p no_ipv4. A literal `::` is IPv6-only and is not rewritten.
     *
     * @param bind      Bare port, `host:port`, or `[ipv6]:port`.
     * @param ipv6_flag Also listen on IPv6 for unspecified binds (`--ipv6`).
     * @param no_ipv4   IPv6-only for unspecified binds (`--no-ipv4`).
     * @return One or more `(address, port)` pairs suitable for bind.
     *
     * @throws std::runtime_error If @p bind is not a valid listen address.
     */
    std::vector<std::pair<std::string, unsigned short>>
    expand_listen(const std::string& bind, const bool ipv6_flag, const bool no_ipv4) {
        auto [host, port] = parse_listen(bind);
        const auto port_s = std::to_string(port);

        if (host.empty() || host == "0.0.0.0")
            return bind_addrs("0.0.0.0:" + port_s, ipv6_flag, no_ipv4, /*force_ipv4_only=*/false);

        if (host == "::")
            return {{"::", port}};

        return {{host, port}};
    }

    /**
     * @brief Protocols in effect for one listen entry.
     *
     * Uses @p listen's own list when it is non-empty; otherwise inherits
     * @p server's protocol list.
     *
     * @param listen Listen spec whose per-entry protocols may override.
     * @param server Server whose protocol list is the fallback.
     * @return Reference to the chosen protocol list (never copied).
     */
    const std::vector<Protocol>&
    effective_protocols(const ListenSpec& listen, const Config::ServerConfig& server) {
        return listen.protocols.empty() ? server.protocol : listen.protocols;
    }

    /**
     * @brief Backend name referenced by a `proxy_pass`, if any.
     *
     * Matches `backend:name` / `backend://name`, a bare known backend name,
     * or a URL whose host is a known backend and has no port. Direct URLs
     * (IP or `host:port`) are not backends.
     *
     * @param proxy_pass Location `proxy_pass` value.
     * @param backends Known backends to match against.
     * @return Backend name; empty string if `backend:` has no name;
     *         `std::nullopt` if this is not a backend reference.
     */
    std::optional<std::string>
    proxy_pass_backend_name(const std::string_view proxy_pass,
                            const std::vector<BackendConfig>& backends) {
        auto is_backend = [&](const std::string_view n) {
            return std::ranges::any_of(backends, [&](const BackendConfig& b) {
                return b.name == n;
            });
        };

        const auto p = trim_copy(proxy_pass);
        if (p.empty())
            return std::nullopt;

        if (p.starts_with("backend:")) {
            std::string name = p.substr(8);
            if (name.starts_with("//"))
                name.erase(0, 2);
            if (const auto slash = name.find('/'); slash != std::string::npos)
                name.resize(slash);
            name = trim_copy(name);
            if (name.empty())
                return std::string{};
            return name;
        }

        const auto sep = p.find("://");
        if (sep == std::string::npos) {
            if (is_backend(p))
                return p;
            return std::nullopt;
        }

        std::string_view rest = std::string_view{p}.substr(sep + 3);
        if (const auto at = rest.find('@'); at != std::string_view::npos)
            rest.remove_prefix(at + 1);

        std::string host;
        bool has_port = false;
        if (!rest.empty() && rest.front() == '[') {
            const auto rb = rest.find(']');
            if (rb == std::string_view::npos)
                return std::nullopt;
            host = std::string{rest.substr(1, rb - 1)};
            if (rb + 1 < rest.size() && rest[rb + 1] == ':')
                has_port = true;
        } else {
            const auto end = rest.find_first_of(":/");
            host = std::string{rest.substr(0, end)};
            if (end != std::string_view::npos && rest[end] == ':')
                has_port = true;
        }

        if (!has_port && is_backend(host))
            return host;
        return std::nullopt;
    }

    /**
     * @brief Resolve sites for the master process.
     *
     * Applies CLI overlay (when set), dual-stack expansion, first-wins
     * listen claims, and the backend subset each site actually uses.
     * A colliding listen is warned and dropped; a site with none left is
     * skipped. Other sites still start.
     *
     * @param config Parsed CLI and YAML configuration.
     * @return Expanded servers, warnings, and federation status.
     */
    ResolvedConfig resolve_config(const Config& config) {
        ResolvedConfig out;
        out.federation_enabled = config.federation.enabled
            && config.federation.role != FederationRole::Standalone;
        out.federation_hub = out.federation_enabled
            && config.federation.role == FederationRole::Hub
            && config.federation.membership == FederationMembership::Certified
            && !config.federation.cert.empty()
            && !config.federation.key.empty();

        if (config.federation.enabled
            && config.federation.role != FederationRole::Standalone) {
            const auto& f = config.federation;
            if (f.role == FederationRole::Hub
                && f.membership != FederationMembership::Certified) {
                out.warnings.emplace_back("hub requires membership: certified; not advertising as hub");
            }
            if (f.role == FederationRole::Hub
                && f.membership == FederationMembership::Certified
                && (f.cert.empty() || f.key.empty())) {
                out.warnings.emplace_back("hub has no federation cert/key; not advertising as hub");
            }
            const bool revoked = !f.node_id.empty()
                && std::ranges::find(f.revoked, f.node_id) != f.revoked.end();
            if (revoked) {
                out.federation_blocked = true;
                out.warnings.push_back(std::format(
                    "federation certificate for node '{}' is revoked; "
                    "leave the federation or install a new certificate",
                    f.node_id));
                return out;
            }
            if (f.role == FederationRole::Member
                && f.membership == FederationMembership::Unverified
                && f.block_unverified
                && !f.allow_unverified) {
                out.federation_blocked = true;
                out.warnings.emplace_back("federation hub blocks unverified members; "
                    "install a federation certificate or set membership: none");
                return out;
            }
            if (f.role == FederationRole::Member
                && f.membership == FederationMembership::Certified
                && (f.cert.empty() || f.key.empty())) {
                out.warnings.emplace_back("certified membership has no federation cert/key; treating as unverified");
                if (f.block_unverified && !f.allow_unverified) {
                    out.federation_blocked = true;
                    out.warnings.emplace_back("federation hub blocks unverified members; "
                        "install a federation certificate or set membership: none");
                    return out;
                }
            }
        }

        std::vector<BackendConfig> backends;
        {
            std::vector<std::string> seen;
            for (const auto& b : config.backends) {
                if (std::ranges::find(seen, b.name) != seen.end()) {
                    out.warnings.push_back(
                        std::format("duplicate backend name '{}' ignored", b.name));
                    continue;
                }
                seen.push_back(b.name);
                backends.push_back(b);
            }
        }

        std::vector<Config::ServerConfig> sources;
        if (config.cli_overrides_servers()) {
            sources.push_back(make_cli_server(config));
        } else if (config.servers.empty()) {
            Config::ServerConfig implicit;
            implicit.server_name = std::string{DEFAULT_HOST};
            implicit.tls_cert = config.cert;
            implicit.tls_key = config.key;
            implicit.protocol = {Protocol::Http2c};
            implicit.listen.push_back(ListenSpec{.bind = std::to_string(DEFAULT_PORT), .protocols = {}});
            sources.push_back(std::move(implicit));
        } else {
            sources = config.servers;
        }

        struct Claim {
            std::string addr;
            unsigned short port = 0;
            bool udp = false;
            bool tls = false; // TCP: TLS (http2) vs cleartext (http11/http2c)
            std::string server_name;
        };
        std::vector<Claim> claims;

        auto canonical_addr = [](std::string addr) {
            if (constexpr std::string_view mapped = "::ffff:"; addr.size() > mapped.size()
                && ascii_lower(addr.substr(0, mapped.size())) == mapped) {
                const auto v4 = addr.substr(mapped.size());
                if (yaml::is_ipv4_literal(v4))
                    return v4;
            }
            return addr;
        };

        auto is_unspec_v4 = [](const std::string_view a) {
            return a == "0.0.0.0";
        };
        auto is_unspec_v6 = [](const std::string_view a) {
            return a == "::";
        };
        auto is_v4 = [&](const std::string_view a) {
            return is_unspec_v4(a) || yaml::is_ipv4_literal(a);
        };
        auto is_v6 = [&](const std::string_view a) {
            return is_unspec_v6(a) || yaml::is_ipv6_literal(a);
        };
        auto addrs_overlap = [&](const std::string_view a, const std::string_view b) {
            if (a == b)
                return true;
            if (is_unspec_v4(a) && is_v4(b))
                return true;
            if (is_unspec_v4(b) && is_v4(a))
                return true;
            if (is_unspec_v6(a) && is_v6(b))
                return true;
            if (is_unspec_v6(b) && is_v6(a))
                return true;
            if (is_unspec_v4(a) && is_unspec_v6(b))
                return true;
            if (is_unspec_v6(a) && is_unspec_v4(b))
                return true;
            return false;
        };

        for (const auto& src : sources) {
            const std::string site = src.server_name.empty()
                ? std::string{DEFAULT_HOST}
                : src.server_name;

            std::vector<BackendConfig> used;
            bool site_error = false;
            for (const auto& loc : src.locations) {
                const auto named = proxy_pass_backend_name(loc.proxy_pass, backends);
                if (!named)
                    continue;
                if (named->empty() || !std::ranges::any_of(backends, [&](const BackendConfig& b) {
                        return b.name == *named;
                    })) {
                    out.warnings.push_back(std::format(
                        "server '{}' skipped: unknown backend '{}' in proxy_pass",
                        site, named->empty() ? loc.proxy_pass : *named));
                    site_error = true;
                    break;
                }
                if (std::ranges::none_of(used, [&](const BackendConfig& b) {
                        return b.name == *named;
                    })) {
                    for (const auto& b : backends) {
                        if (b.name == *named) {
                            used.push_back(b);
                            break;
                        }
                    }
                }
            }
            if (site_error)
                continue;

            ResolvedServer dst;
            dst.server_name = site;
            dst.tls_cert = src.tls_cert.empty() ? config.cert : src.tls_cert;
            dst.tls_key = src.tls_key.empty() ? config.key : src.tls_key;
            dst.indexes = src.indexes;
            dst.locations = src.locations;
            dst.error_log = src.error_log;
            dst.access_log = src.access_log;
            dst.access_log_format = src.access_log_format;
            dst.backends = std::move(used);

            if (src.listen.empty()) {
                out.warnings.push_back(
                    std::format("server '{}' skipped: no listen entries", site));
                continue;
            }

            for (const auto& spec : src.listen) {
                auto protos = effective_protocols(spec, src);
                if (protos.empty()) {
                    out.warnings.push_back(std::format(
                        "listen '{}' on '{}' dropped: no protocol", spec.bind, site));
                    continue;
                }

                std::vector<std::pair<std::string, unsigned short>> addrs;
                try {
                    addrs = expand_listen(spec.bind, config.ipv6, config.no_ipv4);
                } catch (const std::exception& ex) {
                    out.warnings.push_back(std::format(
                        "listen '{}' on '{}' dropped: {}", spec.bind, site, ex.what()));
                    continue;
                }

                for (auto [addr, port] : addrs) {
                    addr = canonical_addr(std::move(addr));
                    for (const Protocol proto : protos) {
                        const bool udp = protocol_is_udp(proto);
                        const bool tls = protocol_requires_tls(proto) && !udp;

                        const Claim* holder = nullptr;
                        for (const auto& c : claims) {
                            if (c.port != port || c.udp != udp)
                                continue;
                            if (!addrs_overlap(c.addr, addr))
                                continue;
                            holder = &c;
                            break;
                        }

                        if (holder) {
                            const bool same_site = holder->server_name == site;
                            if (const bool same_kind = holder->tls == tls; same_site && same_kind) {
                                dst.listens.push_back(ResolvedListen{.addr = addr, .port = port, .protocol = proto});
                                continue;
                            }
                            out.warnings.push_back(std::format(
                                "listen {}:{}/{} ({}) dropped for '{}': held by '{}'",
                                addr, port, udp ? "udp" : "tcp", protocol_name(proto),
                                site, holder->server_name));
                            continue;
                        }

                        claims.push_back(Claim{.addr = addr, .port = port, .udp = udp, .tls = tls, .server_name = site});
                        dst.listens.push_back(ResolvedListen{.addr = addr, .port = port, .protocol = proto});
                    }
                }
            }

            if (dst.listens.empty()) {
                out.warnings.push_back(
                    std::format("server '{}' skipped: no listens remaining", site));
                continue;
            }

            const bool needs_tls = std::ranges::any_of(dst.listens, [](const ResolvedListen& l) {
                return protocol_requires_tls(l.protocol);
            });
            if (needs_tls && (dst.tls_cert.empty() || dst.tls_key.empty())) {
                out.warnings.push_back(std::format(
                    "server '{}' skipped: TLS protocol requires tls_cert/tls_key", site));
                continue;
            }

            out.servers.push_back(std::move(dst));
        }

        if (out.servers.empty()) {
            out.warnings.emplace_back("no servers remaining after resolve");
        }

        return out;
    }

    /**
     * @brief Place relative logs under `log_dir` and a relative pid next to the executable.
     *
     * Absolute paths are kept. An empty `log_dir` means `<exe>/logs`. Quoted
     * path values are unquoted first.
     */
    void apply_runtime_paths(Config& config) {
        auto clean = [](std::string s) {
            s = trim_copy(s);
            if (s.size() >= 2
                && ((s.front() == '"' && s.back() == '"')
                    || (s.front() == '\'' && s.back() == '\'')))
                s = s.substr(1, s.size() - 2);
            return s;
        };
        auto under_log_dir = [](const std::string& log_dir, std::string path) {
            path = path.empty() ? std::string{"microserve.log"} : path;
            return path_is_absolute(path) ? path : join_path(log_dir, path);
        };

        const auto exe_dir = executable_directory();
        config.microserve.log_dir = clean(config.microserve.log_dir);
        config.microserve.error_log = clean(config.microserve.error_log);
        config.microserve.pid = clean(config.microserve.pid);

        std::string log_dir = config.microserve.log_dir;
        if (log_dir.empty())
            log_dir = join_path(exe_dir, "logs");
        else if (!path_is_absolute(log_dir))
            log_dir = join_path(exe_dir, log_dir);
        config.microserve.log_dir = log_dir;
        config.microserve.error_log = under_log_dir(log_dir, config.microserve.error_log);

        if (config.microserve.pid.empty())
            config.microserve.pid = "microserve.pid";
        if (!path_is_absolute(config.microserve.pid))
            config.microserve.pid = join_path(exe_dir, config.microserve.pid);

        for (auto& server : config.servers) {
            server.error_log = clean(server.error_log);
            server.access_log = clean(server.access_log);
            if (!server.error_log.empty() && !path_is_absolute(server.error_log))
                server.error_log = join_path(log_dir, server.error_log);
            if (!server.access_log.empty() && !path_is_absolute(server.access_log))
                server.access_log = join_path(log_dir, server.access_log);
        }
    }

} // namespace microserve

namespace {

    std::vector<microserve::Protocol> parse_protocol_json(const nlohmann::json& v) {
        std::vector<microserve::Protocol> out;
        if (v.is_string()) {
            out.push_back(microserve::parse_protocol(v.get<std::string>()));
            return out;
        }
        if (!v.is_array())
            throw std::runtime_error("protocol must be a string or list, got " + v.dump());
        for (const auto& item : v)
            out.push_back(microserve::parse_protocol(microserve::yaml::json_to_string(item)));
        return out;
    }

    microserve::ListenSpec parse_listen_item(const nlohmann::json& v) {
        microserve::ListenSpec spec;
        if (v.is_object()) {
            if (!v.contains("bind"))
                throw std::runtime_error("listen object requires 'bind'");
            spec.bind = microserve::yaml::json_to_string(v["bind"]);
            (void)microserve::parse_listen(spec.bind);
            if (v.contains("protocol"))
                spec.protocols = parse_protocol_json(v["protocol"]);
            return spec;
        }
        spec.bind = microserve::yaml::json_to_string(v);
        (void)microserve::parse_listen(spec.bind);
        return spec;
    }

    std::vector<microserve::ListenSpec> parse_listen_json(const nlohmann::json& v) {
        std::vector<microserve::ListenSpec> out;
        if (v.is_array()) {
            for (const auto& item : v)
                out.push_back(parse_listen_item(item));
            return out;
        }
        out.push_back(parse_listen_item(v));
        return out;
    }

    bool json_to_bool(const nlohmann::json& v, const bool fallback = false) {
        if (v.is_boolean())
            return v.get<bool>();
        if (v.is_string()) {
            const auto s = v.get<std::string>();
            if (s == "true" || s == "True" || s == "TRUE" || s == "on" || s == "yes")
                return true;
            if (s == "false" || s == "False" || s == "FALSE" || s == "off" || s == "no")
                return false;
        }
        if (v.is_number_integer())
            return v.get<int>() != 0;
        return fallback;
    }

    microserve::FederationConfig parse_federation_json(const nlohmann::json& fed) {
        microserve::FederationConfig out;
        if (fed.contains("enabled"))
            out.enabled = json_to_bool(fed["enabled"]);
        if (fed.contains("hub") && json_to_bool(fed["hub"]))
            out.role = microserve::FederationRole::Hub;
        if (fed.contains("role"))
            out.role = microserve::parse_federation_role(microserve::yaml::json_to_string(fed["role"]));
        if (fed.contains("membership"))
            out.membership = microserve::parse_federation_membership(
                microserve::yaml::json_to_string(fed["membership"]));
        if (fed.contains("node_id"))
            out.node_id = microserve::yaml::json_to_string(fed["node_id"]);
        if (fed.contains("node_name"))
            out.node_name = microserve::yaml::json_to_string(fed["node_name"]);
        if (fed.contains("urn_nid"))
            out.urn_nid = microserve::yaml::json_to_string(fed["urn_nid"]);
        if (fed.contains("cert"))
            out.cert = microserve::yaml::json_to_string(fed["cert"]);
        if (fed.contains("key"))
            out.key = microserve::yaml::json_to_string(fed["key"]);
        if (fed.contains("ca"))
            out.ca = microserve::yaml::json_to_string(fed["ca"]);
        if (fed.contains("crl"))
            out.crl = microserve::yaml::json_to_string(fed["crl"]);
        if (fed.contains("parent"))
            out.parent = microserve::yaml::json_to_string(fed["parent"]);
        if (fed.contains("allow_unverified"))
            out.allow_unverified = json_to_bool(fed["allow_unverified"]);
        if (fed.contains("block_unverified"))
            out.block_unverified = json_to_bool(fed["block_unverified"]);
        if (fed.contains("peers") && fed["peers"].is_array()) {
            for (const auto& p : fed["peers"]) {
                microserve::FederationPeer peer;
                if (p.is_string()) {
                    peer.url = microserve::yaml::json_to_string(p);
                } else if (p.is_object()) {
                    if (p.contains("name"))
                        peer.name = microserve::yaml::json_to_string(p["name"]);
                    if (p.contains("url"))
                        peer.url = microserve::yaml::json_to_string(p["url"]);
                }
                if (!peer.url.empty() || !peer.name.empty())
                    out.peers.push_back(std::move(peer));
            }
        }
        if (fed.contains("revoked") && fed["revoked"].is_array()) {
            for (const auto& r : fed["revoked"])
                out.revoked.push_back(microserve::yaml::json_to_string(r));
        }
        return out;
    }

} // namespace

export namespace microserve {
    /**
     * @brief Load and parse application configuration from the YAML file at @p config_path.
     * @param config_path Path to the configuration file to open and read.
     * @return Config populated from microserve, timeouts, backends, and servers sections.
     */
    Config load_config(const std::string& config_path) {
        std::ifstream ifs(config_path);
        if (!ifs.is_open())
            throw std::runtime_error("failed to open config file: " + config_path);

        nlohmann::json j = yaml::parse_yaml(ifs);
        Config config;

        if (j.contains("microserve")) {
            const auto& ms = j["microserve"];
            if (ms.contains("worker_processes"))
                config.microserve.worker_processes = yaml::json_to_string(ms["worker_processes"]);
            if (ms.contains("error_log"))
                config.microserve.error_log = ms["error_log"].get<std::string>();
            if (ms.contains("error_log_level")) {
                if (auto s = ms["error_log_level"].get<std::string>(); is_valid_error_log_level(s))
                    config.microserve.error_log_level = s;
                else {
                    config.microserve.error_log_level = std::string{DEFAULT_LOGLEVEL};
                    log_warn(std::format("[{:<11}] invalid error log level: {}; using default: {}",
                                         "main", s, DEFAULT_LOGLEVEL));
                }
            }
            if (ms.contains("pid"))
                config.microserve.pid = ms["pid"].get<std::string>();
            if (ms.contains("log_dir"))
                config.microserve.log_dir = ms["log_dir"].get<std::string>();
            if (ms.contains("default_type"))
                config.microserve.default_type = ms["default_type"].get<std::string>();
        }
        if (j.contains("timeouts")) {
            const auto& t = j["timeouts"];
            if (t.contains("connect"))
                config.timeouts.connect = std::chrono::seconds(t["connect"].get<int>());
            if (t.contains("read"))
                config.timeouts.read = std::chrono::seconds(t["read"].get<int>());
            if (t.contains("write"))
                config.timeouts.write = std::chrono::seconds(t["write"].get<int>());
        }
        if (j.contains("backends") && j["backends"].is_array()) {
            for (const auto& backend_json : j["backends"]) {
                BackendConfig backend;
                if (backend_json.contains("name"))
                    backend.name = yaml::json_to_string(backend_json["name"]);
                if (backend_json.contains("servers") && backend_json["servers"].is_array()) {
                    for (const auto& s : backend_json["servers"])
                        backend.servers.push_back(yaml::json_to_string(s));
                }
                if (backend.name.empty())
                    throw std::runtime_error("backend is missing 'name'");
                config.backends.push_back(std::move(backend));
            }
        }
        if (j.contains("servers") && j["servers"].is_array()) {
            for (const auto& server_json : j["servers"]) {
                Config::ServerConfig server;
                if (server_json.contains("listen"))
                    server.listen = parse_listen_json(server_json["listen"]);
                if (server_json.contains("server_name"))
                    server.server_name = server_json["server_name"].get<std::string>();
                if (server_json.contains("protocol"))
                    server.protocol = parse_protocol_json(server_json["protocol"]);
                if (server_json.contains("tls_cert"))
                    server.tls_cert = server_json["tls_cert"].get<std::string>();
                if (server_json.contains("tls_key"))
                    server.tls_key = server_json["tls_key"].get<std::string>();
                if (server_json.contains("error_log"))
                    server.error_log = server_json["error_log"].get<std::string>();
                if (server_json.contains("access_log"))
                    server.access_log = server_json["access_log"].get<std::string>();
                if (server_json.contains("access_log_format"))
                    server.access_log_format = server_json["access_log_format"].get<std::string>();
                if (server_json.contains("indexes") && server_json["indexes"].is_array())
                    for (const auto& index : server_json["indexes"])
                        server.indexes.push_back(index.get<std::string>());
                if (server_json.contains("locations") && server_json["locations"].is_array()) {
                    for (const auto& loc_json : server_json["locations"]) {
                        Config::ServerConfig::Location location;
                        if (loc_json.contains("path"))
                            location.path = loc_json["path"].get<std::string>();
                        if (loc_json.contains("root"))
                            location.root = loc_json["root"].get<std::string>();
                        if (loc_json.contains("auth"))
                            location.auth = loc_json["auth"].get<std::string>();
                        if (loc_json.contains("auth_user"))
                            location.auth_user = loc_json["auth_user"].get<std::string>();
                        if (loc_json.contains("auth_password"))
                            location.auth_password = loc_json["auth_password"].get<std::string>();
                        if (loc_json.contains("auth_file"))
                            location.auth_file = loc_json["auth_file"].get<std::string>();
                        if (loc_json.contains("auth_realm"))
                            location.auth_realm = loc_json["auth_realm"].get<std::string>();
                        if (loc_json.contains("proxy_pass"))
                            location.proxy_pass = loc_json["proxy_pass"].get<std::string>();
                        server.locations.push_back(location);
                    }
                }
                config.servers.push_back(server);
            }
        }
        if (!config.servers.empty()) {
            if (const auto& primary = config.servers[0]; primary.server_name == "localhost")
                config.address = "127.0.0.1";
            else
                config.address = primary.server_name;
        }
        return config;
    }

    /**
     * Overlay `federation.yaml` onto an already-loaded Config.
     * Does not replace `servers`, `backends`, or listen policy.
     */
    void load_federation(const std::string& path, Config& config) {
        std::ifstream ifs(path);
        if (!ifs.is_open())
            throw std::runtime_error("failed to open federation file: " + path);

        nlohmann::json j = yaml::parse_yaml(ifs);
        if (!j.contains("federation"))
            throw std::runtime_error("federation file missing top-level 'federation' key: " + path);

        config.federation = parse_federation_json(j["federation"]);
        config.federation_file = path;
    }

} // namespace microserve
