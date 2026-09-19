// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include <format>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

import microserve.core;
import microserve.config;
import microserve.logging;
import microserve.process;

int main(const int argc, char* argv[]) {
    microserve::setup_logger();

    try {
        std::string config_file;
        microserve::Config config;

        if (!microserve::parse_arguments(argc, argv, config, config_file)) {
            return argc > 1 && std::string(argv[1]) == "--help" ? 0 : 1;
        }

        const auto cli_http_bind  = config.http_bind;
        const auto cli_https_bind = config.https_bind;
        const auto cli_http3_bind = config.http3_bind;
        const auto cli_http11         = config.http11;
        const auto cli_ipv6           = config.ipv6;
        const auto cli_no_ipv4        = config.no_ipv4;
        const auto cli_cert       = config.cert;
        const auto cli_key        = config.key;
        const auto cli_dir        = config.dir;
        const auto cli_verbosity       = config.verbosity;

        const auto cli_federation_set      = config.cli_federation_set;
        const auto cli_federation_file = config.federation_file;
        const auto cli_listen_set          = config.cli_listen_set;
        const auto cli_listen   = config.cli_listen;
        const auto cli_address_set         = config.cli_address_set;
        const auto cli_address         = config.cli_address;
        const auto cli_proto_set           = config.cli_proto_set;
        const auto cli_proto  = config.cli_proto;
        const auto cli_child               = config.cli_child;
        const auto cli_server_index_set    = config.cli_server_index_set;
        const auto cli_server_index         = config.cli_server_index;
        const auto cli_log_stdout          = config.cli_log_stdout;
        const auto cli_service             = config.cli_service;

        if (!config_file.empty()) {
            config = microserve::load_config(config_file);
        }

        config.http_bind  = cli_http_bind;
        config.https_bind = cli_https_bind;
        config.http3_bind = cli_http3_bind;
        config.http11     = cli_http11;
        config.ipv6       = cli_ipv6;
        config.no_ipv4    = cli_no_ipv4;
        config.cert       = cli_cert;
        config.key        = cli_key;
        config.dir        = cli_dir;
        config.verbosity  = cli_verbosity;

        config.cli_federation_set   = cli_federation_set;
        config.federation_file      = cli_federation_file;
        config.cli_listen_set       = cli_listen_set;
        config.cli_listen           = cli_listen;
        config.cli_address_set      = cli_address_set;
        config.cli_address          = cli_address;
        config.cli_proto_set        = cli_proto_set;
        config.cli_proto            = cli_proto;
        config.cli_child            = cli_child;
        config.cli_server_index_set = cli_server_index_set;
        config.cli_server_index     = cli_server_index;
        config.cli_log_stdout       = cli_log_stdout;
        config.cli_service          = cli_service;

        if (!config.federation_file.empty()) {
            microserve::load_federation(config.federation_file, config);
        }

            microserve::apply_runtime_paths(config);

            if (config.verbosity >= 2)
                config.microserve.error_log_level = "trace";
            else if (config.verbosity == 1)
                config.microserve.error_log_level = "info";

            microserve::set_logger_level(config.microserve.error_log_level);

            const auto resolved = microserve::resolve_config(config);

            if (resolved.federation_blocked) {
                try {
                    microserve::rebind_logger_sinks(config.microserve.error_log, true);
                } catch (const std::exception& ex) {
                    microserve::log_warn(std::format(
                        "[{:<11}] file log '{}' unavailable: {}",
                        "main", config.microserve.error_log, ex.what()));
                }
                microserve::log_error(std::format(
                    "[{:<11}] node is blocked; not serving (leave the federation or install a certificate)",
                    "federation"));
                for (const auto& warning : resolved.warnings)
                    microserve::log_warn(std::format("[{:<11}] {}", "config", warning));
                microserve::logger_flush();
                microserve::shutdown_logging();
                return 1;
            }

            const bool isolated_child = config.cli_child;
            std::string log_file = config.microserve.error_log;
            bool console = !isolated_child || config.cli_log_stdout;
            if (isolated_child) {
                if (int index = config.cli_server_index_set ? config.cli_server_index : 0;
                    index >= 0 && static_cast<size_t>(index) < resolved.servers.size()) {
                    const auto& site = resolved.servers[static_cast<size_t>(index)];
                    if (!site.error_log.empty())
                        log_file = site.error_log;
                    else
                        log_file = microserve::site_error_log_path(
                            config.microserve.error_log, site.server_name);
                    microserve::set_logger_identity(site.server_name);
                } else {
                    microserve::set_logger_identity("child");
                }
            } else if (resolved.servers.size() > 1) { // NOLINT(bugprone-branch-clone)
                microserve::set_logger_identity("master");
            } else {
                microserve::set_logger_identity("main");
                if (!resolved.servers.empty() && !resolved.servers.front().error_log.empty()) {
                    log_file = resolved.servers.front().error_log;
                }
            }

            try {
                microserve::rebind_logger_sinks(log_file, console);
            } catch (const std::exception& ex) {
                microserve::log_warn(std::format(
                    "[{:<11}] file log '{}' unavailable: {}",
                    microserve::logger_identity(), log_file, ex.what()));
            }

            if (!isolated_child) {
                microserve::log_info(std::format(
                    "[{:<11}] log level set to: {}", "main", config.microserve.error_log_level));
                microserve::log_info(std::format(
                    "[{:<11}] ipv6={}  no_ipv4={}", "main", config.ipv6, config.no_ipv4));
                microserve::log_info(std::format(
                    "[{:<11}] file log: {}", "main", log_file));
                if (config.cli_service) {
                    microserve::log_info(std::format(
                        "[{:<11}] service mode: console Ctrl+C is not handled here",
                        "main"));
                }

                for (const auto& warning : resolved.warnings) {
                    microserve::log_warn(std::format("[{:<11}] {}", "config", warning));
                }

                if (resolved.federation_enabled) {
                    const auto& fed = config.federation;
                    const auto who = fed.node_name.empty() ? fed.node_id : fed.node_name;
                    const auto urn = microserve::federation_node_urn(fed.node_id, fed.urn_nid);
                    microserve::log_info(std::format(
                        "[{:<11}] mode available: {} {}  node={}{}",
                        "federation",
                        microserve::federation_role_name(fed.role),
                        microserve::federation_membership_name(fed.membership),
                        who.empty() ? "(unnamed)" : who,
                        urn.empty() ? "" : std::format("  urn={}", urn)));
                    if (resolved.federation_hub) {
                        microserve::log_info(std::format(
                            "[{:<11}] add members with an overlay: role: member, membership: certified, parent: this hub, and a federation certificate",
                            "federation"));
                        if (fed.block_unverified && !fed.allow_unverified) {
                            microserve::log_info(std::format(
                                "[{:<11}] unverified join is blocked (set allow_unverified: true to permit guests)",
                                "federation"));
                        }
                    } else if (fed.role == microserve::FederationRole::Hub) {
                        microserve::log_warn(std::format(
                            "[{:<11}] hub overlay is loaded but not certified; serving stand-alone until membership: certified and cert/key are set",
                            "federation"));
                    }
                } else if (!config.federation_file.empty()) {
                    microserve::log_info(std::format(
                        "[{:<11}] overlay loaded from '{}'; stand-alone (enabled: false or role: standalone)",
                        "federation", config.federation_file));
                }
            } else {
                microserve::log_info(std::format(
                    "[{:<11}] file log: {}",
                    microserve::logger_identity(), log_file));
            }

            struct PidFileGuard {
                std::string path;
                bool armed = false;
                ~PidFileGuard() {
                    if (armed)
                        microserve::remove_pid_file(path);
                }
            } pid_file;

            if (!isolated_child) {
                if (microserve::write_pid_file(config.microserve.pid)) {
                    pid_file.path = config.microserve.pid;
                    pid_file.armed = true;
                    microserve::log_info(std::format(
                        "[{:<11}] pid file: {}", "main", config.microserve.pid));
                } else {
                    microserve::log_warn(std::format(
                        "[{:<11}] pid file '{}' could not be created",
                        "main", config.microserve.pid));
                }
                microserve::log_info(std::format(
                    "[{:<11}] log dir: {}", "main", config.microserve.log_dir));
            }

            microserve::logger_flush();

            const int rc = microserve::run_sites(config, resolved, argc, argv);
            microserve::logger_flush();
            microserve::shutdown_logging();
            return rc;

    } catch (const std::exception& ex) {
        microserve::log_error(std::format("[{:<11}] {}", "main", ex.what()));
        microserve::logger_flush();
        microserve::shutdown_logging();
        return 1;
    } catch (...) {
        microserve::log_error(
            std::format("[{:<11}] unknown error", "main"));
        microserve::shutdown_logging();
        return 1;
    }
}
