// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <format>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <spawn.h>
#  include <sys/wait.h>
#  include <unistd.h>
extern char** environ;
#endif

export module microserve.process;

import microserve.core;
import microserve.config;
import microserve.logging;
import microserve.server;
import microserve.handler;

export namespace microserve {

    /**
     * @brief Serve one resolved site in the current process.
     *
     * Configures the file/proxy handler, binds grouped listeners, and runs
     * the I/O loop until SIGINT/SIGTERM (or the Windows console-control
     * equivalents).
     *
     * @param config   Runtime configuration (timeouts, verbosity, CLI flags).
     * @param instance Resolved site to bind and serve.
     * @return 0 on clean shutdown; 1 if handler setup fails or no listener
     *         could be bound.
     */
    int run_server_instance(const Config& config, const ResolvedServer& instance);

    /**
     * @brief Run all resolved sites, spawning children when there is more than one.
     *
     * With `--child`, serves only `config.cli_server_index`. A single site
     * runs in-process. Otherwise this process is the master: it logs each
     * site's listen map, spawns isolated children, and waits for them.
     *
     * @param config   Runtime configuration, including child CLI flags.
     * @param resolved Fully resolved servers and federation state.
     * @param argc     Argument count from `main` (used to rebuild child argv).
     * @param argv     Argument vector from `main`.
     * @return Combined process exit code (0 if every site exited cleanly).
     */
    int run_sites(const Config& config, const ResolvedConfig& resolved,
                  int argc, char* argv[]);

    /**
     * @brief Rewrite argv for an isolated site child (`--child --server-index=N`).
     *
     * Copies the current arguments, dropping any existing `--child` /
     * `--server-index` flags, then appends those flags for @p index.
     *
     * @param argc  Argument count from `main`.
     * @param argv  Argument vector from `main`.
     * @param index Site index in the resolved server list.
     * @return Argument strings suitable for spawning the child.
     */
    std::vector<std::string> make_child_argv(int argc, char* argv[], int index);

    /**
     * @brief Log the console listen map for one site.
     *
     * The master prints this before spawning so operators can see each
     * site's URLs without waiting for child logs.
     *
     * @param instance Resolved site whose listeners are printed.
     */
    void log_site_listen_map(const ResolvedServer& instance);

} // namespace microserve

namespace {

    /**
     * @brief One bind address with the HTTP protocols that share it.
     *
     * Listen entries that use the same address, port, and transport (TCP vs
     * UDP) are merged so a single `Server` can be constructed per socket.
     */
    struct ListenGroup {
        std::string addr;            ///< Bind address (hostname or IP).
        unsigned short port = 0;     ///< Bind port.
        bool udp = false;            ///< `true` for QUIC / HTTP/3 (UDP).
        bool allow_h11 = false;      ///< HTTP/1.1 is enabled on this bind.
        bool allow_h2c = false;      ///< Cleartext HTTP/2 (h2c) is enabled.
        bool http2 = false;          ///< TLS HTTP/2 is enabled.
        bool http3 = false;          ///< HTTP/3 is enabled.
    };

    /**
     * @brief Merge a site's listen entries into one group per socket.
     *
     * Entries that share address, port, and transport (TCP vs UDP) are
     * combined so protocol flags can be applied to a single bind.
     *
     * @param instance Resolved site whose `listens` are grouped.
     * @return Groups ready for listener construction and logging.
     */
    std::vector<ListenGroup> group_listens(const microserve::ResolvedServer& instance) {
        std::vector<ListenGroup> groups;
        auto find_group = [&](const std::string& addr, const unsigned short port,
                              const bool udp) -> ListenGroup& {
            for (auto& g : groups) {
                if (g.addr == addr && g.port == port && g.udp == udp)
                    return g;
            }
            groups.push_back(ListenGroup{.addr = addr, .port = port, .udp = udp});
            return groups.back();
        };
        for (const auto& [addr, port, protocol] : instance.listens) {
            auto& g = find_group(addr, port, microserve::protocol_is_udp(protocol));
            if (protocol == microserve::Protocol::Http11)
                g.allow_h11 = true;
            else if (protocol == microserve::Protocol::Http2c)
                g.allow_h2c = true;
            else if (protocol == microserve::Protocol::Http2)
                g.http2 = true;
            else if (protocol == microserve::Protocol::Http3)
                g.http3 = true;
        }
        return groups;
    }

    /**
     * @brief Build argv for an isolated site child.
     *
     * Copies @p argv, drops any existing `--child` / `--server-index` flags,
     * then appends `--child` and `--server-index=@p index`.
     *
     * @param argc  Argument count from `main`.
     * @param argv  Argument vector from `main`.
     * @param index Site index in the resolved server list.
     * @return Argument strings suitable for spawning the child.
     */
    std::vector<std::string> child_args(const int argc, char* argv[], const int index) {
        std::vector<std::string> args;
        if (argc > 0)
            args.emplace_back(argv[0]);
        for (int i = 1; i < argc; ++i) {
            const std::string_view a{argv[i]};
            if (a == "--child")
                continue;
            if (a == "--server-index") {
                if (i + 1 < argc)
                    ++i;
                continue;
            }
            if (a.starts_with("--server-index="))
                continue;
            args.emplace_back(argv[i]);
        }
        args.emplace_back("--child");
        args.push_back("--server-index=" + std::to_string(index));
        return args;
    }

#ifdef _WIN32
    std::wstring utf8_to_wide(const std::string& s) {
        if (s.empty())
            return {};
        const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        if (n <= 1)
            return {};
        std::wstring w(static_cast<size_t>(n - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
        return w;
    }

    std::wstring quote_windows_arg(const std::string& arg) {
        const auto wide = utf8_to_wide(arg);
        if (wide.find_first_of(L" \t\"") == std::wstring::npos)
            return wide;
        std::wstring out = L"\"";
        for (const wchar_t c : wide) {
            if (c == L'"')
                out += L"\\\"";
            else
                out += c;
        }
        out += L'"';
        return out;
    }

    std::wstring windows_command_line(const std::vector<std::string>& args) {
        std::wstring line;
        for (size_t i = 0; i < args.size(); ++i) {
            if (i)
                line += L' ';
            line += quote_windows_arg(args[i]);
        }
        return line;
    }

    struct WinChild {
        HANDLE process = nullptr;
        DWORD pid = 0;
        std::string name;
    };

    struct ChildStopWait {
        HANDLE event = nullptr;
        std::atomic_bool stop{false};
        std::function<void()> fn;
    };

    struct MasterConsole {
        std::atomic_int phase{0};
        HANDLE notify = nullptr;
    };

    MasterConsole* g_master_console = nullptr;

    DWORD WINAPI child_stop_wait(LPVOID param) {
        auto* w = static_cast<ChildStopWait*>(param);
        while (!w->stop.load()) {
            if (WaitForSingleObject(w->event, 200) == WAIT_OBJECT_0) {
                if (w->fn)
                    w->fn();
                break;
            }
        }
        return 0;
    }

    BOOL WINAPI master_console_handler(DWORD ev) {
        if (!g_master_console || !g_master_console->notify)
            return FALSE;
        switch (ev) {
            case CTRL_C_EVENT:
            case CTRL_BREAK_EVENT:
            case CTRL_CLOSE_EVENT:
            case CTRL_LOGOFF_EVENT:
            case CTRL_SHUTDOWN_EVENT:
                g_master_console->phase.fetch_add(1);
                SetEvent(g_master_console->notify);
                return TRUE;
            default:
                return FALSE;
        }
    }

    HANDLE create_kill_on_close_job() {
        HANDLE job = CreateJobObjectW(nullptr, nullptr);
        if (!job)
            return nullptr;
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                     &info, sizeof(info))) {
            CloseHandle(job);
            return nullptr;
        }
        return job;
    }

    bool spawn_windows(const std::vector<std::string>& args, const HANDLE job, WinChild& out,
                       const bool inherit_console) {
        auto cmdline = windows_command_line(args);
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        DWORD flags = CREATE_UNICODE_ENVIRONMENT;
        if (!inherit_console) {
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = INVALID_HANDLE_VALUE;
            si.hStdOutput = INVALID_HANDLE_VALUE;
            si.hStdError = INVALID_HANDLE_VALUE;
            flags |= CREATE_NO_WINDOW;
        }
        PROCESS_INFORMATION pi{};
        const BOOL ok = CreateProcessW(
            nullptr, cmdline.data(), nullptr, nullptr, FALSE,
            flags, nullptr, nullptr, &si, &pi);
        if (!ok)
            return false;
        if (job)
            AssignProcessToJobObject(job, pi.hProcess);
        CloseHandle(pi.hThread);
        out.process = pi.hProcess;
        out.pid = pi.dwProcessId;
        return true;
    }
#else
    std::atomic_bool g_ignore_sigint{false};
    std::atomic_int g_stop_phase{0};

    void master_signal_handler(int sig) {
        if (sig == SIGINT && g_ignore_sigint.load())
            return;
        int expected = 0;
        if (!g_stop_phase.compare_exchange_strong(expected, 1))
            g_stop_phase.store(2);
    }

    struct PosixChild {
        pid_t pid = -1;
        std::string name;
    };

    bool spawn_posix(const std::vector<std::string>& args, PosixChild& out,
                     const bool inherit_console) {
        std::vector<char*> ptrs;
        ptrs.reserve(args.size() + 1);
        for (const auto& s : args)
            ptrs.push_back(const_cast<char*>(s.c_str()));
        ptrs.push_back(nullptr);

        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        if (!inherit_console) {
            posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
            posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
        }

        pid_t pid = 0;
        const int rc = posix_spawnp(&pid, args.front().c_str(), &fa, nullptr,
                                    ptrs.data(), environ);
        posix_spawn_file_actions_destroy(&fa);
        if (rc != 0)
            return false;
        out.pid = pid;
        return true;
    }
#endif

} // namespace

export namespace microserve {

    std::vector<std::string> make_child_argv(const int argc, char* argv[], const int index) {
        return child_args(argc, argv, index);
    }

    /**
     * @brief Log the console listen map for one site.
     *
     * The master prints this before spawning so operators can see each
     * site's URLs without waiting for child logs.
     *
     * @param instance Resolved site whose listeners are printed.
     */
    void log_site_listen_map(const ResolvedServer& instance) {
        for (const auto& [
            _addr,
            _port,
            _udp,
            _allow_h11,
            _allow_h2c,
            _http2,
            _http3
        ] : group_listens(instance)) {
            Server::Protocol proto;
            bool allow_h11 = true;
            if (_udp || _http3) {
                proto = Server::Protocol::Http3;
            } else if (_http2) {
                proto = Server::Protocol::Http2;
            } else if (_allow_h2c) {
                proto = Server::Protocol::Http2ClearText;
                allow_h11 = _allow_h11;
            } else {
                proto = Server::Protocol::Http1;
            }
            const char* kind =
                proto == Server::Protocol::Http3
                    ? "HTTP/3 (QUIC)"
                    : proto == Server::Protocol::Http2
                    ? "HTTP/2"
                    : proto == Server::Protocol::Http2ClearText
                    ? (allow_h11 ? "HTTP/2 (h2c) + HTTP/1.1" : "HTTP/2 (h2c)")
                    : "HTTP/1.1";
            const char* scheme =
                (proto == Server::Protocol::Http1 ||
                 proto == Server::Protocol::Http2ClearText)
                    ? "http"
                    : "https";
            log_listener_urls(kind, scheme, _addr, _port);
        }
    }

    /**
     * @brief Serve one resolved site in the current process.
     *
     * Configures the file/proxy handler, binds grouped listeners, and runs
     * the I/O loop until SIGINT/SIGTERM (or the Windows console-control
     * equivalents).
     *
     * @param config   Runtime configuration (timeouts, verbosity, CLI flags).
     * @param instance Resolved site to bind and serve.
     * @return 0 on clean shutdown; 1 if handler setup fails or no listener
     *         could be bound.
     */
    int run_server_instance(const Config& config, const ResolvedServer& instance) {
        if (!instance.access_log.empty()) {
            try {
                rebind_access_log(instance.access_log, config.cli_log_stdout);
                log_info(std::format("[{:<11}] access log: {}",
                                     logger_identity(), instance.access_log));
            } catch (const std::exception& ex) {
                log_warn(std::format("[{:<11}] access log '{}' unavailable: {}",
                                     logger_identity(), instance.access_log, ex.what()));
            }
        }

        net::io_context ioc;
        std::vector<std::unique_ptr<Server>> servers;
        auto file_server = std::make_shared<FileHandler>();
        file_server->set_backends(instance.backends);
        file_server->set_timeouts(config.timeouts);

        bool any_location = false;
        for (const auto& loc : instance.locations) {
            if (loc.root.empty() && loc.proxy_pass.empty())
                continue;
            file_server->add_location(loc);
            any_location = true;
        }

        if (!any_location) {
            Config::ServerConfig::Location fallback;
            fallback.path = "/";
            fallback.root = config.dir;
            file_server->add_location(fallback);
        }

        std::vector<std::string> locations;
        bool any_proxy = false;
        for (const auto& loc : instance.locations) {
            if (!loc.proxy_pass.empty()) {
                auto path = loc.path;
                if (path.empty())
                    path = "/";
                if (!path.starts_with('/'))
                    path.insert(0, "/");
                file_server->add_proxy(path, loc.proxy_pass);
                any_proxy = true;
                continue;
            }
            if (loc.root.empty())
                continue;
            locations.push_back(loc.path + ":" + loc.root);
        }
        if (locations.empty() && !any_proxy)
            locations.push_back("/:" + config.dir);

        if (!locations.empty() && !setup_file_handler(locations, *file_server))
            return 1;

        unsigned short h3_port = 0;
        for (const auto& ln : instance.listens) {
            if (ln.protocol == Protocol::Http3)
                h3_port = ln.port;
        }
        if (h3_port != 0)
            file_server->set_alt_svc("h3=\":" + std::to_string(h3_port) + "\"; ma=86400");

        for (const auto& [
            _addr,
            _port,
            _udp,
            _allow_h11,
            _allow_h2c,
            _http2,
            _http3
        ] : group_listens(instance)) {
            Server::Protocol proto;
            bool allow_h11 = true;
            if (_udp || _http3) {
                proto = Server::Protocol::Http3;
            } else if (_http2) {
                proto = Server::Protocol::Http2;
            } else if (_allow_h2c) {
                proto = Server::Protocol::Http2ClearText;
                allow_h11 = _allow_h11;
            } else {
                proto = Server::Protocol::Http1;
                allow_h11 = true;
            }

            const char* kind =
                proto == Server::Protocol::Http3
                    ? "HTTP/3 (QUIC)"
                    : proto == Server::Protocol::Http2
                    ? "HTTP/2"
                    : proto == Server::Protocol::Http2ClearText
                    ? (allow_h11 ? "HTTP/2 (h2c) + HTTP/1.1" : "HTTP/2 (h2c)")
                    : "HTTP/1.1";
            const char* scheme =
                (proto == Server::Protocol::Http1 ||
                 proto == Server::Protocol::Http2ClearText)
                    ? "http"
                    : "https";

            std::unique_ptr<Server> srv;
            try {
                srv = std::make_unique<Server>(
                    ioc, _addr, _port, proto, instance.tls_cert, instance.tls_key,
                    config.verbosity, allow_h11);
            } catch (const std::exception& ex) {
                log_error(std::format("[{:<11}] {}:{} ({}) failed: {}",
                                      "listen", _addr, _port, kind, ex.what()));
                continue;
            }

            srv->set_handler([file_server](const auto& req, auto& res) {
                file_server->handle_request(req, res);
            });
            log_listener_urls(kind, scheme, _addr, _port);
            srv->start();
            servers.push_back(std::move(srv));
        }

        if (servers.empty()) {
            log_error(std::format("[{:<11}] site '{}' has no listeners",
                                  "child", instance.server_name));
            return 1;
        }

        net::signal_set signals(ioc);
        signals.add(SIGTERM);
        if (!config.cli_service) {
            signals.add(SIGINT);
#ifdef _WIN32
            signals.add(SIGBREAK);
#endif
        }
        std::atomic_bool stopping{false};

        auto request_shutdown = [&](const std::string_view why) {
            if (bool expected = false; !stopping.compare_exchange_strong(expected, true))
                return;
            net::post(ioc, [&, why = std::string(why)] {
                log_info(std::format("[{:<11}] {}, shutting down...", "signal", why));
                for (const auto& srv : servers)
                    srv->stop();
                error_code ec;
                signals.cancel(ec);
                ioc.stop();
            });
        };

#ifdef _WIN32
        ChildStopWait stop_wait;
        HANDLE stop_thread = nullptr;
        if (const char* evname = std::getenv("MICROSERVE_SHUTDOWN_EVENT")) {
            stop_wait.event = OpenEventA(SYNCHRONIZE, FALSE, evname);
            if (stop_wait.event) {
                stop_wait.fn = [&] { request_shutdown("shutdown"); };
                stop_thread = CreateThread(nullptr, 0, child_stop_wait, &stop_wait, 0, nullptr);
            }
        }

        if (!config.cli_service) {
            static std::function<void(std::string_view)>* s_fn = nullptr;
            std::function<void(std::string_view)> fn = request_shutdown;
            s_fn = &fn;
            SetConsoleCtrlHandler([](const DWORD ev) -> BOOL {
                if (!s_fn)
                    return FALSE;
                switch (ev) {
                    case CTRL_C_EVENT:        (*s_fn)("CTRL_C");     return TRUE;
                    case CTRL_BREAK_EVENT:    (*s_fn)("CTRL_BREAK"); return TRUE;
                    case CTRL_CLOSE_EVENT:    (*s_fn)("CTRL_CLOSE"); return TRUE;
                    case CTRL_LOGOFF_EVENT:
                    case CTRL_SHUTDOWN_EVENT: (*s_fn)("CTRL_SHUTDOWN"); return TRUE;
                    default: return FALSE;
                }
            }, TRUE);
        }
#endif

        signals.async_wait([&](const error_code& ec, const int sig) {
            if (ec)
                return;
            const char* name =
                sig == SIGINT  ? "SIGINT"  :
                sig == SIGTERM ? "SIGTERM" :
#ifdef _WIN32
                sig == SIGBREAK ? "SIGBREAK" :
#endif
                "signal";
            request_shutdown(name);
        });

        log_info(std::format("[{:<11}] site '{}' running ({})",
                             config.cli_child ? "child" : "main",
                             instance.server_name,
                             config.cli_service ? "SIGTERM to stop" : "Ctrl-C to stop"));
        ioc.run();
#ifdef _WIN32
        stop_wait.stop.store(true);
        if (stop_thread) {
            WaitForSingleObject(stop_thread, INFINITE);
            CloseHandle(stop_thread);
        }
        if (stop_wait.event)
            CloseHandle(stop_wait.event);
#endif
        log_info(std::format("[{:<11}] site '{}' io_context exited",
                             config.cli_child ? "child" : "main",
                             instance.server_name));
        servers.clear();
        return 0;
    }

    /**
     * @brief Run all resolved sites, spawning children when there is more than one.
     *
     * With `--child`, serves only `config.cli_server_index`. A single site
     * runs in-process. Otherwise this process is the master: it logs each
     * site's listen map, spawns isolated children, and waits for them.
     *
     * @param config   Runtime configuration, including child CLI flags.
     * @param resolved Fully resolved servers and federation state.
     * @param argc     Argument count from `main` (used to rebuild child argv).
     * @param argv     Argument vector from `main`.
     * @return Combined process exit code (0 if every site exited cleanly).
     */
    int run_sites(const Config& config, const ResolvedConfig& resolved,
                  const int argc, char* argv[]) {
        if (resolved.servers.empty()) {
            log_error(std::format("[{:<11}] no listeners remaining after resolve", "main"));
            return 1;
        }

        if (config.cli_child) {
            int index = config.cli_server_index_set ? config.cli_server_index : 0;
            if (index < 0 || static_cast<size_t>(index) >= resolved.servers.size()) {
                log_error(std::format("[{:<11}] --server-index {} out of range (0..{})",
                                      "child", index,
                                      resolved.servers.size() - 1));
                return 1;
            }
            const auto& site = resolved.servers[static_cast<size_t>(index)];
            log_info(std::format("[{:<11}] isolated site '{}' (index {})",
                                 "child", site.server_name, index));
            return run_server_instance(config, site);
        }

        if (resolved.servers.size() == 1)
            return run_server_instance(config, resolved.servers.front());

        log_info(std::format("[{:<11}] starting {} isolated site processes",
                             "master", resolved.servers.size()));

        const auto saved_id = logger_identity();
        for (const auto& site : resolved.servers) {
            set_logger_identity(site.server_name);
            log_info(std::format("[{:<11}] site '{}'", "master", site.server_name));
            log_site_listen_map(site);
        }
        set_logger_identity(saved_id);
        logger_flush();

#ifdef _WIN32
        SECURITY_ATTRIBUTES sa{};
        SECURITY_DESCRIPTOR sd{};
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = &sd;
        const auto stop_name = "Local\\microserve-stop-" + std::to_string(GetCurrentProcessId());
        const HANDLE shutdown_event = CreateEventA(&sa, TRUE, FALSE, stop_name.c_str());
        const HANDLE console_event = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        SetEnvironmentVariableA("MICROSERVE_SHUTDOWN_EVENT", stop_name.c_str());
        if (!shutdown_event || !console_event) {
            log_error(std::format("[{:<11}] failed to create shutdown event: {}",
                                  "master", GetLastError()));
            if (shutdown_event)
                CloseHandle(shutdown_event);
            if (console_event)
                CloseHandle(console_event);
            return 1;
        }

        const HANDLE job = create_kill_on_close_job();
        std::vector<WinChild> children;
        children.reserve(resolved.servers.size());
        for (size_t i = 0; i < resolved.servers.size(); ++i) {
            const auto args = child_args(argc, argv, static_cast<int>(i));
            WinChild child;
            child.name = resolved.servers[i].server_name;
            if (!spawn_windows(args, job, child, config.cli_log_stdout)) {
                log_error(std::format("[{:<11}] failed to spawn site '{}': error {}",
                                      "master", child.name, GetLastError()));
                for (const auto& c : children) {
                    TerminateProcess(c.process, 1);
                    CloseHandle(c.process);
                }
                if (job)
                    CloseHandle(job);
                return 1;
            }
            log_info(std::format("[{:<11}] spawned '{}' pid={}",
                                 "master", child.name, child.pid));
            children.push_back(child);
        }

        MasterConsole console_stop;
        console_stop.notify = console_event;
        if (!config.cli_service) {
            g_master_console = &console_stop;
            SetConsoleCtrlHandler(master_console_handler, TRUE);
        }

        int exit_code = 0;
        int applied = 0;
        std::vector<HANDLE> waits;
        auto rebuild = [&] {
            waits.clear();
            for (const auto& c : children)
                if (c.process)
                    waits.push_back(c.process);
            waits.push_back(console_event);
        };
        rebuild();

        while (true) {
            bool any = false;
            for (const auto& c : children) {
                if (c.process) {
                    any = true;
                    break;
                }
            }
            if (!any)
                break;

            const DWORD wr = WaitForMultipleObjects(
                static_cast<DWORD>(waits.size()), waits.data(), FALSE, INFINITE);
            if (wr == WAIT_FAILED)
                break;
            const auto idx = wr - WAIT_OBJECT_0;
            if (idx >= waits.size())
                continue;
            const HANDLE fired = waits[idx];
            if (fired == console_event) {
                ResetEvent(console_event);
                const int phase = console_stop.phase.load();
                if (phase >= 2 && applied < 2) {
                    log_info(std::format("[{:<11}] second stop, killing children", "master"));
                    for (auto& c : children)
                        if (c.process)
                            TerminateProcess(c.process, 1);
                    applied = 2;
                } else if (phase >= 1 && applied < 1) {
                    log_info(std::format("[{:<11}] stopping children", "master"));
                    SetEvent(shutdown_event);
                    applied = 1;
                }
                continue;
            }

            for (auto& c : children) {
                if (c.process != fired)
                    continue;
                DWORD code = 1;
                GetExitCodeProcess(c.process, &code);
                CloseHandle(c.process);
                c.process = nullptr;
                if (code != 0) {
                    log_error(std::format("[{:<11}] site '{}' exited with {}",
                                          "master", c.name, code));
                    exit_code = 1;
                } else {
                    log_info(std::format("[{:<11}] site '{}' exited", "master", c.name));
                }
                break;
            }
            rebuild();
        }

        if (g_master_console == &console_stop)
            g_master_console = nullptr;
        if (!config.cli_service)
            SetConsoleCtrlHandler(master_console_handler, FALSE);
        CloseHandle(shutdown_event);
        CloseHandle(console_event);
        if (job)
            CloseHandle(job);
        return exit_code;
#else
        std::vector<PosixChild> children;
        children.reserve(resolved.servers.size());
        for (size_t i = 0; i < resolved.servers.size(); ++i) {
            const auto args = child_args(argc, argv, static_cast<int>(i));
            PosixChild child;
            child.name = resolved.servers[i].server_name;
            if (!spawn_posix(args, child, config.cli_log_stdout)) {
                log_error(std::format("[{:<11}] failed to spawn site '{}'",
                                      "master", child.name));
                for (auto& c : children)
                    kill(c.pid, SIGTERM);
                return 1;
            }
            log_info(std::format("[{:<11}] spawned '{}' pid={}",
                                 "master", child.name, child.pid));
            children.push_back(child);
        }

        g_ignore_sigint.store(config.cli_service);
        g_stop_phase.store(0);
        struct sigaction sa{};
        sa.sa_handler = master_signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGTERM, &sa, nullptr);
        if (!config.cli_service)
            sigaction(SIGINT, &sa, nullptr);

        int exit_code = 0;
        int applied = 0;
        size_t alive = children.size();
        while (alive > 0) {
            const int phase = g_stop_phase.load();
            if (phase > applied) {
                const int sig = phase >= 2 ? SIGKILL : SIGTERM;
                log_info(std::format("[{:<11}] {}",
                                     "master",
                                     phase >= 2 ? "second stop, killing children"
                                                : "stopping children"));
                for (const auto& c : children) {
                    if (c.pid > 0)
                        kill(c.pid, sig);
                }
                applied = phase >= 2 ? 2 : 1;
            }
            int status = 0;
            const pid_t pid = waitpid(-1, &status, 0);
            if (pid < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            for (auto& c : children) {
                if (c.pid != pid)
                    continue;
                c.pid = -1;
                --alive;
                const int code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
                if (code != 0) {
                    log_error(std::format("[{:<11}] site '{}' exited with {}",
                                          "master", c.name, code));
                    exit_code = 1;
                    for (const auto& o : children) {
                        if (o.pid > 0)
                            kill(o.pid, SIGTERM);
                    }
                } else {
                    log_info(std::format("[{:<11}] site '{}' exited", "master", c.name));
                }
                break;
            }
        }
        return exit_code;
#endif
    }

} // namespace microserve
