// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <spdlog/logger.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <unistd.h>
#  ifdef __APPLE__
#    include <mach-o/dyld.h>
#  endif
#endif

module microserve.logging;

// Module implementation unit: keep heavy/header-only deps and function bodies
// here. Definitions in a module interface are implicitly inline; importers then
// re-emit dependent template code and the link can fail (missing symbols, ODR).
// Interface = declarations/exports only; this TU owns the emitted object code.

namespace microserve {

    using Logger = std::shared_ptr<spdlog::logger>;

    static std::string g_identity{"main"};
    inline constexpr std::string_view ACCESS_LOGGER_NAME = "microserve.access";

    static Logger get_logger() {
        return spdlog::get(std::string{LOGGER_NAME});
    }

    static Logger get_access_logger() {
        return spdlog::get(std::string{ACCESS_LOGGER_NAME});
    }

    static std::string sanitize_site_stem(const std::string_view site) {
        std::string out;
        out.reserve(site.size());
        for (const unsigned char c : site) {
            if (std::isalnum(c) || c == '-' || c == '_')
                out.push_back(static_cast<char>(c));
            else
                out.push_back('_');
        }
        while (!out.empty() && out.front() == '_')
            out.erase(out.begin());
        while (!out.empty() && out.back() == '_')
            out.pop_back();
        return out.empty() ? std::string{"site"} : out;
    }

    void log_info(std::string_view msg) {
        if (const auto l = get_logger()) l->info("{}", msg);
    }

    void log_warn(std::string_view msg) {
        if (const auto l = get_logger()) l->warn("{}", msg);
    }

    void log_error(std::string_view msg) {
        if (const auto l = get_logger()) l->error("{}", msg);
    }

    void log_debug(std::string_view msg) {
        if (const auto l = get_logger()) l->debug("{}", msg);
    }

    void log_access(std::string_view msg) {
        if (const auto a = get_access_logger()) {
            a->info("{}", msg);
            return;
        }
        if (const auto l = get_logger())
            l->info("{}", msg);
    }

    void logger_flush() {
        if (const auto l = get_logger()) l->flush();
        if (const auto a = get_access_logger()) a->flush();
    }

    void set_logger_identity(const std::string_view tag) {
        auto t = std::string{tag};
        if (t.empty())
            t = "main";
        g_identity = std::move(t);
    }

    std::string logger_identity() {
        return g_identity;
    }

    std::string site_error_log_path(const std::string_view base_path, const std::string_view site_name) {
        const auto stem = sanitize_site_stem(site_name);
        std::string path{base_path};
        if (path.empty())
            path = "microserve.log";
        const auto slash = path.find_last_of("/\\");
        if (const auto dot = path.rfind('.');
            dot != std::string::npos && (slash == std::string::npos || dot > slash))
            return path.substr(0, dot) + "-" + stem + path.substr(dot);
        return path + "-" + stem;
    }

    bool path_is_absolute(const std::string_view path) {
        if (path.empty())
            return false;
        if (path.front() == '/' || path.front() == '\\')
            return true;
        return path.size() >= 3
            && std::isalpha(static_cast<unsigned char>(path[0])) != 0
            && path[1] == ':'
            && (path[2] == '/' || path[2] == '\\');
    }

    static std::string wide_to_utf8(const std::wstring_view w) {
#ifdef _WIN32
        if (w.empty())
            return {};
        const int n = WideCharToMultiByte(
            CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (n <= 0)
            return {};
        std::string out(static_cast<size_t>(n), '\0');
        WideCharToMultiByte(
            CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
        return out;
#else
        (void)w;
        return {};
#endif
    }

    std::string executable_directory() {
#ifdef _WIN32
        std::wstring buf(32768, L'\0');
        const DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0 || n >= buf.size())
            return ".";
        buf.resize(n);
        const auto slash = buf.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
            return ".";
        const auto dir = wide_to_utf8(buf.substr(0, slash));
        return dir.empty() ? std::string{"."} : dir;
#elif defined(__APPLE__)
        char buf[4096];
        uint32_t size = sizeof(buf);
        if (_NSGetExecutablePath(buf, &size) != 0)
            return ".";
        std::error_code ec;
        const auto canon = std::filesystem::weakly_canonical(buf, ec);
        const auto parent = (ec ? std::filesystem::path{buf} : canon).parent_path();
        return parent.empty() ? std::string{"."} : parent.string();
#else
        char buf[4096];
        const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (n <= 0)
            return ".";
        const std::string path{buf, static_cast<size_t>(n)};
        const auto slash = path.find_last_of('/');
        if (slash == std::string::npos)
            return ".";
        return path.substr(0, slash);
#endif
    }

    std::string join_path(const std::string_view dir, const std::string_view child) {
        if (child.empty())
            return std::string{dir};
        if (dir.empty() || path_is_absolute(child))
            return std::string{child};
        std::string out{dir};
        if (out.back() != '/' && out.back() != '\\')
            out.push_back('/');
        out.append(child);
        return out;
    }

    void ensure_parent_directory(const std::string& file_path) {
        const auto slash = file_path.find_last_of("/\\");
        if (slash == std::string::npos || slash == 0)
            return;
        const auto dir = file_path.substr(0, slash);
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec)
            throw std::runtime_error(
                "failed to create directory '" + dir + "': " + ec.message());
    }

    bool write_pid_file(const std::string& path) {
        if (path.empty())
            return false;
        try {
            ensure_parent_directory(path);
            std::ofstream out(path, std::ios::trunc);
            if (!out)
                return false;
#ifdef _WIN32
            out << GetCurrentProcessId() << '\n';
#else
            out << static_cast<long>(::getpid()) << '\n';
#endif
            return static_cast<bool>(out);
        } catch (...) {
            return false;
        }
    }

    void remove_pid_file(const std::string& path) {
        if (path.empty())
            return;
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }

    void setup_logger() {
        const auto stdout_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        stdout_sink->set_level(spdlog::level::trace);
        stdout_sink->set_pattern(std::string{LOGGER_PATTERN});

        // The file sink is attached by rebind_logger_sinks() after log_dir is
        // resolved. Opening one here would create microserve.log in the cwd.
        const auto logger_instance = std::make_shared<spdlog::logger>(
            std::string{LOGGER_NAME}, stdout_sink);

        logger_instance->set_level(spdlog::level::trace);
        logger_instance->flush_on(spdlog::level::err);

        spdlog::register_logger(logger_instance);
        spdlog::set_default_logger(logger_instance);
    }

    void set_logger_level(const std::string& level_name) {
        if (const auto logger = get_logger())
            logger->set_level(spdlog::level::from_str(level_name));
    }

    void rebind_logger_sinks(const std::string& file_path, const bool to_stdout) {
        const auto logger = get_logger();
        if (!logger || file_path.empty()) return;

        ensure_parent_directory(file_path);
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            file_path, LOGGER_FILE_MAX_SIZE, LOGGER_FILE_MAX_COUNT);
        file_sink->set_level(spdlog::level::trace);
        file_sink->set_pattern(std::string{LOGGER_PATTERN});

        logger->sinks().clear();
        if (to_stdout) {
            auto stdout_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            stdout_sink->set_level(spdlog::level::trace);
            stdout_sink->set_pattern(std::string{LOGGER_PATTERN});
            logger->sinks().push_back(std::move(stdout_sink));
        }
        logger->sinks().push_back(std::move(file_sink));
        logger->flush_on(spdlog::level::err);
    }

    void rebind_access_log(const std::string& file_path, const bool to_stdout) {
        if (file_path.empty())
            return;

        ensure_parent_directory(file_path);
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            file_path, LOGGER_FILE_MAX_SIZE, LOGGER_FILE_MAX_COUNT);
        file_sink->set_level(spdlog::level::info);
        file_sink->set_pattern(std::string{LOGGER_PATTERN});

        std::vector<spdlog::sink_ptr> sinks;
        if (to_stdout) {
            auto stdout_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            stdout_sink->set_level(spdlog::level::info);
            stdout_sink->set_pattern(std::string{LOGGER_PATTERN});
            sinks.push_back(std::move(stdout_sink));
        }
        sinks.push_back(std::move(file_sink));

        const auto existing = get_access_logger();
        if (existing) {
            existing->sinks() = std::move(sinks);
            existing->set_level(spdlog::level::info);
            existing->flush_on(spdlog::level::info);
            return;
        }

        const auto access = std::make_shared<spdlog::logger>(
            std::string{ACCESS_LOGGER_NAME}, sinks.begin(), sinks.end());
        access->set_level(spdlog::level::info);
        access->flush_on(spdlog::level::info);
        spdlog::register_logger(access);
    }

    void shutdown_logging() {
        spdlog::shutdown();
    }

    void log_listener_urls(const std::string &kind, const std::string &scheme,
                           const std::string &addr, unsigned short port) {
        const auto logger = get_logger();
        if (!logger) return;

        const auto& tag = g_identity;
        if (addr == "0.0.0.0")
            logger->info("[{:<11}] {} listening on {}://127.0.0.1:{}/", tag, kind, scheme, port);
        else if (addr == "::")
            logger->info("[{:<11}] {} listening on {}://[::1]:{}/", tag, kind, scheme, port);
        else
            logger->info("[{:<11}] {} listening on {}://{}:{}/", tag, kind, scheme, addr, port);
    }

} // namespace microserve
