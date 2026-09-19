// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <string>
#include <string_view>

export module microserve.logging;

export namespace microserve {
    // Logging constants
    inline constexpr std::string_view LOGGER_NAME      = "microserve";
    inline constexpr std::string_view LOGGER_PATTERN   = "[%Y-%m-%d %H:%M:%S.%e] [%^%-7l%$] %v";
    inline constexpr std::size_t LOGGER_QUEUE_SIZE     = 32768;
    inline constexpr int LOGGER_THREAD_COUNT           = 1;
    inline constexpr std::size_t LOGGER_FILE_MAX_SIZE  = 10 * 1024 * 1024;
    inline constexpr int LOGGER_FILE_MAX_COUNT         = 3;

    // Logging functions
    void log_info(std::string_view msg);
    void log_warn(std::string_view msg);
    void log_error(std::string_view msg);
    void log_debug(std::string_view msg);
    void log_access(std::string_view msg);
    void logger_flush();
    void setup_logger();
    void set_logger_level(const std::string& level_name);
    void set_logger_identity(std::string_view tag);
    std::string logger_identity();
    std::string site_error_log_path(std::string_view base_path, std::string_view site_name);
    void rebind_logger_sinks(const std::string& file_path, bool to_stdout = true);
    void rebind_access_log(const std::string& file_path, bool to_stdout = false);
    void shutdown_logging();

    /** @brief True for a leading slash or a Windows drive path (`C:/...`). */
    bool path_is_absolute(std::string_view path);

    /**
     * @brief Directory containing the running executable.
     * @return `"."` if the executable path cannot be determined.
     */
    std::string executable_directory();

    /**
     * @brief Join @p dir and @p child. An absolute @p child is returned unchanged.
     */
    std::string join_path(std::string_view dir, std::string_view child);

    /**
     * @brief Create the parent directory of @p file_path when it is missing.
     * @throws std::runtime_error If the directory cannot be created.
     */
    void ensure_parent_directory(const std::string& file_path);

    /**
     * @brief Write this process id to @p path, creating parent directories.
     * @return false if the file cannot be created.
     */
    bool write_pid_file(const std::string& path);

    /** @brief Remove a pid file created by @ref write_pid_file. */
    void remove_pid_file(const std::string& path);

    /**
    * @brief Log a human-readable listener URL for a started server.
    *
    * Wildcard binds are rewritten to loopback so the log line is directly
    * usable in a browser or client:
    * - `0.0.0.0` -> `127.0.0.1`
    * - `::`      -> `[::1]`
    *
    * Other addresses are logged as given. No-op if the microserve logger
    * has not been registered yet.
    *
    * @param kind   Short protocol label.
    * @param scheme URI scheme without `://` (e.g. `"http"`, `"https"`).
    * @param addr   Bound address string (`0.0.0.0`, `::`, or a specific host).
    * @param port   Bound TCP/UDP port.
    */
    void log_listener_urls(const std::string &kind, const std::string &scheme,
                           const std::string &addr, unsigned short port);
} // namespace microserve
