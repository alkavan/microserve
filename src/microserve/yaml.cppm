// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

module;

#include <nlohmann/json.hpp>

#include <format>
#include <fstream>
#include <istream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

export module microserve.yaml;

export namespace microserve::yaml
{
    /**
     * @brief True if @p s is an IPv6 literal, with or without `[]`.
     */
    bool is_ipv6_literal(std::string_view s) {
        if (s.size() >= 2 && s.front() == '[' && s.back() == ']')
            s = s.substr(1, s.size() - 2);
        if (s.empty())
            return false;
        return std::ranges::count(s, ':') >= 2;
    }

    /**
     * @brief True if @p s is a dotted-quad IPv4 literal.
     */
    bool is_ipv4_literal(const std::string_view s) {
        int dots = 0;
        std::string octet;
        auto flush = [&](const std::string_view o) {
            if (o.empty() || o.size() > 3)
                return false;
            for (const char c : o) {
                if (c < '0' || c > '9')
                    return false;
            }
            const int v = std::stoi(std::string{o});
            return v >= 0 && v <= 255;
        };
        for (const char c : s) {
            if (c == '.') {
                if (!flush(octet))
                    return false;
                octet.clear();
                ++dots;
            } else if (c >= '0' && c <= '9') {
                octet.push_back(c);
            } else {
                return false;
            }
        }
        return dots == 3 && flush(octet);
    }

    /**
     * @brief True if @p s is an IPv4 or IPv6 literal.
     */
    bool is_ip_literal(const std::string_view s) {
        return is_ipv4_literal(s) || is_ipv6_literal(s);
    }

    /**
     * @brief Line-oriented YAML parser that emits JSON.
     *
     * Walks preprocessed lines, tracks indentation, and builds mappings,
     * sequences, scalars, and embedded JSON blocks.
     */
    class yaml_parser {
        private:
        std::vector<std::string> lines;
        size_t current_line = 0;

        /**
         * @brief Strip comments and trailing whitespace from the input stream.
         *
         * Splits @p input into lines while keeping the original line breaks
         * otherwise intact.
         *
         * @param input Raw YAML stream to preprocess.
         */
        void preprocess_input(std::istream& input) {
            std::string line;
            while (std::getline(input, line)) {
                // Remove comments
                if (const size_t comment_pos = line.find('#'); comment_pos != std::string::npos) {
                    line = line.substr(0, comment_pos);
                }
                // Remove trailing whitespace (handle whitespace-only lines safely)
                if (!line.empty()) {
                    if (const auto last = line.find_last_not_of(" \t\r\n"); last != std::string::npos) {
                        line.erase(last + 1);
                    } else {
                        line.clear();
                    }
                }

                // Keep all lines, including empty ones, to maintain the line structure
                lines.push_back(line);
            }
        }

        /**
         * @brief Calculates the indentation level of a given line based on spaces and tabs.
         *
         * @param line The string for which the indentation level needs to be calculated.
         * @return The total indentation count, treating spaces as 1 unit and tabs as 2 units by default.
         */
        static int get_indent(const std::string& line) {
            int indent = 0;
            for (const char i : line) {
                if (i == ' ') {
                    indent++;
                } else if (i == '\t') {
                    indent += 2;  // Treat tab as 2 spaces (adjust to 4 or 8 if preferred based on convention)
                } else {
                    break;
                }
            }
            return indent;
        }

        /**
         * @brief Next indentation deeper than the parent, starting at a given line.
         *
         * Determines the next line's indentation level that is greater than the parent indentation,
         * starting from a specified line index. Skips empty lines and stops search at the first
         * line with an indentation level that does not match the condition.
         *
         * @param start_line The index of the line to start checking from.
         * @param parent_indent The indentation level of the parent line used as a reference.
         * @return The indentation level of the next suitable line if it exists; otherwise, returns -1.
         */
        [[nodiscard]] int get_next_sub_indent(const size_t start_line, const int parent_indent) const {
            size_t peek = start_line;
            while (peek < lines.size()) {
                const std::string& p_line = lines[peek];

                if (p_line.empty()) {
                    ++peek;
                    continue;
                }

                if (const int p_indent = get_indent(p_line); p_indent > parent_indent) {
                    return p_indent;
                }

                return -1;
            }
            return -1;
        }

        /**
         * @brief Parse a JSON array from a string.
         *
         * Parses a JSON array from a given string and returns the corresponding JSON object.
         * The input string must represent a valid JSON array syntax.
         *
         * @param str The string containing the JSON array to parse.
         * @return A JSON object representing the parsed array.
         * @throws std::runtime_error If the input string is not a valid JSON array.
         */
        static nlohmann::json parse_json_array(const std::string& str) {
            try {
                return nlohmann::json::parse(str);
            } catch (...) {
                throw std::runtime_error("Invalid JSON array syntax: " + str);
            }
        }

        /**
         * @brief Parse a JSON object from a string.
         *
         * Parses a JSON object from a given string and returns the corresponding JSON representation.
         * The input string must represent a valid JSON object syntax.
         *
         * @param str The string containing the JSON object to parse.
         * @return A JSON object representing the parsed input string.
         * @throws std::runtime_error If the input string is not a valid JSON object.
         */
        static nlohmann::json parse_json_object(const std::string& str) {
            try {
                return nlohmann::json::parse(str);
            } catch (...) {
                throw std::runtime_error("Invalid JSON object syntax: " + str);
            }
        }

        /**
         * @brief Check whether a string looks like a JSON array.
         *
         * Determines whether the provided string represents a valid JSON array.
         * A valid JSON array is identified by being non-empty, trimmed of leading
         * and trailing whitespace, and starting with '[' and ending with ']'.
         *
         * @param str The string to check for JSON array syntax.
         * @return True if the string represents a JSON array, otherwise false.
         */
        static bool is_json_array(const std::string& str) {
            std::string trimmed = str;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            trimmed.erase(trimmed.find_last_not_of(" \t") + 1);
            return !trimmed.empty() && trimmed.front() == '[' && trimmed.back() == ']';
        }

        /**
         * @brief Check whether a string looks like a JSON object.
         *
         * Determines whether the provided string represents a valid JSON object.
         * A valid JSON object is identified by being non-empty, trimmed of leading
         * and trailing whitespace, and starting with '{' and ending with '}'.
         *
         * @param str The string to check for JSON object syntax.
         * @return True if the string represents a JSON object, otherwise false.
         */
        static bool is_json_object(const std::string& str) {
            std::string trimmed = str;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            trimmed.erase(trimmed.find_last_not_of(" \t") + 1);
            return !trimmed.empty() && trimmed.front() == '{' && trimmed.back() == '}';
        }

        /**
         * @brief Check whether a string starts with a JSON array or object token.
         *
         * Determines whether the given string starts with a JSON token
         * after ignoring leading whitespace.
         *
         * @param str The input string to analyze.
         * @return True if the string starts with a '[' or '{' character after
         *         whitespace is trimmed; otherwise, false.
         */
        static bool starts_with_json_token(const std::string& str) {
            const size_t i = str.find_first_not_of(" \t");
            if (i == std::string::npos) return false;
            const char c = str[i];
            return c == '[' || c == '{';
        }

        /**
         * @brief Collect a contiguous JSON object or array from the current lines.
         *
         * Starting at @p current_indent, gathers a block that begins with `{` or `[`
         * and has balanced braces/brackets, ignoring those inside strings and
         * escape sequences.
         *
         * @param current_indent Indentation expected for the first line of the block.
         * @param[out] out_json  Receives the collected JSON text on success.
         * @return `true` if a complete JSON block was collected; otherwise `false`.
         */
        bool try_collect_json_block(const int current_indent, std::string& out_json) {
            const size_t saved_line = current_line;

            size_t i = current_line;
            bool started = false;

            int curly = 0;
            int square = 0;
            bool in_string = false;
            char quote_char = '\0';
            bool escape = false;

            std::string buffer;

            while (i < lines.size()) {
                const std::string& raw = lines[i];

                // Skip empty lines before we start
                if (!started && raw.empty()) {
                    i++;
                    continue;
                }

                const int indent = get_indent(raw);

                // If we haven't started yet, ensure this line is at the expected indent and starts with { or [
                if (!started) {
                    if (indent != current_indent) {
                        break;
                    }
                    std::string content = raw.substr(indent);
                    // Trim leading spaces for start check
                    const size_t s = content.find_first_not_of(" \t");
                    if (s == std::string::npos) {
                        // nothing meaningful on this line
                        i++;
                        continue;
                    }
                    if (const char first = content[s]; first != '{' && first != '[') {
                        // Not a JSON block start
                        break;
                    }
                    started = true;
                }

                // Once started, lines with indent less than current_indent terminate unless we already balanced
                if (started && indent < current_indent) {
                    break;
                }

                const std::string content = raw.substr(indent);

                // Append content to buffer (newline separates lines; JSON allows whitespace)
                if (!buffer.empty()) {
                    buffer.push_back('\n');
                }
                buffer.append(content);

                // Scan content to update bracket/brace counters while respecting strings
                for (const char c : content) {
                    if (in_string) {
                        if (escape) {
                            escape = false;
                        } else if (c == '\\') {
                            escape = true;
                        } else if (c == quote_char) {
                            in_string = false;
                        }
                    } else {
                        if (c == '"' || c == '\'') {
                            in_string = true;
                            quote_char = c;
                        } else if (c == '{') {
                            ++curly;
                        } else if (c == '}') {
                            --curly;
                        } else if (c == '[') {
                            ++square;
                        } else if (c == ']') {
                            --square;
                        }
                    }
                }

                ++i;

                if (started && curly <= 0 && square <= 0) {
                    // Completed a JSON value
                    current_line = i;
                    out_json = buffer;
                    return true;
                }
            }

            // Not a valid/complete JSON block – restore and signal failure
            current_line = saved_line;
            return false;
        }

        /**
         * @brief Parse a YAML scalar into a JSON value.
         *
         * Interprets @p value as a string, number, boolean, null, or a special YAML
         * scalar (quoted strings and escape sequences included).
         *
         * @param value Scalar text to convert.
         * @return JSON value of the matching type.
         */
        static nlohmann::json parse_scalar(const std::string& value) {
            std::string val = value;

            // Remove leading/trailing whitespace
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);

            // Check for JSON array syntax
            if (is_json_array(val)) {
                return parse_json_array(val);
            }

            // Check for JSON object syntax
            if (is_json_object(val)) {
                return parse_json_object(val);
            }

            // Remove quotes if present
            if (!val.empty() && ((val.front() == '"' && val.back() == '"') ||
                                (val.front() == '\'' && val.back() == '\''))) {
                val = val.substr(1, val.size() - 2);
                // Handle escaped characters in quoted strings
                std::string result;
                for (size_t i = 0; i < val.size(); ++i) {
                    if (val[i] == '\\' && i + 1 < val.size()) {
                        switch (val[i + 1]) {
                            case 'n': result += '\n'; break;
                            case 't': result += '\t'; break;
                            case 'r': result += '\r'; break;
                            case '\\': result += '\\'; break;
                            case '"': result += '"'; break;
                            case '\'': result += '\''; break;
                            default: result += val[i + 1]; break;
                        }
                        ++i; // skip the escaped character
                    } else {
                        result += val[i];
                    }
                }
                return result;
            }

            // Handle special YAML values
            if (val == "null" || val == "~" || val == "Null" || val == "NULL") return nullptr;
            if (val == "true" || val == "True" || val == "TRUE") return true;
            if (val == "false" || val == "False" || val == "FALSE") return false;

            // Handle special float values
            if (val == ".inf" || val == ".Inf" || val == ".INF" || val == "+.inf") {
                return std::numeric_limits<double>::infinity();
            }

            if (val == "-.inf" || val == "-.Inf" || val == "-.INF") {
                return -std::numeric_limits<double>::infinity();
            }

            if (val == ".nan" || val == ".NaN" || val == ".NAN") {
                return std::numeric_limits<double>::quiet_NaN();
            }

            // Try parsing as different number formats. Require the entire
            // token to be consumed so values like 127.0.0.1:9191 stay strings.
            try {
                if (val.size() > 2 && val[0] == '0') {
                    if (val[1] == 'x' || val[1] == 'X') {
                        size_t idx = 0;
                        const int n = std::stoi(val, &idx, 16);
                        if (idx == val.size())
                            return n;
                    } else if (val[1] == 'o' || val[1] == 'O') {
                        size_t idx = 0;
                        const int n = std::stoi(val.substr(2), &idx, 8);
                        if (idx == val.size() - 2)
                            return n;
                    } else if (val[1] == 'b' || val[1] == 'B') {
                        size_t idx = 0;
                        const int n = std::stoi(val.substr(2), &idx, 2);
                        if (idx == val.size() - 2)
                            return n;
                    }
                }

                if (val.find('.') != std::string::npos
                    || val.find('e') != std::string::npos
                    || val.find('E') != std::string::npos) {
                    size_t idx = 0;
                    const double d = std::stod(val, &idx);
                    if (idx == val.size())
                        return d;
                } else {
                    size_t idx = 0;
                    const long long n = std::stoll(val, &idx);
                    if (idx == val.size())
                        return n;
                }
            } catch (...) {
            }
            return val; // Return as string
        }

        /**
         * @brief Parse a YAML sequence into a JSON array.
         *
         * Reads list items from the current line onward, using @p current_indent to
         * decide where the sequence ends.
         *
         * @param current_indent Indentation that bounds this sequence.
         * @return JSON array of the parsed items.
         * @throws std::runtime_error On invalid YAML sequence syntax.
         */
        nlohmann::json parse_sequence(const int current_indent) {
            nlohmann::json array = nlohmann::json::array();

            while (current_line < lines.size()) {
                const std::string& line = lines[current_line];

                // Skip empty lines
                if (line.empty()) {
                    current_line++;
                    continue;
                }

                const int line_indent = get_indent(line);

                // If indentation is less than the current level, we're done
                if (line_indent < current_indent) {
                    break;
                }

                // If indentation doesn't match, break
                if (line_indent != current_indent) {
                    break;
                }

                // Check if this is a sequence item
                if (line[line_indent] != '-') {
                    break;
                }

                current_line++;

                // Extract the value after the dash
                std::string value = line.substr(line_indent + 1);
                value.erase(0, value.find_first_not_of(" \t"));

                if (value.empty()) {
                    // Complex value on next line(s)
                    int sub_indent = get_next_sub_indent(current_line, current_indent);
                    if (sub_indent == -1) {
                        throw std::runtime_error("Expected indented block for sequence item at line "
                            + std::to_string(current_line - 1));
                    }
                    nlohmann::json sub = parse_value(sub_indent);
                    if (sub.is_null()) {
                        throw std::runtime_error("Failed to parse block for sequence item at line "
                            + std::to_string(current_line - 1));
                    }
                    array.push_back(sub);
                } else if (!value.empty() && value[0] == '-') {
                    // Inline nested sequence - handle specially
                    nlohmann::json nested_array = nlohmann::json::array();

                    // Parse the current line as nested sequence items
                    std::string remaining = value;
                    while (!remaining.empty() && remaining[0] == '-') {
                        remaining = remaining.substr(1); // Remove the dash
                        remaining.erase(0, remaining.find_first_not_of(" \t"));

                        // Find the next dash or end of line
                        size_t next_dash = remaining.find(" -");
                        std::string item_value;
                        if (next_dash != std::string::npos) {
                            item_value = remaining.substr(0, next_dash);
                            remaining = remaining.substr(next_dash + 1);
                            remaining.erase(0, remaining.find_first_not_of(" \t"));
                        } else {
                            item_value = remaining;
                            remaining.clear();
                        }

                        if (!item_value.empty()) {
                            nested_array.push_back(parse_scalar(item_value));
                        }
                    }

                    // Now check for continuation lines at higher indentation
                    int sub_indent = -1;
                    while (current_line < lines.size()) {
                        const std::string& next_line = lines[current_line];
                        if (next_line.empty()) {
                            current_line++;
                            continue;
                        }

                        const int next_indent = get_indent(next_line);
                        if (next_indent <= current_indent) {
                            break; // End of this nested sequence
                        }

                        if (next_line[next_indent] == '-') {
                            if (sub_indent == -1) {
                                sub_indent = next_indent;
                            } else if (next_indent != sub_indent) {
                                throw std::runtime_error(
                                    "Inconsistent indentation in nested sequence continuation at line "
                                    + std::to_string(current_line));
                            }
                            current_line++;
                            std::string next_value = next_line.substr(next_indent + 1);
                            next_value.erase(0, next_value.find_first_not_of(" \t"));
                            nested_array.push_back(parse_scalar(next_value));
                        } else {
                            break;
                        }
                    }

                    array.push_back(nested_array);
                } else if (value.find(':') != std::string::npos) {
                    // Unquoted IPv4 host:port (backend/listen) is a scalar, not `- path: /`.
                    const size_t colon_pos = value.find(':');
                    std::string maybe_host = value.substr(0, colon_pos);
                    if (const auto last = maybe_host.find_last_not_of(" \t"); last != std::string::npos)
                        maybe_host.erase(last + 1);
                    else
                        maybe_host.clear();
                    std::string maybe_port = value.substr(colon_pos + 1);
                    maybe_port.erase(0, maybe_port.find_first_not_of(" \t"));
                    bool port_digits = !maybe_port.empty();
                    for (const char c : maybe_port) {
                        if (c < '0' || c > '9') {
                            port_digits = false;
                            break;
                        }
                    }
                    if (is_ipv4_literal(maybe_host) && port_digits) {
                        array.push_back(parse_scalar(value));
                        continue;
                    }

                    // Inline mapping
                    nlohmann::json obj = nlohmann::json::object();

                    // Parse the first key-value pair from the current line
                    std::string key = value.substr(0, colon_pos);
                    key.erase(key.find_last_not_of(" \t") + 1);

                    std::string val = value.substr(colon_pos + 1);
                    val.erase(0, val.find_first_not_of(" \t"));

                    if (val.empty()) {
                        int sub_indent = get_next_sub_indent(current_line, current_indent);
                        if (sub_indent == -1) {
                            throw std::runtime_error("Expected indented block for key '" + key
                                + "' at line " + std::to_string(current_line - 1));
                        }
                        nlohmann::json sub = parse_value(sub_indent);
                        if (sub.is_null()) {
                            throw std::runtime_error("Failed to parse block for key '" + key
                                + "' at line " + std::to_string(current_line - 1));
                        }
                        obj[key] = sub;
                    } else {
                        obj[key] = parse_scalar(val);
                    }

                    // Now check for additional key-value pairs at a consistent higher indentation
                    int key_indent = -1;
                    while (current_line < lines.size()) {
                        const std::string& next_line = lines[current_line];
                        if (next_line.empty()) {
                            current_line++;
                            continue;
                        }

                        const int next_indent = get_indent(next_line);

                        // If indentation is less than or equal to sequence item level, we're done
                        if (next_indent <= current_indent) {
                            break;
                        }

                        // Must have a colon to be a mapping entry
                        size_t next_colon_pos = next_line.find(':');
                        if (next_colon_pos == std::string::npos) {
                            break;
                        }

                        // Set or check consistent key indentation
                        if (key_indent == -1) {
                            key_indent = next_indent;
                        } else if (next_indent != key_indent) {
                            break;
                        }

                        current_line++;

                        std::string next_key = next_line.substr(next_indent, next_colon_pos - next_indent);
                        next_key.erase(next_key.find_last_not_of(" \t") + 1);

                        std::string next_val = next_line.substr(next_colon_pos + 1);
                        next_val.erase(0, next_val.find_first_not_of(" \t"));

                        if (next_val.empty()) {
                            int next_sub_indent = get_next_sub_indent(current_line, key_indent);
                            if (next_sub_indent == -1) {
                                throw std::runtime_error("Expected indented block for key '" + next_key
                                    + "' at line " + std::to_string(current_line - 1));
                            }
                            nlohmann::json next_sub = parse_value(next_sub_indent);
                            if (next_sub.is_null()) {
                                throw std::runtime_error("Failed to parse block for key '" + next_key
                                    + "' at line " + std::to_string(current_line - 1));
                            }
                            obj[next_key] = next_sub;
                        } else {
                            obj[next_key] = parse_scalar(next_val);
                        }
                    }

                    array.push_back(obj);
                } else {
                    // Simple scalar value (including JSON arrays and objects)
                    array.push_back(parse_scalar(value));
                }
            }

            return array;
        }

        /**
         * @brief Parse a YAML mapping into a JSON object.
         *
         * Reads key/value pairs from the current line onward, using @p current_indent
         * to bound the mapping and to nest further mappings or sequences.
         *
         * @param current_indent Indentation that bounds this mapping.
         * @return JSON object of the parsed keys and values.
         * @throws std::runtime_error On missing nested blocks or invalid mapping syntax.
         */
        nlohmann::json parse_mapping(const int current_indent) {
            nlohmann::json object = nlohmann::json::object();

            while (current_line < lines.size()) {
                const std::string& line = lines[current_line];

                // Skip empty lines
                if (line.empty()) {
                    current_line++;
                    continue;
                }

                const int line_indent = get_indent(line);

                // If indentation is less than the current level, we're done
                if (line_indent < current_indent) {
                    break;
                }

                // If indentation doesn't match the current level, break
                if (line_indent != current_indent) {
                    break;
                }

                // Look for key-value separator
                const size_t colon_pos = line.find(':');
                if (colon_pos == std::string::npos) {
                    break; // Not a mapping line
                }

                current_line++;

                // Extract key and value
                std::string key = line.substr(line_indent, colon_pos - line_indent);
                key.erase(key.find_last_not_of(" \t") + 1);

                std::string value = line.substr(colon_pos + 1);
                value.erase(0, value.find_first_not_of(" \t"));

                if (value.empty()) {
                    // Complex value on next line(s)
                    const int sub_indent = get_next_sub_indent(current_line, current_indent);
                    if (sub_indent == -1) {
                        throw std::runtime_error("Expected indented block for key '" + key
                            + "' at line " + std::to_string(current_line - 1));
                    }
                    nlohmann::json sub = parse_value(sub_indent);
                    if (sub.is_null()) {
                        throw std::runtime_error("Failed to parse block for key '" + key
                            + "' at line " + std::to_string(current_line - 1));
                    }
                    object[key] = sub;
                } else {
                    // Simple scalar value (including JSON arrays and objects)
                    object[key] = parse_scalar(value);
                }
            }

            return object;
        }

        /**
         * @brief Parse the next YAML value at the given indent.
         *
         * Dispatches on the current line to a scalar, sequence, mapping, or JSON
         * block. Deeper lines are nested; shallower lines end this value.
         *
         * @param current_indent Expected indent for this value.
         * @return JSON for the parsed value, or `nullptr` if none remains.
         */
        nlohmann::json parse_value(const int current_indent) {
            while (current_line < lines.size()) {
                const std::string& line = lines[current_line];

                // Skip empty lines
                if (line.empty()) {
                    current_line++;
                    continue;
                }

                const int line_indent = get_indent(line);

                // If indentation is less than expected, return null
                if (line_indent < current_indent) {
                    return nullptr;
                }

                // If indentation matches, determine the type
                if (line_indent == current_indent) {
                    const std::string at_level = line.substr(line_indent);

                    // If this line starts with a JSON token, try to parse a (potentially multi-line) JSON block
                    if (starts_with_json_token(at_level)) {
                        const size_t saved = current_line;
                        if (std::string json_text; try_collect_json_block(current_indent, json_text)) {
                            try {
                                return nlohmann::json::parse(json_text);
                            } catch (...) {
                                // If parsing fails, revert and fall through to other handlers
                                current_line = saved;
                            }
                        }
                    }

                    if (line[line_indent] == '-') {
                        return parse_sequence(current_indent);
                    } else if (line.find(':') != std::string::npos) {
                        return parse_mapping(current_indent);
                    } else {
                        current_line++;
                        return parse_scalar(at_level);
                    }
                } else {
                    // Skip lines with greater indentation until we find our level
                    current_line++;
                    continue;
                }
            }

            return nullptr;
        }

    public:
        /**
         * @brief Construct a parser from a YAML input stream.
         *
         * Reads @p is and preprocesses it so subsequent parse calls can walk the
         * prepared lines.
         *
         * @param is Stream of raw YAML text.
         */
        explicit yaml_parser(std::istream& is) {
            preprocess_input(is);
        }

        /**
         * @brief Parse the preprocessed YAML document into JSON.
         *
         * Walks the prepared lines and builds mappings, sequences, and scalars
         * (including nested structures).
         *
         * @return JSON object for the document root.
         * @throws std::runtime_error If the YAML structure is invalid.
         */
        nlohmann::json parse() {
            nlohmann::json root = nlohmann::json::object();
            current_line = 0;

            while (current_line < lines.size()) {
                const std::string& line = lines[current_line];

                // Skip empty lines
                if (line.empty()) {
                    current_line++;
                    continue;
                }

                const int line_indent = get_indent(line);

                // Check if this is a sequence at the root level
                if (line[0] == '-') {
                    if (root.empty()) {
                        return parse_sequence(0);
                    } else {
                        throw std::runtime_error("Cannot mix sequences and mappings at root level");
                    }
                }

                // Look for mapping
                const size_t colon_pos = line.find(':');
                if (colon_pos == std::string::npos) {
                    current_line++;
                    continue; // Skip lines that aren't key-value pairs
                }

                // Extract key and value
                std::string key = line.substr(line_indent, colon_pos - line_indent);
                key.erase(key.find_last_not_of(" \t") + 1);

                std::string value = line.substr(colon_pos + 1);
                value.erase(0, value.find_first_not_of(" \t"));

                current_line++;

                if (value.empty()) {
                    // Complex value on next line(s)
                    const int sub_indent = get_next_sub_indent(current_line, line_indent);
                    if (sub_indent == -1) {
                        throw std::runtime_error("Expected indented block for key '" + key
                            + "' at line " + std::to_string(current_line - 1));
                    }

                    nlohmann::json sub = parse_value(sub_indent);
                    if (sub.is_null()) {
                        throw std::runtime_error("Failed to parse block for key '" + key
                            + "' at line " + std::to_string(current_line - 1));
                    }

                    root[key] = sub;
                } else {
                    // Simple scalar value (including JSON arrays and objects)
                    root[key] = parse_scalar(value);
                }
            }

            return root;
        }
    };

    /**
     * @brief Parse YAML from an input stream into JSON.
     *
     * @param input Stream of YAML text.
     * @return JSON object for the parsed document.
     */
    nlohmann::json parse_yaml(std::istream& input) {
        yaml_parser parser(input);
        return parser.parse();
    }

    /**
     * @brief Parse YAML from a string into JSON.
     *
     * @param input YAML text.
     * @return JSON object for the parsed document.
     */
    nlohmann::json parse_yaml(const std::string& input) {
        std::istringstream iss(input);
        return parse_yaml(iss);
    }

    /**
     * @brief Convert a JSON scalar to a string.
     *
     * Strings are returned as-is. Integers, unsigned integers, and floats are
     * formatted with `std::to_string`. A single-key object is treated as a
     * `host:port` pair (YAML sequence items such as `- 127.0.0.1:9934`).
     *
     * @param v JSON value to convert.
     * @return String representation of @p v.
     * @throws std::runtime_error If @p v is not a string, number, or one-key object.
     */
    std::string json_to_string(const nlohmann::json& v) {
        if (v.is_string())
            return v.get<std::string>();
        if (v.is_number_integer())
            return std::to_string(v.get<long long>());
        if (v.is_number_unsigned())
            return std::to_string(v.get<unsigned long long>());
        if (v.is_number_float())
            return std::to_string(v.get<double>());
        // Sequence items such as `- 127.0.0.1:9934` used to parse as a
        // one-key mapping because of the colon. Rebuild host:port.
        if (v.is_object() && v.size() == 1) {
            const auto it = v.begin();
            return it.key() + ":" + json_to_string(it.value());
        }
        throw std::runtime_error("expected string or number, got " + v.dump());
    }

    /**
     * @brief Convert a JSON value to a boolean.
     *
     * Accepts JSON booleans, YAML-style strings (`true`/`false`, `on`/`off`,
     * `yes`/`no`, any common capitalisation), and integers (non-zero is true).
     *
     * @param v        JSON value to convert.
     * @param fallback Value used when @p v has no recognised boolean form.
     * @return Converted boolean, or @p fallback.
     */
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

} // namespace microserve
