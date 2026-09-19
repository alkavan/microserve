// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

import microserve.core;
import microserve.yaml;

namespace {

struct TempFile {
    std::string path;

    explicit TempFile(const std::string& contents, std::string name = "microserve_yaml_test.yaml")
        : path(std::move(name))
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << contents;
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    ~TempFile()
    {
        std::remove(path.c_str());
    }
};

} // namespace

TEST_CASE("parse_yaml maps simple key-value pairs", "[yaml][mapping]")
{
    const auto j = microserve::yaml::parse_yaml("name: microserve\nport: 8080\n");
    REQUIRE(j.is_object());
    REQUIRE(j.contains("name"));
    REQUIRE(j.contains("port"));
    REQUIRE(j.at("name") == "microserve");
    REQUIRE(j.at("port") == 8080);
}

TEST_CASE("parse_yaml strips comments and blank lines", "[yaml][comments]")
{
    const auto j = microserve::yaml::parse_yaml(
        "# header comment\n"
        "\n"
        "key: value # inline comment\n"
        "\n"
        "other: 1\n");
    REQUIRE(j.at("key") == "value");
    REQUIRE(j.at("other") == 1);
}

TEST_CASE("parse_yaml parses nested mappings", "[yaml][mapping]")
{
    const auto j = microserve::yaml::parse_yaml(
        "server:\n"
        "  listen: 443\n"
        "  tls:\n"
        "    cert: server.crt\n"
        "    key: server.key\n");
    REQUIRE(j.contains("server"));
    REQUIRE(j.at("server").at("listen") == 443);
    REQUIRE(j.at("server").at("tls").at("cert") == "server.crt");
    REQUIRE(j.at("server").at("tls").at("key") == "server.key");
}

TEST_CASE("parse_yaml parses sequences and nested mappings in sequences", "[yaml][sequence]")
{
    const auto j = microserve::yaml::parse_yaml(
        "indexes:\n"
        "  - index.html\n"
        "  - index.htm\n"
        "locations:\n"
        "  - path: /\n"
        "    root: public\n"
        "  - path: /api\n"
        "    proxy_pass: http://127.0.0.1:9000\n");

    REQUIRE(j.at("indexes").is_array());
    REQUIRE(j.at("indexes").size() == 2);
    REQUIRE(j.at("indexes").at(0) == "index.html");
    REQUIRE(j.at("indexes").at(1) == "index.htm");
    REQUIRE(j.at("locations").size() == 2);
    REQUIRE(j.at("locations").at(0).at("path") == "/");
    REQUIRE(j.at("locations").at(0).at("root") == "public");
    REQUIRE(j.at("locations").at(1).at("proxy_pass") == "http://127.0.0.1:9000");
}

TEST_CASE("parse_yaml accepts a root-level sequence", "[yaml][sequence]")
{
    const auto j = microserve::yaml::parse_yaml("- red\n- green\n- blue\n");
    REQUIRE(j.is_array());
    REQUIRE(j.size() == 3);
    REQUIRE(j.at(0) == "red");
    REQUIRE(j.at(2) == "blue");
}

TEST_CASE("parse_yaml parses booleans, null, and numbers", "[yaml][scalar]")
{
    const auto j = microserve::yaml::parse_yaml(
        "t1: true\n"
        "t2: True\n"
        "t3: TRUE\n"
        "f1: false\n"
        "f2: False\n"
        "n1: null\n"
        "n2: ~\n"
        "n3: NULL\n"
        "i: 42\n"
        "neg: -7\n"
        "flt: 3.5\n"
        "sci: 1e3\n"
        "hex: 0x10\n"
        "oct: 0o10\n"
        "bin: 0b10\n");

    REQUIRE(j.at("t1") == true);
    REQUIRE(j.at("t2") == true);
    REQUIRE(j.at("t3") == true);
    REQUIRE(j.at("f1") == false);
    REQUIRE(j.at("f2") == false);
    REQUIRE(j.at("n1").is_null());
    REQUIRE(j.at("n2").is_null());
    REQUIRE(j.at("n3").is_null());
    REQUIRE(j.at("i") == 42);
    REQUIRE(j.at("neg") == -7);
    REQUIRE(j.at("flt") == 3.5);
    REQUIRE(j.at("sci") == 1000.0);
    REQUIRE(j.at("hex") == 16);
    REQUIRE(j.at("oct") == 8);
    REQUIRE(j.at("bin") == 2);
}

TEST_CASE("parse_yaml parses quoted strings and escape sequences", "[yaml][scalar]")
{
    const auto j = microserve::yaml::parse_yaml(
        "dq: \"hello\\nworld\"\n"
        "sq: 'plain'\n"
        "colon: \"a: b\"\n");
    REQUIRE(j.at("dq").get<std::string>().find('\n') != std::string::npos);
    REQUIRE(j.at("sq") == "plain");
    REQUIRE(j.at("colon") == "a: b");
}

TEST_CASE("parse_yaml parses special float values", "[yaml][scalar]")
{
    const auto j = microserve::yaml::parse_yaml(
        "pinf: .inf\n"
        "ninf: -.inf\n"
        "nan: .nan\n");
    REQUIRE(std::isinf(j.at("pinf").get<double>()));
    REQUIRE(j.at("pinf").get<double>() > 0);
    REQUIRE(std::isinf(j.at("ninf").get<double>()));
    REQUIRE(j.at("ninf").get<double>() < 0);
    REQUIRE(std::isnan(j.at("nan").get<double>()));
}

TEST_CASE("parse_yaml accepts inline JSON arrays and objects", "[yaml][json]")
{
    const auto j = microserve::yaml::parse_yaml(
        "arr: [1, 2, 3]\n"
        "obj: {\"a\": 1, \"b\": \"x\"}\n");
    REQUIRE(j.at("arr").is_array());
    REQUIRE(j.at("arr").size() == 3);
    REQUIRE(j.at("arr").at(0) == 1);
    REQUIRE(j.at("arr").at(1) == 2);
    REQUIRE(j.at("arr").at(2) == 3);
    REQUIRE(j.at("obj").at("a") == 1);
    REQUIRE(j.at("obj").at("b") == "x");
}

TEST_CASE("parse_yaml accepts a multi-line JSON block", "[yaml][json]")
{
    const auto j = microserve::yaml::parse_yaml(
        "data:\n"
        "  {\n"
        "    \"enabled\": true,\n"
        "    \"count\": 2\n"
        "  }\n");
    REQUIRE(j.at("data").at("enabled") == true);
    REQUIRE(j.at("data").at("count") == 2);
}

TEST_CASE("parse_yaml treats two-space indent as a nested mapping", "[yaml][indent]")
{
    const auto j = microserve::yaml::parse_yaml("parent:\n  child: 1\n");
    REQUIRE(j.contains("parent"));
    REQUIRE(j.at("parent").contains("child"));
    REQUIRE(j.at("parent").at("child") == 1);
}

TEST_CASE("parse_yaml empty input yields an empty object", "[yaml]")
{
    const auto j = microserve::yaml::parse_yaml("");
    REQUIRE(j.is_object());
    REQUIRE(j.empty());
}

TEST_CASE("parse_yaml throws when a mapping key has no indented block", "[yaml][error]")
{
    REQUIRE_THROWS_AS(microserve::yaml::parse_yaml("foo:\nbar: 1\n"), std::runtime_error);
}

TEST_CASE("parse_yaml throws when root sequences and mappings are mixed", "[yaml][error]")
{
    REQUIRE_THROWS_AS(microserve::yaml::parse_yaml("foo: 1\n- bar\n"), std::runtime_error);
}

TEST_CASE("parse_yaml throws on invalid inline JSON", "[yaml][error]")
{
    REQUIRE_THROWS_AS(microserve::yaml::parse_yaml("arr: [1, 2,]\n"), std::runtime_error);
}

TEST_CASE("parse_yaml istream overload matches the string overload", "[yaml]")
{
    const std::string text = "a: 1\nb: two\n";
    std::istringstream in(text);
    REQUIRE(microserve::yaml::parse_yaml(in) == microserve::yaml::parse_yaml(text));
}
