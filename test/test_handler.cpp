// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

import microserve.core;
import microserve.config;
import microserve.handler;

namespace fs = std::filesystem;

namespace {

fs::path make_temp_dir(const std::string_view tag) {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    auto dir = fs::temp_directory_path() /
               ("microserve-handler-" + std::string(tag) + "-" + std::to_string(stamp));
    fs::create_directories(dir);
    return dir;
}

void write_file(const fs::path& path, const std::string_view body) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    REQUIRE(out);
    out << body;
}

struct TempRoot {
    fs::path root = make_temp_dir("root");

    ~TempRoot() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }

    fs::path path(const std::string_view rel) const { return root / rel; }

    std::string str() const { return root.string(); }
};

microserve::Request make_request(const microserve::http::verb method, const std::string& target) {
    microserve::Request req;
    req.method(method);
    req.target(target);
    req.version(11);
    return req;
}

} // namespace

TEST_CASE("get_mime_type maps known extensions", "[handler][mime]") {
    CHECK(microserve::get_mime_type("index.html") == "text/html");
    CHECK(microserve::get_mime_type("/a/b/style.CSS") == "text/plain"); // extension is case-sensitive today
    CHECK(microserve::get_mime_type("app.css") == "text/css");
    CHECK(microserve::get_mime_type("app.js") == "application/javascript");
    CHECK(microserve::get_mime_type("data.json") == "application/json");
    CHECK(microserve::get_mime_type("img.png") == "image/png");
    CHECK(microserve::get_mime_type("photo.jpg") == "image/jpeg");
    CHECK(microserve::get_mime_type("photo.jpeg") == "image/jpeg");
    CHECK(microserve::get_mime_type("anim.gif") == "image/gif");
    CHECK(microserve::get_mime_type("icon.svg") == "image/svg+xml");
    CHECK(microserve::get_mime_type("favicon.ico") == "image/x-icon");
}

TEST_CASE("get_mime_type falls back to text/plain", "[handler][mime]") {
    CHECK(microserve::get_mime_type("README") == "text/plain");
    CHECK(microserve::get_mime_type("file.unknown") == "text/plain");
    CHECK(microserve::get_mime_type("archive.tar.gz") == "text/plain"); // extension == ".gz"
}

TEST_CASE("serve_file loads content and sets headers", "[handler][serve]") {
    TempRoot tmp;
    const auto file = tmp.path("hello.html");
    write_file(file, "<h1>hi</h1>");

    microserve::Response res;
    REQUIRE(microserve::serve_file(file.string(), res));

    CHECK(res.result() == microserve::http::status::ok);
    CHECK(res.body() == "<h1>hi</h1>");
    CHECK(res[microserve::http::field::content_type] == "text/html");
    CHECK(res[microserve::http::field::server] == "microserve/1.0");
}

TEST_CASE("serve_file returns false for missing or non-regular paths", "[handler][serve]") {
    TempRoot tmp;
    const auto missing = tmp.path("nope.txt");
    const auto dir = tmp.path("subdir");
    fs::create_directories(dir);

    microserve::Response res;
    CHECK_FALSE(microserve::serve_file(missing.string(), res));
    CHECK_FALSE(microserve::serve_file(dir.string(), res));
}

TEST_CASE("FileHandler 404 when no location matches", "[handler][routes]") {
    microserve::FileHandler handler;
    handler.add_location("/static", "/tmp/does-not-matter");

    auto req = make_request(microserve::http::verb::get, "/other/file.txt");
    microserve::Response res;
    handler.handle_request(req, res);

    CHECK(res.result() == microserve::http::status::not_found);
    CHECK(res.body() == "404 Not Found");
    CHECK(res[microserve::http::field::content_type] == "text/plain");
}

TEST_CASE("FileHandler serves files with longest-prefix match", "[handler][routes]") {
    TempRoot tmp;
    write_file(tmp.path("site/index.html"), "root-index");
    write_file(tmp.path("site/about.html"), "about-page");
    write_file(tmp.path("site/blog/post.html"), "blog-post");
    write_file(tmp.path("site/blog/index.html"), "blog-index");

    microserve::FileHandler handler;
    handler.add_location("/", tmp.str() + "/site");
    handler.add_location("/blog", tmp.str() + "/site/blog");

    SECTION("root file") {
        auto req = make_request(microserve::http::verb::get, "/about.html");
        microserve::Response res;
        handler.handle_request(req, res);
        CHECK(res.result() == microserve::http::status::ok);
        CHECK(res.body() == "about-page");
        CHECK(res[microserve::http::field::content_type] == "text/html");
    }

    SECTION("directory default index at /") {
        auto req = make_request(microserve::http::verb::get, "/");
        microserve::Response res;
        handler.handle_request(req, res);
        CHECK(res.result() == microserve::http::status::ok);
        CHECK(res.body() == "root-index");
    }

    SECTION("longer prefix wins for /blog") {
        auto req = make_request(microserve::http::verb::get, "/blog/post.html");
        microserve::Response res;
        handler.handle_request(req, res);
        CHECK(res.result() == microserve::http::status::ok);
        CHECK(res.body() == "blog-post");
    }

    SECTION("index under nested location when target is the location prefix") {
        // relative_path empty → /index.html under the matched dir
        auto req = make_request(microserve::http::verb::get, "/blog");
        microserve::Response res;
        handler.handle_request(req, res);
        CHECK(res.result() == microserve::http::status::ok);
        CHECK(res.body() == "blog-index");
    }

    SECTION("missing file under a matching location is 404") {
        auto req = make_request(microserve::http::verb::get, "/missing.html");
        microserve::Response res;
        handler.handle_request(req, res);
        CHECK(res.result() == microserve::http::status::not_found);
        CHECK(res.body() == "404 Not Found");
    }
}

TEST_CASE("FileHandler sets Alt-Svc when configured", "[handler][altsvc]") {
    TempRoot tmp;
    write_file(tmp.path("index.html"), "ok");

    microserve::FileHandler handler;
    handler.add_location("/", tmp.str());
    handler.set_alt_svc("h3=\":9443\"; ma=86400");

    auto req = make_request(microserve::http::verb::get, "/");
    microserve::Response res;
    handler.handle_request(req, res);

    REQUIRE(res.result() == microserve::http::status::ok);
    CHECK(res["Alt-Svc"] == "h3=\":9443\"; ma=86400");
}

TEST_CASE("FileHandler HEAD clears the body after a successful serve", "[handler][head]") {
    TempRoot tmp;
    write_file(tmp.path("index.html"), "secret-body");

    microserve::FileHandler handler;
    handler.add_location("/", tmp.str());

    auto req = make_request(microserve::http::verb::head, "/");
    microserve::Response res;
    handler.handle_request(req, res);

    CHECK(res.result() == microserve::http::status::ok);
    CHECK(res.body().empty());
    CHECK(res[microserve::http::field::content_type] == "text/html");
}

TEST_CASE("setup_file_handler registers valid locations", "[handler][setup]") {
    TempRoot tmp;
    write_file(tmp.path("public/index.html"), "pub");
    fs::create_directories(tmp.path("assets"));

    microserve::FileHandler handler;
    const std::vector<std::string> locations{
        "/:" + tmp.str() + "/public",
        "/assets:" + tmp.str() + "/assets",
        "docs:" + tmp.str() + "/public", // leading slash inserted
    };

    REQUIRE(microserve::setup_file_handler(locations, handler));

    auto req = make_request(microserve::http::verb::get, "/");
    microserve::Response res;
    handler.handle_request(req, res);
    CHECK(res.result() == microserve::http::status::ok);
    CHECK(res.body() == "pub");

    // Normalized /docs should resolve under public
    req = make_request(microserve::http::verb::get, "/docs/");
    res = {};
    handler.handle_request(req, res);
    CHECK(res.result() == microserve::http::status::ok);
    CHECK(res.body() == "pub");
}

TEST_CASE("setup_file_handler rejects invalid entries", "[handler][setup]") {
    microserve::FileHandler handler;

    SECTION("missing colon") {
        CHECK_FALSE(microserve::setup_file_handler({"nocolon"}, handler));
    }
    SECTION("empty route") {
        CHECK_FALSE(microserve::setup_file_handler({":/tmp"}, handler));
    }
    SECTION("empty directory") {
        CHECK_FALSE(microserve::setup_file_handler({"/route:"}, handler));
    }
}

    TEST_CASE("is_basic_auth_enabled accepts basic variants", "[handler][auth]") {
        CHECK(microserve::is_basic_auth_enabled("basic"));
        CHECK(microserve::is_basic_auth_enabled("Basic"));
        CHECK(microserve::is_basic_auth_enabled("BASIC"));
        CHECK_FALSE(microserve::is_basic_auth_enabled(""));
        CHECK_FALSE(microserve::is_basic_auth_enabled("digest"));
        CHECK_FALSE(microserve::is_basic_auth_enabled("off"));
    }

    TEST_CASE("constant_time_equals compares equal-length strings", "[handler][auth]") {
        CHECK(microserve::constant_time_equals("abc", "abc"));
        CHECK_FALSE(microserve::constant_time_equals("abc", "abd"));
        CHECK_FALSE(microserve::constant_time_equals("abc", "ab"));
        CHECK_FALSE(microserve::constant_time_equals("abc", "abcd"));
    }

    TEST_CASE("base64 encode/decode round-trip", "[handler][auth]") {
        const std::string plain = "admin:change-me";
        const auto encoded = microserve::base64_encode(
            reinterpret_cast<const unsigned char*>(plain.data()), plain.size());
        CHECK(microserve::base64_decode(encoded) == plain);
        CHECK(microserve::base64_decode("YWRtaW46Y2hhbmdlLW1l") == "admin:change-me");
    }

    TEST_CASE("verify_htpasswd_entry accepts SHA512 and PLAIN", "[handler][auth]") {
        const auto digest = microserve::sha512_base64("change-me");
        CHECK(microserve::verify_htpasswd_entry("change-me", "{SHA512}" + digest));
        CHECK_FALSE(microserve::verify_htpasswd_entry("wrong", "{SHA512}" + digest));
        CHECK(microserve::verify_htpasswd_entry("change-me", "{PLAIN}change-me"));
        CHECK_FALSE(microserve::verify_htpasswd_entry("change-me", "{PLAIN}other"));
        CHECK_FALSE(microserve::verify_htpasswd_entry("change-me", "$apr1$salt$hash"));
        CHECK_FALSE(microserve::verify_htpasswd_entry("change-me", ""));
    }

    TEST_CASE("verify_htpasswd_file matches user entries", "[handler][auth]") {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto path = std::filesystem::temp_directory_path() /
            ("microserve-htpasswd-" + std::to_string(stamp));

        {
            std::ofstream out(path);
            REQUIRE(out.good());
            out << "# comment\n";
            out << "admin:{SHA512}" << microserve::sha512_base64("change-me") << "\n";
            out << "guest:{PLAIN}guest-pass\n";
        }

        CHECK(microserve::verify_htpasswd_file(path.string(), "admin", "change-me"));
        CHECK(microserve::verify_htpasswd_file(path.string(), "guest", "guest-pass"));
        CHECK_FALSE(microserve::verify_htpasswd_file(path.string(), "admin", "wrong"));
        CHECK_FALSE(microserve::verify_htpasswd_file(path.string(), "missing", "change-me"));
        CHECK_FALSE(microserve::verify_htpasswd_file("no-such-htpasswd-file", "admin", "change-me"));

        std::error_code ec;
        std::filesystem::remove(path, ec);
    }

    namespace {

    microserve::Request make_get(const std::string_view target, const std::string_view authorization = {}) {
        microserve::Request req;
        req.method(microserve::http::verb::get);
        req.target(std::string{target});
        req.version(11);
        if (!authorization.empty())
            req.set(microserve::http::field::authorization, std::string{authorization});
        req.prepare_payload();
        return req;
    }

    std::string basic_header(const std::string_view user, const std::string_view password) {
        const auto creds = std::string{user} + ":" + std::string{password};
        return "Basic " + microserve::base64_encode(
            reinterpret_cast<const unsigned char*>(creds.data()), creds.size());
    }

    } // namespace

    TEST_CASE("FileHandler basic auth with user/password", "[handler][auth]") {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto dir = std::filesystem::temp_directory_path() /
            ("microserve-auth-root-" + std::to_string(stamp));
        std::filesystem::create_directories(dir);
        {
            std::ofstream out(dir / "index.html");
            REQUIRE(out.good());
            out << "<html>secret</html>";
        }

        microserve::Config::ServerConfig::Location loc;
        loc.path = "/secret";
        loc.root = dir.string();
        loc.auth = "basic";
        loc.auth_user = "admin";
        loc.auth_password = "change-me";
        loc.auth_realm = "secret space";

        microserve::FileHandler handler;
        handler.add_location(loc);

        {
            microserve::Response res;
            handler.handle_request(make_get("/secret/"), res);
            CHECK(res.result() == microserve::http::status::unauthorized);
            CHECK(res["WWW-Authenticate"].find("secret space") != std::string::npos);
        }
        {
            microserve::Response res;
            handler.handle_request(make_get("/secret/", basic_header("admin", "wrong")), res);
            CHECK(res.result() == microserve::http::status::unauthorized);
        }
        {
            microserve::Response res;
            handler.handle_request(make_get("/secret/", basic_header("admin", "change-me")), res);
            CHECK(res.result() == microserve::http::status::ok);
            CHECK(res.body().find("secret") != std::string::npos);
        }

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    TEST_CASE("FileHandler basic auth with SHA512 htpasswd file", "[handler][auth]") {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto dir = std::filesystem::temp_directory_path() /
            ("microserve-auth-file-" + std::to_string(stamp));
        std::filesystem::create_directories(dir);
        const auto htpasswd = dir / ".htpasswd";
        {
            std::ofstream page(dir / "index.html");
            REQUIRE(page.good());
            page << "<html>private</html>";
            std::ofstream creds(htpasswd);
            REQUIRE(creds.good());
            creds << "admin:{SHA512}" << microserve::sha512_base64("change-me") << "\n";
        }

        microserve::Config::ServerConfig::Location loc;
        loc.path = "/secret";
        loc.root = dir.string();
        loc.auth = "basic";
        loc.auth_realm = "secret space";
        loc.auth_file = htpasswd.string();

        microserve::FileHandler handler;
        handler.add_location(loc);

        {
            microserve::Response res;
            handler.handle_request(make_get("/secret/"), res);
            CHECK(res.result() == microserve::http::status::unauthorized);
        }
        {
            microserve::Response res;
            handler.handle_request(make_get("/secret/", basic_header("admin", "change-me")), res);
            CHECK(res.result() == microserve::http::status::ok);
            CHECK(res.body().find("private") != std::string::npos);
        }

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    TEST_CASE("FileHandler leaves unprotected routes open", "[handler][auth]") {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto dir = std::filesystem::temp_directory_path() /
            ("microserve-public-root-" + std::to_string(stamp));
        std::filesystem::create_directories(dir);
        {
            std::ofstream out(dir / "index.html");
            REQUIRE(out.good());
            out << "<html>public</html>";
        }

        microserve::Config::ServerConfig::Location loc;
        loc.path = "/";
        loc.root = dir.string();

        microserve::FileHandler handler;
        handler.add_location(loc);

        microserve::Response res;
        handler.handle_request(make_get("/"), res);
        CHECK(res.result() == microserve::http::status::ok);
        CHECK(res.body().find("public") != std::string::npos);

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
