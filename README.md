# Microserve

A modern HTTP server for experimentation and development
supporting HTTP/3, HTTP/2, and HTTP/1.1.

**Version 0.5 is out now, Yarr!**

![version_05_banner.jpg](doc/version_05_banner.jpg)

---

## Features

* **Wide protocol support**
  - **HTTP/1.1** ([RFC 9112](https://datatracker.ietf.org/doc/html/rfc9112)) 
  - **HTTP/2** ([RFC 9113](https://www.rfc-editor.org/info/rfc9113/))
  - **HTTP/2 cleartext/h2c** ([RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)) 
  - **HTTP/3** ([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html)) 
  - **HTTP3/QUIC** ([RFC 9000](https://datatracker.ietf.org/doc/rfc9000/))
  - Choose protocols per listen (`http11`, `http2c`, `http2`, `http3`)
  - HTTP/2 and HTTP/3 can share a port (TCP+UDP)
* **Stand-alone first** — `microserve --dir ./public` is enough. YAML and federation are opt-in.
* **Multi-site YAML** — several `server_name` blocks, per-site TLS, locations (`root` / `proxy_pass`), named backends, index files, and access logs.
* **CLI listen overlay** — `--listen`, `--address`, and `--proto` ignore YAML `servers` and start a single site.
* **Process isolation** — one child process per site when two or more sites are resolved. A single site still runs in-process.
* **Reverse proxy** — nginx-style `proxy_pass` to a host or named backend (`backend://api/`); hop-by-hop headers stripped; failures return 502/504.
* **H2C origins** — h2c-only sockets (HTTP/1.1 closed unless configured). The proxy can speak HTTP/2 prior-knowledge (`h2c://`).
* **Dual-stack** — `--ipv6` / `--no-ipv4` expand unspecified binds; explicit addresses stay as written.
* **Optional federation** (`-f federation.yaml`) — hub or member; certified vs. unverified membership; certs can be revoked. Default remains stand-alone.
* **HTTP Basic Authorization** — per location with `{SHA512}` `.htpasswd` ([RFC 7617](https://www.rfc-editor.org/info/rfc7617/)).
* **Logging and timeouts** — per-site error logs, YAML `access_log`, and connect/read/write timeouts.
* **Self-contained** — Mini YAML parser for config (no extra YAML library, Boost dependency is probably temporary).
* **C++20 modules** — The only deps are Boost.Asio/Beast, nlohmann_json, nghttp2, ngtcp2/nghttp3, OpenSSL.
* **Over 100 test cases and 700 assertions** — Based on the Catch2 framework.
* **Microserve is also a static library** — Can be easily embedded into other applications.

**Note: After v1.0 the Boost dependencies are scheduled for removal,
considering replacement of nlohmann_json as well.** 

## Linux Install Instructions and Dependencies

### Linux (Fedora Linux 44)
```shell
sudo dnf install spdlog-devel \
  libnghttp3-devel libnghttp2-devel \
  ngtcp2-devel ngtcp2-crypto-ossl-devel \
  boost-devel boost-thread boost-program-options
```

#### If you need/want to install `boost` manually (probably not):
```bash
cd deps/
./get_boost.sh
cd ..
```

### Windows (UCRT64/MSYS2)
Install dependencies:

```shell
pacman -S mingw-w64-ucrt-x86_64-boost \
          mingw-w64-ucrt-x86_64-nlohmann-json \
          mingw-w64-ucrt-x86_64-zstd \
          mingw-w64-ucrt-x86_64-spdlog
```

```shell
pacman -S msys/libnghttp3 msys/libnghttp3-devel \
          msys/libngtcp2 msys/libngtcp2-devel 
```

## Build and install (CMake)

Requires CMake 3.31+ and a C++20 compiler with modules support. Install the
dependencies above first, then:

```shell
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_INSTALL_PREFIX=/opt/microserve
cmake --build build
sudo cmake --install build
```

If Ninja is not installed, use Unix Makefiles instead:

```shell
cmake -S . -B build -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_INSTALL_PREFIX=/opt/microserve
cmake --build build
sudo cmake --install build
```

This installs:

    microserver → /opt/microserve/bin/microserver
    sample public/ and private/ → /opt/microserve/share/microserve/
    sample certs/ → /opt/microserve/share/microserve/certs
    dist/*.yaml → /opt/microserve/etc/microserve/

Configs in `dist/` are written for prefix `/`. Install rewrites absolute
filesystem paths when the prefix is not `/` (both `-DCMAKE_INSTALL_PREFIX`
and `cmake --install --prefix`). With the prefix above,
`pid: /run/microserve/microserve.pid` becomes
`pid: /opt/microserve/run/microserve/microserve.pid`.


Run from the prefix (adjust `--dir` / TLS paths as needed):

```shell
/opt/microserve/bin/microserver --dir /opt/microserve/share/microserve/public
```

To skip tests or Tailwind during the build:

```shell
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_INSTALL_PREFIX=/opt/microserve \
  -DMICROSERVE_BUILD_TESTS=OFF \
  -DMICROSERVE_BUILD_TAILWIND=OFF
```

## Generate TLS/SSL Certificate
```shell
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "//CN=localhost"
```

## Basic Authorization with `.htpasswd`

microserve supports HTTP Basic Authorization ([RFC 7617](https://www.rfc-editor.org/info/rfc7617/)) per location.

```yaml
    locations:
      - path: /
        root: ../public
      - path: /secret
        root: ../private
        auth: basic
        auth_realm: secret space
        auth_file: ../.htpasswd
```

### Generate an Apache SHA512 `.htpasswd` entry:
```shell
printf "admin:{SHA512}" > .htpasswd
printf "change-me" | openssl dgst -sha512 -binary | openssl base64 -A >> .htpasswd
printf "\n" >> .htpasswd
```

## Todo

* [x] Install `/` or `/opt` ready configuration files.
* [ ] Support all compressions: `Accept-Encoding: gzip, deflate, br, zstd`
* [ ] Support smart caching (lower priority, needed mostly for production)

## Documentation

* [Online Documentation](https://docs.tekfed.org/microserve/latest/)

API pages use the [m.css Doxygen theme](https://mcss.mosra.cz/documentation/doxygen/)
with a custom **Earth Heaven** palette (`doc/m-theme-earth-heaven.css`, moss and
clay earth, sunlight gold, sky-blue info). `doc/conf.py` and `doc/Doxyfile-mcss`
drive that pipeline. The stock Doxygen HTML theme is still available from the
same `Doxyfile`.

### Generate local docs with m.css

**On Linux or macOS:**

```bash
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install jinja2 Pygments
git clone --depth 1 https://github.com/mosra/m.css /tmp/m.css
python3 /tmp/m.css/documentation/doxygen.py doc/conf.py
```

**On MSYS2/Windows (UCRT64):**

```bash
pacman -S mingw-w64-ucrt-x86_64-doxygen
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install jinja2 Pygments
git clone --depth 1 https://github.com/mosra/m.css "$HOME/m.css"
```

**Issue with modules (temporary)**

Doxygen 1.18 writes C++20 `module` XML that m.css does not handle. In
`$HOME/m.css/documentation/doxygen.py`, after the language skip in
`parse_xml()`, add:

```patch
diff --git a/documentation/doxygen.py b/documentation/doxygen.py
index 008c197..f92832c 100755
--- a/documentation/doxygen.py
+++ b/documentation/doxygen.py
@@ -2783,6 +2783,9 @@ def parse_xml(state: State, xml: str):
     # See extract_metadata() for why `in []` is used
     if compounddef.attrib.get('language', 'C++') not in ['C++']:
         return
+    if compounddef.attrib['kind'] in ['dir', 'module', 'concept']:
+        logging.warning("{}: skipping unsupported compound kind {}".format(state.current, compounddef.attrib['kind']))
+        return

     assert len([i for i in root]) == 1
```

Then:

```bash
python3 "$HOME/m.css/documentation/doxygen.py" doc/conf.py
```

### Stock Doxygen HTML
```bash
cd doc && doxygen Doxyfile
```

## Resources

* [ngtcp2/nghttp3](https://github.com/ngtcp2/nghttp3) (HTTP/3 library written in C)
* [Chrome's QUIC Implementation](https://github.com/chromium/chromium/tree/main/net/quic)
* [CloudFlare QUIC Test URL](https://cloudflare-quic.com/)
