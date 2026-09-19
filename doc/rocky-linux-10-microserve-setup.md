# Install Microserve on Rocky Linux 10

C++20 modules + Boost.Asio/Beast. **GCC 16 is required** (GCC 14/15 reject
Asio in `export module`). Rocky 10 ships GCC 14 and `gcc-toolset-15` only.
Build GCC 16 into `/opt/gcc-16`. Do not install it to `/usr` or `/usr/local`.

Compared with Rocky 9 this host already has a usable toolchain:

| Piece            | Rocky 9             | Rocky 10                    |
|------------------|---------------------|-----------------------------|
| System GCC       | 11                  | 14.3                        |
| CMake            | 3.26                | 3.30                        |
| Ninja            | 1.10.2 (too old)    | **1.11.1 in CRB**           |
| OpenSSL          | 3.0.x               | **3.5.x**                   |
| GCC Toolset      | 15 via `scl enable` | 15 via `gcc-toolset-15-env` |
| `gcc-toolset-16` | no                  | not in AppStream yet        |

Stock Ninja 1.11.1 is enough for CMake C++ modules. Do not replace it with a
GitHub zip.

## 1. Repos and packages

```bash
sudo dnf upgrade --refresh
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --set-enabled crb
sudo dnf install -y epel-release

sudo dnf group install development -y
sudo dnf install -y \
  git cmake ninja-build python3 \
  gcc-toolset-15 gcc-toolset-15-gcc-c++ \
  gmp-devel mpfr-devel libmpc-devel flex bison texinfo \
  glibc-devel kernel-headers binutils \
  spdlog-devel fmt-devel libzstd-devel \
  libnghttp2-devel ngtcp2-devel ngtcp2-crypto-ossl-devel \
  openssl-devel zlib-devel libcurl-devel \
  autoconf automake libtool
```

`ninja-build` lives in CRB. `spdlog-devel`, `fmt-devel`, and `ngtcp2-*` come
from EPEL 10. Skip `isl-devel`; it is not in AppStream/CRB and GCC’s
`download_prerequisites` vendors ISL.

`gcc-toolset-15` is **only** the compiler used to *build* GCC 16. Do not
compile Microserve with it.

Check OpenSSL before insisting on the crypto package:

```bash
openssl version
# expect 3.5.x
rpm -q ngtcp2-crypto-ossl-devel || true
```

If `ngtcp2-crypto-ossl-devel` is missing, install `ngtcp2-devel` alone.
pkg-config can still find `libngtcp2_crypto_ossl` when that `.so` is present.

## 2. GCC 16 → `/opt/gcc-16`

Use toolset 15 as the host compiler and **disable bootstrap**. That avoids
GCC 16’s stage1 `-latomic_asneeded` failure (`libgomp` configure cannot find
that linker script before `libatomic` exists).

Do not configure or `make` inside the source tree.

On Rocky 10 the toolset wrapper is **not** `scl enable`:

```bash
gcc-toolset-15-env bash

cd /tmp
curl -fLO https://ftp.gnu.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.xz
# if that 404s, pick the newest gcc-16.* on https://ftp.gnu.org/gnu/gcc/
tar xf gcc-16.2.0.tar.xz
cd gcc-16.2.0
./contrib/download_prerequisites

cd /tmp
rm -rf gcc16-build
mkdir gcc16-build
cd gcc16-build

../gcc-16.2.0/configure \
  --prefix=/opt/gcc-16 \
  --enable-languages=c,c++ \
  --disable-multilib \
  --disable-nls \
  --disable-bootstrap \
  --enable-checking=release \
  --with-system-zlib \
  --enable-default-pie \
  --enable-default-ssp \
  --disable-fixincludes

make -j"$(nproc)"
sudo make install
/opt/gcc-16/bin/g++ --version    # 16.2.x
```

If you ever drop `--disable-bootstrap` (full 3-stage), add:

```bash
make -j"$(nproc)" \
  CFLAGS_FOR_TARGET='-g -O2 -fno-link-libatomic' \
  CXXFLAGS_FOR_TARGET='-g -O2 -fno-link-libatomic'
```

and start from a **pristine** source tree. An in-tree `host-x86_64-pc-linux-gnu/`
directory makes out-of-tree configure refuse the build.

Point the dynamic linker at GCC 16’s `libstdc++`. Rocky 10’s
`/lib64/libstdc++.so.6` does not provide `GLIBCXX_3.4.30` / `3.4.35`:

```bash
echo '/opt/gcc-16/lib64' | sudo tee /etc/ld.so.conf.d/gcc-16.conf
# if libstdc++ landed in lib/ instead:
# echo '/opt/gcc-16/lib' | sudo tee /etc/ld.so.conf.d/gcc-16.conf
sudo ldconfig
```

Do **not** `--prefix=/usr/local`. That shadows the system toolchain. If that
already happened, `sudo make uninstall` from the build dir (configured with
that prefix), then install again to `/opt/gcc-16`.

## 3. Boost 1.88 → `/opt/boost-1.88`

Build Boost with GCC 16 so its objects match Microserve’s libstdc++.

```bash
cd /tmp
curl -fLO https://archives.boost.io/release/1.88.0/source/boost_1_88_0.tar.gz
tar xf boost_1_88_0.tar.gz
cd boost_1_88_0

export PATH=/opt/gcc-16/bin:$PATH
export CC=/opt/gcc-16/bin/gcc
export CXX=/opt/gcc-16/bin/g++

./bootstrap.sh --prefix=/opt/boost-1.88 \
  --with-libraries=system,thread,program_options \
  --with-toolset=gcc
./b2 -j"$(nproc)" toolset=gcc cxxstd=20 link=shared threading=multi install
```

Asio and Beast are header-only; they install with the tree.

```bash
ls /opt/boost-1.88/include/boost/asio.hpp \
   /opt/boost-1.88/include/boost/beast.hpp \
   /opt/boost-1.88/lib/libboost_system.so.1.88.0

echo '/opt/boost-1.88/lib' | sudo tee /etc/ld.so.conf.d/boost-1.88.conf
sudo ldconfig
unset CC CXX CFLAGS CXXFLAGS LDFLAGS
export PATH=/usr/bin:/usr/sbin
```

## 4. nghttp3

Not in Rocky 10 / EPEL 10.

```bash
cd /tmp
curl -fLO https://github.com/ngtcp2/nghttp3/releases/download/v1.18.0/nghttp3-1.18.0.tar.xz
tar xf nghttp3-1.18.0.tar.xz
cd nghttp3-1.18.0
./configure --prefix=/usr --enable-lib-only --disable-static
make -j"$(nproc)"
sudo make install
sudo ldconfig
pkg-config --modversion libnghttp3
```

## 5. Configure and build Microserve

### Clone Microserve
```bash
sudo mkdir -p /opt/src
sudo git clone https://github.com/alkavan/microserve.git /opt/src/microserve
cd /opt/src/microserve
```

Download Tailwind binary:

```bash
curl -fL https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.3/tailwindcss-linux-x64 \
  -o bin/tailwindcss-linux-x64
chmod +x bin/tailwindcss-linux-x64
```

### Clean and build Microserve

```bash
rm -rf build
cmake -S . -B build -G Ninja \
  -DCMAKE_PREFIX_PATH=/opt/boost-1.88 \
  -DCMAKE_C_COMPILER=/opt/gcc-16/bin/gcc-16 \
  -DCMAKE_CXX_COMPILER=/opt/gcc-16/bin/g++-16
cmake --build build
```

`Boost_NO_SYSTEM_PATHS` is ignored (Boost 1.88 uses Config mode).
`CMAKE_PREFIX_PATH` is what finds `/opt/boost-1.88`.

In-tree CMake should FetchContent nlohmann/json at `develop` (3.12.0 fails
GCC 15/16 modules). That is a `CMakeLists.txt` change, not a DNF package.

## 6. Install / uninstall

Default CMake prefix is `/usr/local`. Prefer `/opt`:

```bash
cmake --install build --prefix /opt/microserve
```

Undo a `/usr/local` install from this build:

```bash
sudo xargs -a build/install_manifest.txt rm -f
```

## 7. systemd and libstdc++

The unit fails until it is pointed at GCC 16’s libstdc++. The journal names
the system library, which is the one the loader opened:

```text
/opt/microserve/bin/microserver: /lib64/libstdc++.so.6: version `GLIBCXX_3.4.35' not found
/opt/microserve/bin/microserver: /lib64/libstdc++.so.6: version `GLIBCXX_3.4.30' not found
```

`ldconfig` for `/opt/gcc-16/lib64` is enough for interactive shells. systemd
units still need an explicit path:

```bash
sudo systemctl stop microserve.service
sudo mkdir -p /etc/systemd/system/microserve.service.d
sudo tee /etc/systemd/system/microserve.service.d/libstdc++.conf >/dev/null <<'EOF'
[Service]
Environment=LD_LIBRARY_PATH=/opt/gcc-16/lib64:/opt/boost-1.88/lib
EOF
sudo systemctl daemon-reload
```

`daemon-reload` is required after editing the drop-in. Check the value systemd
will actually use:

```bash
systemctl show microserve.service -p Environment
```

It must print:

```text
Environment=LD_LIBRARY_PATH=/opt/gcc-16/lib64:/opt/boost-1.88/lib
```

Then check the mapping (adjust the binary path if you used `/usr/local`):

```bash
BIN=/opt/microserve/bin/microserver
LD_LIBRARY_PATH=/opt/gcc-16/lib64:/opt/boost-1.88/lib \
  ldd "$BIN" | grep -E 'stdc|libgcc|boost'
```

`libstdc++.so.6` and `libgcc_s.so.1` must resolve under `/opt/gcc-16/lib64`,
not `/lib64`.

```bash
sudo systemctl start microserve.service
sudo systemctl status microserve.service --no-pager
```

## 8. Benchmark tools

```bash
sudo dnf install -y httpd-tools siege nghttp2
ulimit -n 65535
ab -n 10000 -c 100 -k http://127.0.0.1/
siege -c 50 -t 1M -b http://127.0.0.1/
h2load -n 100000 -c 100 -m 10 https://127.0.0.1/
```

Generate load from another machine.

## 9. Pitfalls

- `dnf install gcc-toolset-16` is not available on Rocky 10 AppStream yet.
  CentOS Stream 10 already has it; do not mix Stream RPMs onto this box.
- Building GCC inside the source directory contaminates the tree. Re-extract
  if configure says `contains host-x86_64-pc-linux-gnu`.
- `cannot find -latomic_asneeded` means a full bootstrap without
  `-fno-link-libatomic`. Use `--disable-bootstrap` with toolset 15 instead.
- Compiling Microserve with `gcc-toolset-15-env` will fail on Asio modules.
  Always pass `/opt/gcc-16/bin/g++` to CMake.
- Putting GCC 16 on the global `PATH` is optional. CMake compiler paths are
  enough. Do not replace `/usr/bin/gcc`.
