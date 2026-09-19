# Rocky Linux 9 setup for microserve

Working path only. This tree is a C++20 modules + Boost.Asio/Beast project. It
needs **GCC 16** (GCC 15 rejects Asio in `export module`). Rocky 9 has no
`gcc-toolset-16`. Build GCC 16 into `/opt/gcc-16`. Do not install it to
`/usr/local`.

Stock GCC 11 and `ninja-build` 1.10.2 cannot configure or generate this project.

## 1. Repos and packages

```bash
sudo dnf update -y
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --set-enabled crb
sudo dnf install -y epel-release

sudo dnf group install development -y
sudo dnf install -y git cmake python3 unzip bzip2 \
  gcc-toolset-15 gcc-toolset-15-gcc-c++ \
  gmp-devel mpfr-devel libmpc-devel flex bison texinfo \
  spdlog-devel fmt-devel libzstd-devel \
  libnghttp2-devel ngtcp2-devel \
  openssl-devel zlib-devel libcurl-devel \
  autoconf automake libtool
```

`gcc-toolset-15` is **only** the compiler used to *build* GCC 16. Do not compile
microserve with toolset 15.

If DNF offers `ngtcp2-crypto-ossl-devel` and OpenSSL is 3.5+, install it.
Otherwise skip it; pkg-config can still find `libngtcp2_crypto_ossl` if that
`.so` is already on the box.

## 2. Ninja 1.13+

CMake C++ modules need Ninja **1.11+**.

```bash
sudo dnf remove -y ninja-build
cd /tmp
curl -fLO https://github.com/ninja-build/ninja/releases/download/v1.13.2/ninja-linux.zip
sudo unzip -o ninja-linux.zip -d /usr/local/bin
sudo chmod +x /usr/local/bin/ninja
echo 'export PATH=/usr/local/bin:$PATH' | sudo tee /etc/profile.d/local-bin.sh
source /etc/profile.d/local-bin.sh
hash -r
ninja --version    # 1.13.2
```

## 3. GCC 16 to `/opt/gcc-16`

Yes: use toolset 15 as the **bootstrap** compiler. System GCC 11 is a weaker
host for GCC 16 sources. `--disable-bootstrap` is enough once 15 can compile
the tree.

```bash
scl enable gcc-toolset-15 bash

cd /tmp
# pick the newest gcc-16.* on https://ftp.gnu.org/gnu/gcc/ if 16.2.0 404s
curl -fLO https://ftp.gnu.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.xz
tar xf gcc-16.2.0.tar.xz
mkdir gcc16-build && cd gcc16-build

../gcc-16.2.0/configure \
  --prefix=/opt/gcc-16 \
  --enable-languages=c,c++ \
  --disable-multilib \
  --disable-bootstrap

make -j"$(nproc)"
sudo make install
/opt/gcc-16/bin/g++ --version    # 16.x
```

Point the dynamic linker at GCC 16’s `libstdc++` (Rocky’s `/lib64/libstdc++.so.6`
has no `GLIBCXX_3.4.30` / `3.4.35`):

```bash
echo '/opt/gcc-16/lib64' | sudo tee /etc/ld.so.conf.d/gcc-16.conf
# if libstdc++ landed in lib/ instead:
# echo '/opt/gcc-16/lib' | sudo tee /etc/ld.so.conf.d/gcc-16.conf
sudo ldconfig
```

Do **not** `--prefix=/usr/local`. That shadows the system toolchain. If that
already happened, `sudo make uninstall` from `gcc16-build` (configured with
that prefix), then install again to `/opt/gcc-16`.

## 4. Boost 1.88 to `/opt/boost-1.88`

```bash
cd /tmp
curl -fLO https://archives.boost.io/release/1.88.0/source/boost_1_88_0.tar.gz
tar xf boost_1_88_0.tar.gz
cd boost_1_88_0

scl enable gcc-toolset-15 bash
./bootstrap.sh --prefix=/opt/boost-1.88 --with-libraries=system,thread,program_options
./b2 -j"$(nproc)" cxxstd=20 link=shared threading=multi install
```

Asio and Beast are header-only; they install with the tree. Check:

```bash
ls /opt/boost-1.88/include/boost/asio.hpp \
   /opt/boost-1.88/include/boost/beast.hpp \
   /opt/boost-1.88/lib/libboost_system.so.1.88.0
```

```bash
echo '/opt/boost-1.88/lib' | sudo tee /etc/ld.so.conf.d/boost-1.88.conf
sudo ldconfig
```

## 5. nghttp3

Not in Rocky 9 / EPEL 9.

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

## 6. Configure and build microserve


**Clone Microserve:**
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

Clean and build Microserve:
```bash
rm -rf build
cmake -S . -B build -G Ninja \
  -DCMAKE_PREFIX_PATH=/opt/boost-1.88 \
  -DCMAKE_C_COMPILER=/opt/gcc-16/bin/gcc \
  -DCMAKE_CXX_COMPILER=/opt/gcc-16/bin/g++
cmake --build build
```

`Boost_NO_SYSTEM_PATHS` is ignored (Boost 1.88 uses Config mode).
`CMAKE_PREFIX_PATH` is what finds `/opt/boost-1.88`.

In-tree CMake should FetchContent nlohmann/json at `develop` (3.12.0 fails
GCC 15/16 modules). That is a `CMakeLists.txt` change, not a DNF package.

## 7. Install / uninstall the server

Default CMake prefix is `/usr/local`. Prefer:

```bash
cmake --install build --prefix /opt/microserve
```

To undo a `/usr/local` install from this build:

```bash
sudo xargs -a build/install_manifest.txt rm -f
```

## 8. Troubleshoot

### Issues with systemd and GLIBCXX_3.4.35

The service fails until it is pointed at GCC 16's libstdc++. The journal
names the system library, which is the one the loader opened:

    /usr/local/bin/microserver: /lib64/libstdc++.so.6: version `GLIBCXX_3.4.35' not found (required by /usr/local/bin/microserver)
    /usr/local/bin/microserver: /lib64/libstdc++.so.6: version `GLIBCXX_3.4.30' not found (required by /usr/local/bin/microserver)

Write /etc/systemd/system/microserve.service.d/libstdc++.conf:

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
will actually use before starting the unit:

```bash
systemctl show microserve.service -p Environment
```

It must print:
```
Environment=LD_LIBRARY_PATH=/opt/gcc-16/lib64:/opt/boost-1.88/lib
```

Then check the mapping. Use /opt/microserve/bin/microserver if that prefix was used:

```bash
LD_LIBRARY_PATH=/opt/gcc-16/lib64:/opt/boost-1.88/lib \
  ldd /usr/local/bin/microserver | grep -E 'stdc|libgcc'
```

libstdc++.so.6 and libgcc_s.so.1 must resolve under /opt/gcc-16/lib64, not /lib64.  


Restart the `microserve` service:
```bash
sudo systemctl start microserve.service
```

## 9. Benchmark tools

```bash
sudo dnf install -y httpd-tools siege nghttp2
ulimit -n 65535
ab -n 10000 -c 100 -k http://127.0.0.1/
siege -c 50 -t 1M -b http://127.0.0.1/
h2load -n 100000 -c 100 -m 10 https://127.0.0.1/
```

**Generate load from another machine!**
