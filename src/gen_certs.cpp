// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

// Build: g++ -std=c++17 gen_certs.cpp -o gen_certs -lssl -lcrypto
// Writes: ca.key, ca.crt, server.cnf, server.key, server.crt, server-chain.crt
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace {

template <typename T, void (*FreeFn)(T*)>
struct SslDeleter {
    void operator()(T* p) const {
        if (p) {
            FreeFn(p);
        }
    }
};

using PKey = std::unique_ptr<EVP_PKEY, SslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using Cert = std::unique_ptr<X509, SslDeleter<X509, X509_free>>;
using PKeyCtx = std::unique_ptr<EVP_PKEY_CTX, SslDeleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;

[[noreturn]] void fail(const char* what) {
    std::cerr << "error: " << what << "\n";
    ERR_print_errors_fp(stderr);
    std::exit(1);
}

void restrict_key(const char* path) {
#ifndef _WIN32
    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        std::perror(path);
    }
#else
    (void)path;
#endif
}

PKey generate_rsa(const int bits) {
    const PKeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx) {
        fail("EVP_PKEY_CTX_new_id");
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        fail("EVP_PKEY_keygen_init");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
        fail("EVP_PKEY_CTX_set_rsa_keygen_bits");
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) {
        fail("EVP_PKEY_keygen");
    }
    return PKey(raw);
}

void set_random_serial(X509* cert) {
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        fail("RAND_bytes");
    }
    buf[0] &= 0x7f;
    BIGNUM* bn = BN_bin2bn(buf, static_cast<int>(sizeof(buf)), nullptr);
    if (!bn) {
        fail("BN_bin2bn");
    }
    ASN1_INTEGER* serial = BN_to_ASN1_INTEGER(bn, nullptr);
    BN_free(bn);
    if (!serial) {
        fail("BN_to_ASN1_INTEGER");
    }
    if (X509_set_serialNumber(cert, serial) != 1) {
        ASN1_INTEGER_free(serial);
        fail("X509_set_serialNumber");
    }
    ASN1_INTEGER_free(serial);
}

void add_name_entry(X509_NAME* name, const char* field, const char* value) {
    if (X509_NAME_add_entry_by_txt(
            name,
            field,
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(value),
            -1,
            -1,
            0) != 1) {
        fail("X509_NAME_add_entry_by_txt");
    }
}

void add_ext(X509* cert, X509V3_CTX* ctx, const int nid, const char* value) {
    X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, ctx, nid, value);
    if (!ex) {
        fail("X509V3_EXT_conf_nid");
    }
    const int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    if (ok != 1) {
        fail("X509_add_ext");
    }
}

void set_validity(const X509* cert, const int days) {
    const long seconds = static_cast<long>(days) * 24L * 60L * 60L;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert), seconds)) {
        fail("X509_gmtime_adj");
    }
#else
    if (!X509_gmtime_adj(X509_get_notBefore(cert), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(cert), seconds)) {
        fail("X509_gmtime_adj");
    }
#endif
}

Cert make_ca(EVP_PKEY* key, const int days) {
    Cert cert(X509_new());
    if (!cert) {
        fail("X509_new");
    }
    if (X509_set_version(cert.get(), 2) != 1) {
        fail("X509_set_version");
    }
    set_random_serial(cert.get());
    set_validity(cert.get(), days);
    if (X509_set_pubkey(cert.get(), key) != 1) {
        fail("X509_set_pubkey");
    }

    X509_NAME* subject = X509_get_subject_name(cert.get());
    add_name_entry(subject, "C", "US");
    add_name_entry(subject, "O", "Microserve");
    add_name_entry(subject, "CN", "Microserve Root CA");
    if (X509_set_issuer_name(cert.get(), subject) != 1) {
        fail("X509_set_issuer_name");
    }

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    X509V3_set_ctx_nodb(&ctx);
    add_ext(cert.get(), &ctx, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(cert.get(), &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_ext(cert.get(), &ctx, NID_subject_key_identifier, "hash");

    if (X509_sign(cert.get(), key, EVP_sha256()) == 0) {
        fail("X509_sign CA");
    }
    return cert;
}

Cert make_server(EVP_PKEY* key, EVP_PKEY* ca_key, X509* ca, const int days) {
    Cert cert(X509_new());
    if (!cert) {
        fail("X509_new");
    }
    if (X509_set_version(cert.get(), 2) != 1) {
        fail("X509_set_version");
    }
    set_random_serial(cert.get());
    set_validity(cert.get(), days);
    if (X509_set_pubkey(cert.get(), key) != 1) {
        fail("X509_set_pubkey");
    }

    X509_NAME* subject = X509_get_subject_name(cert.get());
    add_name_entry(subject, "C", "US");
    add_name_entry(subject, "ST", "Local");
    add_name_entry(subject, "L", "Local");
    add_name_entry(subject, "O", "Microserve");
    add_name_entry(subject, "OU", "server");
    add_name_entry(subject, "CN", "localhost");
    if (X509_set_issuer_name(cert.get(), X509_get_subject_name(ca)) != 1) {
        fail("X509_set_issuer_name");
    }

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca, cert.get(), nullptr, nullptr, 0);
    X509V3_set_ctx_nodb(&ctx);
    add_ext(cert.get(), &ctx, NID_basic_constraints, "critical,CA:FALSE");
    add_ext(cert.get(), &ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    add_ext(cert.get(), &ctx, NID_ext_key_usage, "serverAuth");
    add_ext(cert.get(), &ctx, NID_subject_key_identifier, "hash");
    add_ext(cert.get(), &ctx, NID_authority_key_identifier, "keyid,issuer");
    add_ext(
        cert.get(),
        &ctx,
        NID_subject_alt_name,
        "DNS:localhost,DNS:localhost.localdomain,IP:127.0.0.1,IP:::1");

    if (X509_sign(cert.get(), ca_key, EVP_sha256()) == 0) {
        fail("X509_sign server");
    }
    return cert;
}

void write_key(const char* path, const EVP_PKEY* key) {
    FILE* f = std::fopen(path, "wb");
    if (!f) {
        fail(path);
    }
    const int ok = PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
    std::fclose(f);
    if (ok != 1) {
        fail("PEM_write_PrivateKey");
    }
    restrict_key(path);
}

void write_cert(const char* path, const X509* cert) {
    FILE* f = std::fopen(path, "wb");
    if (!f) {
        fail(path);
    }
    const int ok = PEM_write_X509(f, cert);
    std::fclose(f);
    if (ok != 1) {
        fail("PEM_write_X509");
    }
}

void write_chain(const char* path, const X509* leaf, const X509* ca) {
    FILE* f = std::fopen(path, "wb");
    if (!f) {
        fail(path);
    }
    const int ok_leaf = PEM_write_X509(f, leaf);
    const int ok_ca = PEM_write_X509(f, ca);
    std::fclose(f);
    if (ok_leaf != 1 || ok_ca != 1) {
        fail("PEM_write_X509 chain");
    }
}

void write_server_cnf(const char* path) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        fail(path);
    }
    out << R"CNF(# server.cnf — HTTP server certificate for Microserve.
# Signed by the self-signed CA in ca.crt / ca.key.

[ req ]
default_bits       = 2048
prompt             = no
encrypt_key        = no
default_md         = sha256
distinguished_name = dn
req_extensions     = v3_req

[ dn ]
C  = US
ST = Local
L  = Local
O  = Microserve
OU = server
CN = localhost

[ v3_req ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ server_cert ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = localhost.localdomain
IP.1  = 127.0.0.1
IP.2  = ::1
)CNF";
    if (!out) {
        fail("write server.cnf");
    }
}

}  // namespace

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    write_server_cnf("server.cnf");

    // Regular self-signed root CA: RSA-4096, CA:TRUE, 10 years.
    const PKey ca_key = generate_rsa(4096);
    const Cert ca = make_ca(ca_key.get(), 3650);
    write_key("ca.key", ca_key.get());
    write_cert("ca.crt", ca.get());

    // HTTP server leaf signed by that CA: RSA-2048, serverAuth, 825 days.
    const PKey server_key = generate_rsa(2048);
    const Cert server = make_server(server_key.get(), ca_key.get(), ca.get(), 825);
    write_key("server.key", server_key.get());
    write_cert("server.crt", server.get());
    write_chain("server-chain.crt", server.get(), ca.get());

    std::cout
        << "self-signed CA: ca.key, ca.crt\n"
        << "server config:  server.cnf\n"
        << "HTTP server:    server.key, server.crt, server-chain.crt\n"
        << "Trust ca.crt in clients that should accept this server.\n";
    return 0;
}
