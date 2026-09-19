# Federation identity certificates

These are **federation identity** certs (`certs/federation.*`), not the site HTTPS certs in `microserve.yaml`. Run from the **repo root**. You need the CA **private key** to sign or revoke; `at_root_ca.crt` alone is not enough.

## MSYS2 / UCRT64 / Git Bash

- `/O=...` in `-subj` is rewritten as a Windows path (`C:/msys64/O=...`).
- Prefix OpenSSL commands that take a leading-slash subject with `MSYS2_ARG_CONV_EXCL='*'`.
- Do **not** double the slash (`//O=`) when conversion is excluded — OpenSSL then treats `/O` as an unknown attribute.
- Do **not** use `-config /dev/null` or `extfile -`; MSYS maps `/dev/null` to `nul`.

Optional, once per shell:

```shell
mkdir -p certs
```

## 1. Self-signed (tiny / first hub)

The node cert *is* the trust anchor. Copy it to `ca` so the overlay paths match.

```shell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out certs/federation.key

MSYS2_ARG_CONV_EXCL='*' openssl req -new -x509 -sha256 -days 3650 \
  -key certs/federation.key \
  -out certs/federation.crt \
  -subj "/O=First Foundation/OU=Hub/CN=fed-node-1" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" \
  -addext "extendedKeyUsage=clientAuth,serverAuth" \
  -addext "subjectKeyIdentifier=hash"

cp certs/federation.crt certs/federation-ca.crt
```

OpenSSL `ca -gencrl` wants a config. Minimal version that works:

```shell
cat > certs/federation-ca.cnf << 'EOF'
[ ca ]
default_ca = federation

[ federation ]
dir              = certs
database         = certs/federation-index.txt
new_certs_dir    = certs
certificate      = certs/federation.crt
private_key      = certs/federation.key
serial           = certs/federation-serial
crlnumber        = certs/federation-crlnumber
default_md       = sha256
default_crl_days = 365
crl_extensions   = crl_ext
policy           = policy_any

[ policy_any ]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

touch certs/federation-index.txt
echo 1000 > certs/federation-crlnumber
echo 1000 > certs/federation-serial

MSYS2_ARG_CONV_EXCL='*' openssl ca -gencrl -batch \
  -config certs/federation-ca.cnf \
  -out certs/federation.crl
```

`federation.yaml`:

```yaml
cert: certs/federation.crt
key: certs/federation.key
ca: certs/federation-ca.crt
crl: certs/federation.crl
```

---

## 2. Issued under `at_root_ca.crt`

Assumes you already have:

- `certs/at_root_ca.crt`
- `certs/at_root_ca.key`  (required to sign)

Node key + CSR:

```shell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out certs/federation.key

MSYS2_ARG_CONV_EXCL='*' openssl req -new -sha256 \
  -key certs/federation.key \
  -out certs/federation.csr \
  -subj "/O=First Foundation/OU=Member/CN=fed-node-1"
```

Sign with the root (leaf, **not** a CA):

```shell
cat > certs/federation-leaf.ext << 'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth,serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:localhost,URI:urn:microserve:node:fed-node-1
EOF
```

```shell
MSYS2_ARG_CONV_EXCL='*' openssl x509 -req -sha256 -days 825 \
  -in certs/federation.csr \
  -CA certs/at_root_ca.crt \
  -CAkey certs/at_root_ca.key \
  -CAcreateserial \
  -out certs/federation.crt \
  -copy_extensions copyall \
  -extfile certs/federation-leaf.ext
```

Trust store for the overlay is the **root**, not the leaf:

```shell
cp certs/at_root_ca.crt certs/federation-ca.crt
```

CRL is issued **by the root** (revoking a node is a CA operation):

```shell
cat > certs/at-root-ca.cnf << 'EOF'
[ ca ]
default_ca = at_root

[ at_root ]
dir              = certs
database         = certs/at-root-index.txt
new_certs_dir    = certs
certificate      = certs/at_root_ca.crt
private_key      = certs/at_root_ca.key
serial           = certs/at-root-serial
crlnumber        = certs/at-root-crlnumber
default_md       = sha256
default_crl_days = 30
crl_extensions   = crl_ext
policy           = policy_any

[ policy_any ]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

touch certs/at-root-index.txt
echo 1000 > certs/at-root-crlnumber
echo 1000 > certs/at-root-serial

MSYS2_ARG_CONV_EXCL='*' openssl ca -gencrl -batch \
  -config certs/at-root-ca.cnf \
  -out certs/federation.crl
```

Revoke later (then regenerate the CRL):

```shell
MSYS2_ARG_CONV_EXCL='*' openssl ca -revoke certs/federation.crt -config certs/at-root-ca.cnf
MSYS2_ARG_CONV_EXCL='*' openssl ca -gencrl -batch -config certs/at-root-ca.cnf -out certs/federation.crl
```

Also, put that node’s `node_id` on `federation.revoked` if you use the YAML list
(the current resolver checks the overlay list, not the CRL file yet).

---

## Check

```shell
# self-signed: issuer == subject
openssl x509 -in certs/federation.crt -noout -subject -issuer -dates

# CA-signed: chain to at_root_ca
openssl verify -CAfile certs/at_root_ca.crt certs/federation.crt

openssl crl -in certs/federation.crl -noout -text
```

EC instead of RSA (same flow):

```shell
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out certs/federation.key
```

Do **not** reuse `server.crt` / `server.key` here.
Site TLS is per vhost; federation certs are membership identity.
Keep `federation.key` and `at_root_ca.key` off the public tree.
