#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <ca_certificate> <ca_key>" >&2
    exit 1
fi

CA_CRT="$1"
CA_KEY="$2"

SERVER_KEY="server.key"
SERVER_CSR="server.csr"
SERVER_CRT="server.crt"
SERVER_CNF="server.cnf"

# Check if required config and CA files exist
if [ ! -f "$SERVER_CNF" ]; then
    echo "Error: Config file '$SERVER_CNF' not found. Aborting." >&2
    exit 1
fi

if [ ! -f "$CA_KEY" ] || [ ! -s "$CA_KEY" ]; then
    echo "Error: Root CA private key '$CA_KEY' not found or empty." >&2
    exit 1
fi

if [ ! -f "$CA_CRT" ] || [ ! -s "$CA_CRT" ]; then
    echo "Error: Root CA certificate '$CA_CRT' not found or empty." >&2
    exit 1
fi

# Prevent overwriting existing server files
for file in "$SERVER_KEY" "$SERVER_CSR" "$SERVER_CRT"; do
    if [ -f "$file" ]; then
        echo "Error: '$file' already exists. Remove it manually to regenerate." >&2
        exit 1
    fi
done

# Step 1a: Generate unencrypted server private key (modern PKCS#8 format)
echo "Generating unencrypted server private key..."
openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:4096 \
    -out "$SERVER_KEY"

if [ $? -ne 0 ] || [ ! -s "$SERVER_KEY" ]; then
    echo "Error: Private key generation failed." >&2
    exit 1
fi

# Secure the private key file permissions
chmod 600 "$SERVER_KEY"
echo "Generated unencrypted $SERVER_KEY"

# Step 1b: Generate CSR from the private key
echo "Generating CSR from the private key..."
openssl req -new \
    -key "$SERVER_KEY" \
    -sha256 \
    -config "$SERVER_CNF" \
    -out "$SERVER_CSR"

if [ $? -ne 0 ] || [ ! -s "$SERVER_CSR" ]; then
    echo "Error: CSR generation failed." >&2
    rm -f "$SERVER_KEY" "$SERVER_CSR"
    exit 1
fi
echo "Generated $SERVER_CSR"

# Step 2: Sign the CSR with the root CA to create the server certificate
echo "Signing the server certificate with the root CA..."
openssl x509 -req -in "$SERVER_CSR" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -sha256 -days 825 \
    -extfile "$SERVER_CNF" -extensions v3_req \
    -out "$SERVER_CRT"

if [ $? -ne 0 ] || [ ! -s "$SERVER_CRT" ]; then
    echo "Error: Signing the server certificate failed." >&2
    # Clean up partial files on failure
    rm -f "$SERVER_KEY" "$SERVER_CSR" "$SERVER_CRT"
    exit 1
fi
echo "Signed server certificate generated: $SERVER_CRT"

# Optional: Clean up the CSR (no longer needed)
rm -f "$SERVER_CSR"

# Final verification
echo ""
echo "Verifying certificate chain..."
openssl verify -CAfile "$CA_CRT" "$SERVER_CRT"

echo ""
echo "Certificate details:"
openssl x509 -in "$SERVER_CRT" -noout -subject -issuer -dates -ext subjectAltName,keyUsage,extendedKeyUsage

echo ""
echo "Usage:"
echo "  - Private key:  $SERVER_KEY  (unencrypted, protect with file permissions)"
echo "  - Certificate:  $SERVER_CRT"
echo "  - CA (for clients / trust store): $CA_CRT"
echo ""
echo "For local testing: install $CA_CRT into the system/browser trust store."
echo "WARNING: Only do this on test machines — never trust dummy roots in production!"