## Install self-signed root certificate 

We assume the certificate `my_root_ca.crt` located inside this folder.

```bash
sudo cp my_root_ca.crt /etc/pki/ca-trust/source/anchors/my_root_ca.crt
sudo chmod 644 /etc/pki/ca-trust/source/anchors/my_root_ca.crt
sudo update-ca-trust extract
```

The command prints nothing on success. It rebuilds the bundles under `/etc/pki/ca-trust/extracted/`.

## Verify

```bash
trust list | grep -A2 -i "my_root"

openssl verify -CAfile /etc/pki/tls/certs/ca-bundle.crt server.crt
```

`openssl verify` should print `server.crt: OK`.

Against a live service signed by this CA:

```bash
curl -vI https://your.server.example/
```

## Remove

```bash
sudo rm -f /etc/pki/ca-trust/source/anchors/my_root_ca.crt
sudo update-ca-trust extract
```

## Server certificate for the localhost (using CA)
You may wish to update `server.cnf` but the default should be fine for local and
remote development scenarios.

```bash
../bin/gen_server_cert.sh my_root_ca.crt my_root_ca.key
```