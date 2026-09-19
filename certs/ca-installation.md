## Install

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
