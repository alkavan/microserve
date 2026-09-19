#!/usr/bin/env sh

``
curl -I http://localhost:9090/
curl -I --http2-prior-knowledge http://localhost:9090/
curl -I --http2 https://localhost:9443/
curl -I --http3 https://localhost:9443/

curl -v http://localhost:9090/
curl -v --http2-prior-knowledge http://localhost:9090/
curl -v --http2 https://localhost:9443/
curl -v --http3 https://localhost:9443/
