docker run -p 8443:8443 -ti \
    -e REDIS_HOST=192.168.43.18 \
    -e REDIS_USER=test \
    -e REDIS_PASS=123456 \
    -e PORT=8443 \
    -e GATEWAY_ID=1234567 \
    secure.server.quic:latest
