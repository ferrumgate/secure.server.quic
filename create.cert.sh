#!/bin/bash
cd /tmp
set -e
rm -rf certs
mkdir -p certs
cd certs

openssl req -x509 -newkey rsa:4096 -days 365 -keyout ca.key.pem -out ca.cert.pem -nodes -subj "/C=FR/ST=World/L=Istanbul/O=Ferrum/OU=Computer/CN=*.ferrumgate.com/emailAddress=security@ferrumgate.com"
echo "CA's self-signed certificate"
openssl x509 -noout -text -in ca.cert.pem

tee v3.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = ferrumgate.dev
DNS.2 = sec.ferrumgate.dev

EOF

openssl req -newkey rsa:4096 -keyout server.key.pem -out server.req.pem -nodes -subj "/C=FR/ST=World/L=Istanbul/O=FerrumQuic/OU=Computer/CN=www.ferrumgate.com/emailAddress=security@ferrumgate.com"
openssl x509 -req -in server.req.pem -CA ca.cert.pem -extfile v3.ext -CAkey ca.key.pem -CAcreateserial -out server.cert.pem
openssl verify -CAfile ca.cert.pem server.cert.pem
#openssl x509 -noout -text -in server.crt
openssl x509 -outform der -in server.cert.pem -out server.cert.der
openssl x509 -outform der -in ca.cert.pem -out ca.cert.der

#client start
#./client --loglevel debug --host sec.ferrumgate.dev:8443  --ca /tmp/certs/ca.cert.der
#server start
#./server --loglevel info  --redis_host 192.168.43.172:6379 --key certs/server.key.pem --cert certs/server.cert.der
