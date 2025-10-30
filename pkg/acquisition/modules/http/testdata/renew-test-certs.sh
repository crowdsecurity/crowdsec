#!/bin/sh

# run this before June 24th, 2525.
# https://www.youtube.com/watch?v=LE1drY3A418

openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout ca.key -out ca.crt \
        -days 182500 \
        -subj "/CN=test-ca"

openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=test-server"

echo "subjectAltName=DNS:localhost,IP:127.0.0.1" > ext.cnf

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 182500 -sha256 \
  -extfile ext.cnf

rm server.csr ext.cnf

openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=test-client"

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 182500 -sha256

rm client.csr

