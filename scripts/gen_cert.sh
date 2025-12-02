#!/usr/bin/env bash
set -e

if [ -z "$1" ]; then
    echo "usage: $0 server|client <common_name>"
    exit 1
fi

ROLE=$1
CN=${2:-"$ROLE.local"}

mkdir -p certs
cd certs

if [ ! -f rootCA.pem ]; then
    echo "Error: rootCA.pem not found! Run gen_ca.sh first."
    exit 1
fi

# Generate key
openssl genrsa -out ${ROLE}.key 2048

# Create CSR config
cat > ${ROLE}.cnf <<EOL
[ req ]
distinguished_name = req_distinguished_name
prompt = no
[ req_distinguished_name ]
C = PK
ST = SomeState
L = SomeCity
O = ISCourse
OU = Devices
CN = ${CN}
EOL

# Generate CSR
openssl req -new -key ${ROLE}.key -config ${ROLE}.cnf -out ${ROLE}.csr

# SAN file for Windows
echo "subjectAltName=DNS:${CN}" > san.txt

# Sign CSR with Root CA
openssl x509 -req -in ${ROLE}.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial \
    -out ${ROLE}.pem -days 365 -sha256 -extfile san.txt

# Cleanup
rm san.txt ${ROLE}.cnf ${ROLE}.csr

echo "Created certs/${ROLE}.key and certs/${ROLE}.pem"
