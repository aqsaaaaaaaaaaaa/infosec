#!/usr/bin/env bash
set -e

mkdir -p certs
cd certs

if [ ! -f rootCA.key ]; then
    openssl genrsa -out rootCA.key 4096

    # Root CA config
    cat > rootCA.cnf <<EOL
[ req ]
distinguished_name = req_distinguished_name
prompt = no
[ req_distinguished_name ]
C = PK
ST = SomeState
L = SomeCity
O = ISCourse
OU = A02
CN = MyRootCA
EOL

    # Self-signed cert
    openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 \
        -config rootCA.cnf -out rootCA.pem

    rm rootCA.cnf
    echo "Created rootCA.key and rootCA.pem"
else
    echo "rootCA already exists"
fi
