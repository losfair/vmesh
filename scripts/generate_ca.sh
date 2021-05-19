#!/bin/sh

if [ -z "$1" ]; then
    echo "Output name needed"
    exit 1
fi

openssl genpkey -algorithm ed25519 -out "$1.key"
openssl req -new -x509 -key "$1.key" -out "$1.crt" -days 3650
