#!/bin/sh

if [ -z "$1" ]; then
    echo "Output name needed"
    exit 1
fi

openssl ecparam -name secp256r1 -genkey -out "$1.key"
openssl req -new -key "$1.key" -out "$1.csr"
