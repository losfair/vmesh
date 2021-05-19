#!/bin/sh

if [ -z "$1" ]; then
    echo "CA name needed"
    exit 1
fi

if [ -z "$2" ]; then
    echo "Node CSR path needed"
    exit 1
fi

if [ -z "$3" ]; then
    echo "Output path needed"
    exit 1
fi

CA_PATH=$(readlink -f "$1")
CSR_PATH=$(readlink -f "$2")
OUT_PATH=$(readlink -f "$3")

cd $(dirname $1)

openssl x509 -req -in "$CSR_PATH" -CA "$CA_PATH.crt" -CAkey "$CA_PATH.key" -CAcreateserial -out "$OUT_PATH" -days 365
