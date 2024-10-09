#!/bin/bash

# Check if a key file is provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <private_key_di2.pem> <define name>"
    exit 1
fi

# Input PEM file
PEM_FILE=$1
DEFINE_NAME=$2

# The below command dumps out only the public key and formats it for teh define
HEX_STRING=$(openssl pkey -in "$PEM_FILE" -text -noout -pubout | grep -v "dilithium2 public key:" | grep -v "PQ key material:" | tr -d '\n\t :')

# Print the compact hex string
echo "#define $DEFINE_NAME \"$HEX_STRING\""

