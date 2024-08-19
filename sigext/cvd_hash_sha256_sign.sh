#!/bin/bash

# Create the keypair with:
# openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
# openssl rsa -pubout -in private_key.pem -out public_key.pem

# The public exponent and modulus can be extracted from the public key with:
# openssl rsa -pubin -in public_key.pem -text -noout

# The public exponent and modulus can be used to create a public key in C with:
#define CLI_NSTR_EXT_SIG "E32B3AC1D501EE975296A45BA65DD699100DADD340FF3BBD1F1030C66D6BB16DBFBD53DF4D97BBD42EF8FC777E7C114A6074A87DD8095A5C08B3DD7B85817713047647EF396C58358C5C22B5C3ADF85CE8D0ABC429F89E936EC917B64DD00E02A712E6666FAE1A71591092BCEE59E3141758C4719B4B08589117B0FF7CDBDBB261F8486A193E2E720AE0B16D40DD5E56E97346CBD8010DC81B35332F41C9E93E61490802DDCDFC823D581BA6888588968C68A3C95B93949AF411682E73323F7469473F668B0958F6966849FF03BDE808866D127A2C058B16F17C741A9EE50812A5C7841224E55BF7ADDB5AEAE8EB5476F9BC8740178AB35926D5DC375583C641"
#define CLI_ESTR_EXT_SIG "010001"


if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file_path> <private_key>"
    exit 1
fi

file_path="$1"
private_key="$2"
offset=512  # 0x200 in decimal

# Generate the hexadecimal SHA-256 hash
sha256_hash_hex=$(tail -c +$((offset + 1)) "$file_path" | sha256sum | awk '{print $1}')

# Sign the binary hash (using the binary data corresponding to the hex hash) and output the signature in base64
signature_hex=$(echo -n "$sha256_hash_hex" | xxd -r -p | openssl pkeyutl -sign -inkey "$private_key" -pkeyopt digest:sha256 | xxd -p -c 1024)

# Output the hexadecimal hash and the base64-encoded signature
echo "$sha256_hash_hex:$signature_hex"

