#!/bin/bash


if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <file_path> <private_key> <hash algorithm> <signature algorithm>"
    echo "Example: $0 /path/to/file private_key.pem 1 1"
    echo "Hash Algorithms: "
    echo "1 - MD5"
    echo "2 - SHA-256"
    echo "3 - SHA3-512"
    echo "Signature Algorithms: "
    echo "1 - RSA"
    echo "2 - Dilithium2"
    exit 1
fi

file_path="$1"
private_key="$2"
hash_algorithm="$3"
signature_algorithm="$4"
offset=512  # 0x200 in decimal

# Base on the $algorithm, select the right way to hash and sign
case $hash_algorithm in
    '1')
        hash_alg_name="md5"
        # Generate the hexadecimal MD5 hash
        hash_hex=$(tail -c +$((offset + 1)) "$file_path" | md5sum | awk '{print $1}')
        ;;
    '2')
        hash_alg_name="sha1"
        # Generate the hexadecimal SHA-1 hash
        hash_hex=$(tail -c +$((offset + 1)) "$file_path" | shasum | awk '{print $1}')
        ;;
    '3')
        hash_alg_name="sha256"
        # Generate the hexadecimal SHA-256 hash
        hash_hex=$(tail -c +$((offset + 1)) "$file_path" | sha256sum | awk '{print $1}')
        ;;
    '4')
        hash_alg_name="sha3-512"
        # Generate the hexidecimal SHA3-512 hash
        hash_hex=$(tail -c +$((offset + 1)) "$file_path" | openssl dgst -sha3-512 | awk '{print $2}')
    ;;
esac

case $signature_algorithm in
    '1')
        # Create the RSA keypair with:
        # openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
        # openssl rsa -pubout -in private_key.pem -out public_key.pem   
        signature_hex=$(echo -n "$hash_hex" | xxd -r -p | openssl pkeyutl -sign -inkey "$private_key" -pkeyopt digest:$hash_alg_name | xxd -p -c 8192)
    ;;

    '2')
        # Create the dilithium2 key with:
        # openssl genpkey -algorithm dilithium2 -out private_key_di2.pem
        # openssl pkey -in private_key_di2.pem -pubout -out public_key_di2.pem
        signature_hex=$(echo -n "$hash_hex" | xxd -r -p | openssl pkeyutl -sign -inkey "$private_key" -pkeyopt digest:$hash_alg_name | xxd -p -c 8192)
    ;;
esac

# Output the hexadecimal hash and the base64-encoded signature
echo "$hash_algorithm:$signature_algorithm:$hash_hex:$signature_hex"
