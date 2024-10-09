#!/bin/bash

# This produces the defines needed to use a generated signing key with the ClamAV Database External signature
# system.  You must replace the define values for CLI_NSTR_EXT_SIG and CLI_ESTR_EXT_SIG with the values produced
# by this script in order to change the public signing key that CalmAV uses to validate the external signature
# files when in FIPS mode.

# Useage:
# $ ./extract_mod_and_exp.sh public_key.pem CLI_NSTR_EXT_SIG CLI_ESTR_EXT_SIG
# #define CLI_NSTR_EXT_SIG "E32B3AC1D501EE975296A45BA65DD699100DADD340FF3BBD1F1030C66D6BB16DBFBD53DF4D97BBD42EF8FC777E7C114A6074A87DD8095A5C08B3DD7B85817713047647EF396C58358C5C22B5C3ADF85CE8D0ABC429F89E936EC917B64DD00E02A712E6666FAE1A71591092BCEE59E3141758C4719B4B08589117B0FF7CDBDBB261F8486A193E2E720AE0B16D40DD5E56E97346CBD8010DC81B35332F41C9E93E61490802DDCDFC823D581BA6888588968C68A3C95B93949AF411682E73323F7469473F668B0958F6966849FF03BDE808866D127A2C058B16F17C741A9EE50812A5C7841224E55BF7ADDB5AEAE8EB5476F9BC8740178AB35926D5DC375583C641"
# #define CLI_ESTR_EXT_SIG 65537

# Check for correct number of arguments
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <public_key_file> <modulus_name> <exponent_name>"
    exit 1
fi

# Assign command line arguments to variables
public_key_file=$1
modulus_name=$2
exponent_name=$3

# Extract the modulus and exponent
modulus=$(openssl rsa -in "$public_key_file" -pubin -noout -modulus | sed 's/Modulus=//')
exponent=$(openssl rsa -in "$public_key_file" -pubin -noout -text | grep 'Exponent' | awk '{print $2}')

# Format the modulus as a single line string
formatted_modulus=$(echo $modulus | tr -d '\n')

# Create the #define strings
echo "#define $modulus_name \"$formatted_modulus\""
echo "#define $exponent_name $exponent"

