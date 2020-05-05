#!/bin/bash

# Make a self signed certificate for use by libcoap-2-openssl.

# Make a private key and self signed certificate.
openssl req -x509 -newkey rsa:2048 -passout pass:123456 -keyout key.pem -out cert.pem

# Remove passphrase from private key
openssl rsa -in key.pem -passin pass:123456 -out plainkey.pem

# Create combined file
cp plainkey.pem selfsigned.pem
cat cert.pem >> selfsigned.pem

# We let the user decide if they want to rm the uneccessary files or not.
echo "key.pem, plainkey.pem, and cert.pem may be removed."
