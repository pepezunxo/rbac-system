#!/bin/bash

# Remove old certificates
rm -f service1/key.pem service1/cert.pem

# Generate new private key
openssl genrsa -out service1/key.pem 2048

# Generate certificate signing request
openssl req -new -key service1/key.pem -out service1/csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in service1/csr.pem -signkey service1/key.pem -out service1/cert.pem

# Remove CSR file as it's no longer needed
rm -f service1/csr.pem

echo "Service 1 certificates regenerated successfully."