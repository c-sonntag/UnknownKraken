##Generate CA cert and key files
openssl genrsa -des3 -out ca_key.pem 4096
openssl req -new -x509 -days 365 -key ca_key.pem -out ca.pem
