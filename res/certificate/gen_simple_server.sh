openssl genrsa -des3 -out csr_server_key.pem 4096
openssl req -new -x509 -days 365 -key csr_server_key.pem -out csr_server.pem

openssl genrsa -des3 -out tls_server_key.pem 4096
openssl req -new -x509 -days 365 -key tls_server_key.pem -out tls_server.pem

openssl genrsa -des3 -out cipher_server_key.pem 4096
openssl req -new -x509 -days 365 -key cipher_server_key.pem -out cipher_server.pem

openssl genrsa -des3 -out signer_server_key.pem 4096
openssl req -new -x509 -days 365 -key signer_server_key.pem -out signer_server.pem
