##Generate Server cert and key files for CSR
openssl genrsa -des3 -out csr_server_key.pem 4096
openssl req -new -key csr_server_key.pem -out csr_server.csr
 
##Sign using CA
openssl x509 -req -days 365 -in csr_server.csr -CA ca.pem -CAkey ca_key.pem -set_serial 01 -out csr_server.pem

##Remove CSR
rm csr_server.csr


##Generate Server cert and key files for TLS
openssl genrsa -des3 -out tls_server_key.pem 4096
openssl req -new -key tls_server_key.pem -out tls_server.csr
 
##Sign using CA
openssl x509 -req -days 365 -in tls_server.csr -CA ca.pem -CAkey ca_key.pem -set_serial 01 -out tls_server.pem

##Remove CSR
rm tls_server.csr


##Generate Server cert and key files for cipher
openssl genrsa -des3 -out cipher_server_key.pem 4096
openssl req -new -key cipher_server_key.pem -out cipher_server.csr
 
##Sign using CA
openssl x509 -req -days 365 -in cipher_server.csr -CA ca.pem -CAkey ca_key.pem -set_serial 01 -out cipher_server.pem

##Remove CSR
rm cipher_server.csr


##Generate Server cert and key files for signer
openssl genrsa -des3 -out signer_server_key.pem 4096
openssl req -new -key signer_server_key.pem -out signer_server.csr
 
##Sign using CA
openssl x509 -req -days 365 -in signer_server.csr -CA ca.pem -CAkey ca_key.pem -set_serial 01 -out signer_server.pem

##Remove CSR
rm signer_server.csr
