##Generate CA cert and key files
openssl genrsa -des3 -out ca_key.pem 4096
openssl req -new -x509 -days 365 -key ca_key.pem -out ca.pem
 
##Generate Server cert and key files
openssl genrsa -des3 -out server_key.pem 4096
openssl req -new -key server_key.pem -out server.csr
 
##Sign using CA
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca_key.pem -set_serial 01 -out server.pem
 
##Generate Client cert and key files
openssl genrsa -des3 -out client_key.pem 4096
openssl req -new -key client_key.pem -out client.csr
 
##Sign using CA
openssl x509 -req -days 365 -in client.csr -CA ca.pem -CAkey ca_key.pem -set_serial 01 -out client.pem

##Remove CSR
rm server.csr
rm client.csr
