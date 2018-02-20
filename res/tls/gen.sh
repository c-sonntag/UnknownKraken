##generate CA cert and key files
openssl genrsa -des3 -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt
 
##generate Server cert and key files
openssl genrsa -des3 -out ssl_server.key 4096
openssl req -new -key ssl_server.key -out ssl_server.csr
 
##Sign using CA
openssl x509 -req -days 365 -in ssl_server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out ssl_server.crt
 
##generate Client cert and key files
openssl genrsa -des3 -out ssl_client.key 4096
openssl req -new -key ssl_client.key -out ssl_client.csr
 
##Sign using CA
openssl x509 -req -days 365 -in ssl_client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out ssl_client.crt
