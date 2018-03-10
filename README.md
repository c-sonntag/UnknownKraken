# LibUnknownEcho

LibUnknownEcho helps to put secure exchanges in the development of C client/server application.

***

# Low level features
* TLS connection between a client and a server.
* TLS connection between multiple clients through a server.
* Encrypt messages with symmetric and asymmetric cryptography.
* Generate x509 certificates.
* Generate Certificate Signing Request (CSR) and send it to server to sign a certificate.
* Manipulate PKCS12 keystore.
* Sign a message wit asymmetric cryptography.
* Hashing.
* Encoding in Base64.
* Compression with Inflate/Deflate.

***

# Hight level features

## Channel protocol
Channel protocol is an all-in-one protocol to create a server that handle multiple client exchanges in different channels.
A possible application of this protocol can be a secure chat application, where each channel is a conversation room.

The process is the following :
* The server is launched. If it's the first time, it creates 4 certificate/key pairs :
    * A pair for the TLS connection.
    * A pair for ciphering messages.
    * A pair for signing messages.
    * A pair for Certificate Signing Request (CSR) of client(s).
Each pair will be record in a corresponding keystore.
The server is now listening on two ports :
    * One for incoming TLS connection.
    * One for CSR, in order to establish further TLS connection.
* Before launch the client, we needs the 4 server certificate in order to communicate with it. They must be provided with the application. After that, we can launch the client.
* If it's the first time, the client build 3 certificate/key pairs, for TLS, ciphering and signing, and build for each of them a CSR. This CSR is send to the server on the CSR port in order to sign each certificate. The server will record this signed certificates, and the client will save them in 3 distinct keystores.
* The client can now establish a connection with a channel. If he's the only connected, he will be responsible of the session key of the channel. If not, he ask through the server the session key. Note that the server doesn't have the knowledge of the key. After that, each message will be encrypted with the key.

***

# Dependencies
* libssl 1.1.0 for TLS connection support.
* libcrypto 1.1.0 for encryption support.
* libz 1.2.11 for compression support.

***

# Installation from sources
* Install libssl version 1.10 (that contains also libcrypto 1.10) :
    * wget https://www.openssl.org/source/openssl-1.1.0.tar.gz
    * tar -zxvf openssl-1.1.0.tar.gz
    * cd openssl-1.1.0
    * ./config
    * make
    * sudo make install
* Install zlib version 1.2.11
    * Download source code from web site : https://zlib.net/
    * ./configure
    * make
    * sudo make install
* Install a recent version of CMake.
* Compile LibUnknownEcho
    * In debug mode : ./build_debug.sh
    * In release mode : ./build_release.sh
    * Clean all : ./clean.sh
The lib will appear in bin folder, and all the examples in bin/debug/examples or bin/release/examples according to the compilation mode.

***

# Other dependencies
* Make, CMake for compilation.
* Valgrind for memory debugging/memory leak detection.

***

# Architecture

## Facade design pattern
The facade design pattern is use to simplify the complexity of a module.
In the module, we have 2 to 4 sub folders which are :
* api : that contains the highest level of functions/structs of the module.
* impl : that contains implementation(s) a api files.
* factory (optional) : that contains factories to create complex objects from the api files.
* utils (optional) : that contains utils functions only used in this module.
