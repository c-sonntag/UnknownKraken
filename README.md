# LibUnknownEcho

LibUnknownEcho helps to put secure exchanges in the development of C client/server application.

## Channel protocol
Channel protocol is an all-in-one protocol to create a server that handle multiple client exchanges in different channels.
A possible application of this protocol can be a secure chat application, where each channel is a conversation room.

The process is the following:
* The server is launched. If it's the first time, it creates 4 certificate/key pairs:
    * A pair for the TLS connection.
    * A pair for ciphering messages.
    * A pair for signing messages.
    * A pair for Certificate Signing Request (CSR) of client(s).
Each pair will be record in a corresponding keystore.
The server is now listening on two ports:
    * One for incoming TLS connection.
    * One for CSR, in order to establish further TLS connection.
* Before launch the client, we needs the 4 server certificate in order to communicate with it. They must be provided with the application. After that, we can launch the client.
* If it's the first time, the client build 3 certificate/key pairs, for TLS, ciphering and signing, and build for each of them a CSR. This CSR is send to the server on the CSR port in order to sign each certificate. The server will record this signed certificates, and the client will save them in 3 distinct keystores.
* The client can now establish a connection with a channel. If he's the only connected, he will be responsible of the session key of the channel. If not, he ask through the server the session key. Note that the server doesn't have the knowledge of the key. After that, each message will be encrypted with the key.

## Relay protocol

TBD. Experimental version on wip branch https://github.com/swasun/LibUnknownEcho/tree/wip_relay_protocol_backup.

## Installation from sources
See [INSTALL](INSTALL.md).

## Examples

* Start the server with:
```bash
 ./bin/release/examples/channel_server_protocol_example
 ```
* When the server has finished to generate certificates, copy the `certificate` directory from `out/server/certificate` to `out` directory,
  in order to allow the client to use them (image that's the server certificates provided after application installation).
* Start the client with:
```bash
./bin/release/examples/channel_client_protocol_example
```
* Connect to a channel with: `@channel_connection 0`
  which connect to channel n°0.
* After that, you can connect other clients in this same channel start communicate.

## Architecture

### Facade design pattern
The facade design pattern is use to simplify the complexity of a module.
In the module, we have 2 to 4 sub directories which are:
* api: that contains the highest level of functions/structs of the module.
* impl: that contains implementation(s) a api files.
* factory (optional): that contains factories to create complex objects from the api files.
* utils (optional): that contains utils functions only used in this module.

## Cross-plateform

Tested on:
* Windows x86
* Windows 64
* Ubuntu 14.04
* Ubuntu 16.04