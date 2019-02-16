A cross-platform C11 library which depends on [OpenSSL](https://github.com/openssl/openssl) that allows to easily and quickly add crypto capabilities to your projects.

Its main purpose is to be the crypto module of [LibUnknownEcho](https://github.com/swasun/LibUnknownEcho) library.

The goal is **NOT** to wrap all features of Openssl, but only the most widely used features.

# Features

* data encryption
  * using symmetric encryption
  * using asymmetric encryption
  * using both asynmmetric and symmetric encryption for large data

* file encryption
  * using symmetric encryption

* certificate management
  * x509 certificate generation
  * x509 certificate signing
  * x509 certificate signing request (CSR)

* hashing

* pkcs12 keystore

* signing

* crypto random

* encoding
  * base64 encoding

* compression

# Installation

Clone the repository:
```bash
git clone http://github.com/swasun/LibUnknownEchoUtilsModule
```

Build in release mode:
```bash
mkdir -p build/release
cmake -Bbuild/release -H. -DCMAKE_BUILD_TYPE=Release
cd build/release
make
```

Or build in debug mode:
```bash
mkdir -p build/debug
cmake -Bbuild/debug -H. -DCMAKE_BUILD_TYPE=Debug
cd build/debug
make
```

* By default, dependencies are built and install in the `build` directoy.
To install in another place, add `-DLIBEI_INSTALL=/usr` flag in `cmake` command.

* To build with LIBEI already installed in the system, add `-DLIBEI_SYSTEM=TRUE` flag in `cmake` command.

* To build with LIBUEUM already installed in the system, add `-DLIBUEUM_SYSTEM=TRUE` flag in `cmake` command.

* Alternatively, you can build using `build_release.sh` and `build_debug.sh` scripts.

Finally, to install in the system:
```bash
cd build/release
sudo make install
```

# Examples

Some examples are available in `examples` directory.

```bash
./bin/release/examples/progress_bar_example
```

# Basic usage

The following `basic_usage.c` is an example of a simple usage of the library (for the sake of clarity, error handling are omitted here, but complete example file is availabe in ̀`examples` directory):
```c
#include <uecm/uecm.h> /* Include LibUnknownEchoCryptoModule */
#include <ueum/ueum.h> /* Include LibUnknownEchoUtilsModule */
#include <ei/ei.h> /* Include LibErrorInterceptor */

#include <stddef.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned char *plain_data, *cipher_data, *decipher_data;
    size_t plain_data_size, cipher_data_size, decipher_data_size;
    uecm_asym_key *key;
    int key_size;

    ei_init_or_die(); /* Initialize LibErrorInterceptor */

    uecm_init_or_die();  /* Initialize LibUnknownEchoCryptoModule */

    /* Use LibUnknownEchoCryptoModule */

    plain_data = NULL;
    cipher_data = NULL;
    decipher_data = NULL;
    key_size = 4096;

    /* Convert the string input in bytes */
    plain_data = ueum_bytes_create_from_string(argv[1]);
    plain_data_size = strlen(argv[1]);

    /* Generate a random RSA key pair */
    key = uecm_rsa_asym_key_create(key_size);
    
    /**
     * Cipher plain data using both asymmetric (4096-RSA) and
     * symmetric encryption (AES-256-CBC), compression
     * (inflate/deflate of zlib), signing (SHA-256).
     * The private key parameter (key->sk) is optional,
     * and used to sign the cipher data.
     */ 
    uecm_cipher_plain_data(plain_data, plain_data_size, key->pk, key->sk, &cipher_data, &cipher_data_size, "aes-256-cbc", "sha256");

    /**
     * Decipher cipher data using both asymmetric (4096-RSA) and
     * symmetric encryption (AES-256-CBC), compression
     * (inflate/deflate of zlib), signing (SHA-256).
     * The public key parameter (key->pk) is optional,
     * and used to verify the signature of the cipher data.
     */
    uecm_decipher_cipher_data(cipher_data, cipher_data_size, key->sk, key->pk, &decipher_data, &decipher_data_size,
        "aes-256-cbc", "sha256");

    /* Check if decipher data and plain data are equals */
    ei_logger_info("Comparing decipher data with plain data...");
    if (plain_data_size == decipher_data_size && memcmp(decipher_data, plain_data, plain_data_size) == 0) {
        ei_logger_info("Plain data and decipher data match");
    } else {
        ei_logger_error("Plain data and decipher data doesn't match");
    }

clean_up:
    /* Clean_up variables */
    ueum_safe_free(plain_data);
    ueum_safe_free(cipher_data);
    ueum_safe_free(decipher_data);
    uecm_asym_key_destroy_all(key);

    /**
     * Each time ei_stacktrace API is used in libueum or libuecm,
     * an error is record to the stacktrace of the current thread.
     */
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }

    uecm_uninit(); /* uninitialize LibUnknownEchoCryptoModule */

    ei_uninit(); /* uninitialize LibErrorInterceptor */

    return 0;
}
```

Compile statically:
```bash
gcc -o basic_usage examples/basic_usage.c -lei_static -luecm_static -lueum_static -pthread lib/openssl/lib/libssl.a lib/openssl/lib/libcrypto.a lib/zlib/lib/libz.a -ldl
```

Run:
```bash
./basic_usage "Hello world !"
```

*note*: `-pthread` and `-ldl` flags are necessary for Unix systems.

# Dependencies
* [LibErrorInterceptor](https://github.com/swasun/LibErrorInterceptor), a lightweight and cross-plateform library to handle stacktrace and logging in C99.
* [LibUnknownEchoUtilsModule](https://github.com/swasun/LibUnknownEchoUtilsModule) Utils module of [LibUnknownEcho](https://github.com/swasun/LibUnknownEcho). Last version
* [Openssl](https://github.com/openssl/openssl) provides general cryptographic and X.509 support needed by SSL/TLS but
	not logically part of it. Version 1.1.0.
* [Zlib](https://github.com/madler/zlib) A massively spiffy yet delicately unobtrusive compression library. Version 1.2.11.

# Architecture

## Facade design pattern
The facade design pattern is use to simplify the complexity of a module.
In the module, we have 2 to 4 sub folders which are:
* api: that contains the highest level of functions/structs of the module.
* impl: that contains implementation(s) a api files.
* factory (optional): that contains factories to create complex objects from the api files.
* utils (optional): that contains utils functions only used in this module.

# Cross-plateform

Successfully tested on the following OS (on 64 bits):
* Ubuntu 14.04
* Ubuntu 16.04
* Windows 10
