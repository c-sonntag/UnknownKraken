# Dependencies list
* [LibErrorInterceptor](https://github.com/swasun/LibErrorInterceptor), a lightweight and cross-plateform library to handle stacktrace and logging in C99.
* [LibUnknownEchoUtilsModule](https://github.com/swasun/LibUnknownEchoUtilsModule) Utils module of [LibUnknownEcho](https://github.com/swasun/LibUnknownEcho). Last version
* [LibUnknownEchoCryptoModule](https://github.com/swasun/LibUnknownEchoCryptoModule) Crypto module of [LibUnknownEcho](https://github.com/swasun/LibUnknownEcho). Last version.
* [Libssl](https://github.com/openssl/openssl) Provides the client and server-side implementations for SSLv3 and TLS. Version 1.1
* [Libcrypto](https://github.com/openssl/openssl) Provides general cryptographic and X.509 support needed by SSL/TLS but not logically part of it. Version 1.1.
* [Zlib](https://github.com/madler/zlib) A massively spiffy yet delicately unobtrusive compression library. Version 1.2.11.
* A recent version of CMake.
* Optional: ccache is supported to reduce build time of LibUnknownEcho.
* Optional: valgrind for memory debugging/memory leak detection

# Dependencies installation

## Installation from sources
* Download last version of LibUnknownEcho
```bash
git clone https://github.com/swasun/LibUnknownEcho.git
```

## With Docker (outdated)

### From Docker Hub
```bash
docker run -it -P swasun/libunknownecho bash
```

### From Dockerfile
```bash
wget https://github.com/swasun/LibUnknownEcho/Dockerfile && \
docker build -t libunknownecho . && \
docker run -it -P libunknownecho bash
```

# Build LibUnknownEcho

In debug mode:
```bash
./build_debug.sh
```

In release mode:
```bash
./build_release.sh
```

Clean-up build files, binaries:
```bash
./clean.sh
```

Install:
```bash
./build_release.sh && sudo ./install.sh
```

The static lib will appear in the `bin` directory, and all the examples in `bin/debug/examples` or `bin/release/examples`, according to the compilation mode.