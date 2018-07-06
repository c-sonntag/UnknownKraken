# Dependencies list
* libssl >= 1.1.0 for TLS connection.
* libcrypto >= 1.1.0 for encryption.
* zlib >= 1.2.11 for compression.
* libei for stacktrace and logging.
* A recent version of CMake.
* Optional: ccache is supported to reduce build time of LibUnknownEcho.
* Optional: valgrind for memory debugging/memory leak detection

# Dependencies installation

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

## Installation from sources
* Download last version of LibUnknownEcho
```bash
git clone https://github.com/swasun/LibUnknownEcho.git
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