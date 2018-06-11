# Dependencies list
* libssl >= 1.1.0 for TLS connection.
* libcrypto >= 1.1.0 for encryption.
* libz >= 1.2.11 for compression.
* libuv >= 1.20.3 for networking and threading.
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

* Install libssl version 1.10 (that also contains libcrypto 1.10):
```bash
wget https://www.openssl.org/source/openssl-1.1.0.tar.gz && \
tar -zxvf openssl-1.1.0.tar.gz && \
cd openssl-1.1.0 && \
./config && \
make && \
sudo make install && \
cd ..
```

Then you can copy libssl and libcrypto librarie files in `lib/<os>`, where os is `linux` or `windows`.

* Install zlib version 1.2.11:
```bash
wget https://zlib.net/zlib-1.2.11.tar.gz && \
tar -zxvf zlib-1.2.11.tar.gz && \
cd zlib-1.2.11 && \
./configure && \
make && \
sudo make install && \
cd ..
```
    
* Install libuv version 1.20.3:
```bash
sudo apt install -y automake libtoolize && \
git clone https://github.com/libuv/libuv.git && \
cd libuv && \
sh autogen.sh && \
make && \
make check && \
sudo make install && \
cd ..
```

* Install libei:
```bash
git clone https://github.com/swasun/LibErrorInterceptor.git && \
cd LibErrorInterceptor && \
./buid_release && \
sudo ./install && \
cd ..
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

# FAQ
* Could NOT find PkgConfig (missing: PKG_CONFIG_EXECUTABLE)
On Debian distributions, you can fix this by installating `pgk-config` packet with:
```bash
sudo apt-get install pkg-config
```