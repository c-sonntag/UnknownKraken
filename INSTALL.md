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
    * wget https://zlib.net/zlib-1.2.11.tar.gz
    * tar -zxvf zlib-1.2.11.tar.gz
    * cd zlib-1.2.11
    * ./configure
    * make
    * sudo make install
* Install a recent version of CMake.
* Compile LibUnknownEcho
    * In debug mode : ./build_debug.sh
    * In release mode : ./build_release.sh
    * Clean all : ./clean.sh
The static lib will appear in bin folder, and all the examples in bin/debug/examples or bin/release/examples according to the compilation mode.

***


# Other dependencies
* Make, CMake for compilation.
* Valgrind for memory debugging/memory leak detection.

***


# Common errors
* Could NOT find PkgConfig (missing: PKG_CONFIG_EXECUTABLE)
On Debian distributions, you can fix this by installating pgk-config packet with :
sudo apt-get install pkg-config
