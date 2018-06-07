#!/bin/bash

os_type="unknown"

case "$OSTYPE" in
    linux*)   os_type="linux" ;;
    msys*)    os_type="windows" ;;
    *)        os_type="unsuported" ;;
esac

if [ $os_type == "unsuported" ]; then
    printf "Your OS isn't supported for now\n"
    exit 1
fi

mkdir -p install && \
cd install

# Install libssl version 1.10 (that also contains libcrypto 1.10):
wget https://www.openssl.org/source/openssl-1.1.0.tar.gz && \
tar -zxf openssl-1.1.0.tar.gz && \
cd openssl-1.1.0 && \
./config && \
make && \
make install && \
cd ..

if [ $os_type == "linux" ]; then
    cp libcrypto.so.1.1 ../lib/linux/ && \
    cp libssl.so.1.1 ../lib/linux/
elif [ $os_type == "windows" ]; then
    cp libcrypto* ../lib/windows/ && \
    cp libssl* ../lib/windows/
fi

rm -rf openssl-1.1.0.tar.gz && \
rm -rf openssl-1.1.0

# Install zlib version 1.2.11:
wget https://zlib.net/zlib-1.2.11.tar.gz && \
tar -zxf zlib-1.2.11.tar.gz && \
cd zlib-1.2.11 && \
./configure && \
make && \
make install && \
cd .. && \
rm -rf zlib-1.2.11.tar.gz && \
rm -rf zlib-1.2.11
    
# Install libuv version 1.20.3:
apt install -y automake libtool && \
git clone https://github.com/libuv/libuv.git && \
cd libuv && \
sh autogen.sh && \
make && \
make check && \
make install && \
cd .. && \
rm -rf libuv

# Install libei:
git clone https://github.com/swasun/LibErrorInterceptor.git && \
cd LibErrorInterceptor && \
./build_release.sh && \
./install.sh && \
cd .. && \
rm -rf LibErrorInterceptor

# Install a recent version of CMake.
wget http://www.cmake.org/files/v3.11/cmake-3.11.0.tar.gz && \
tar xf cmake-3.11.0.tar.gz && \
cd cmake-3.11.0 && \
./configure && \
make && \
make install && \
cd .. && \
rm -rf cmake-3.11.0.tar.gz && \
rm -rf cmake-3.11.0

# Remove temp directory install
cd .. && \
rm -rf install