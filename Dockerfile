# Download base image ubuntu 16.04
FROM ubuntu:16.04

MAINTAINER Charly Lamothe

# Update Ubuntu Software repository and install some dependencies
RUN apt-get update && \
    #apt-get install --no-install-recommends --no-upgrade -y \
    apt-get install -y \
    #ca_certificates
    build-essential \
    wget \
    git \
    pkg-config \
    automake \
    libtool \
    ccache && \
    # Clean up APT when done, and remove unnecessary intermediate tar files
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Clone LibUnknownEcho and go to the install folder
RUN git clone https://github.com/swasun/LibUnknownEcho.git && \
    cd LibUnknownEcho && \
    mkdir install

# Install libssl version 1.10 (that contains also libcrypto 1.10)
RUN cd /LibUnknownEcho/install && \
    wget https://www.openssl.org/source/openssl-1.1.0.tar.gz && \
    tar -zxvf openssl-1.1.0.tar.gz && \
    cd openssl-1.1.0 && \
    ./config && \
    make && \
    make install && \
    cp libcrypto.so.1.1 ../../lib/linux/ && \
    cp libssl.so.1.1 ../../lib/linux/ && \
    cd .. && \
    rm -rf openssl-1.1.0.tar.gz && \
    rm -rf openssl-1.1.0

# Install zlib version 1.2.11
RUN cd /LibUnknownEcho/install && \
    wget https://zlib.net/zlib-1.2.11.tar.gz && \
    tar -zxvf zlib-1.2.11.tar.gz && \
    cd zlib-1.2.11 && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm -rf zlib-1.2.11.tar.gz && \
    rm -rf zlib-1.2.11

# Install a recent version of CMake.
RUN cd /LibUnknownEcho/install && \
    wget http://www.cmake.org/files/v3.11/cmake-3.11.0.tar.gz && \
    tar xf cmake-3.11.0.tar.gz && \
    cd cmake-3.11.0 && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm -rf cmake-3.11.0.tar.gz && \
    rm -rf cmake-3.11.0

# Install libuv version 1.20.3:
RUN cd /LibUnknownEcho/install && \
    git clone https://github.com/libuv/libuv.git && \
    cd libuv && \
    ls && \
    ls .. && \
    sh autogen.sh && \
    make && \
    make check && \
    make install && \
    cd .. && \
    rm -rf libuv

# Install libei:
RUN cd /LibUnknownEcho/install && \
    git clone https://github.com/swasun/LibErrorInterceptor.git && \
    cd LibErrorInterceptor && \
    ./build_release.sh && \
    ./install.sh && \
    cd .. && \
    rm -rf LibErrorInterceptor

# Remove temp directory install
RUN rm -rf /LibUnknownEcho/install

# Build and install LibUnknownEcho
RUN cd /LibUnknownEcho &&  \
    ./build_release.sh && \
    ./install.sh && \
    cd ..

VOLUME /LibUnknownEcho/out

EXPOSE 5001 5002
