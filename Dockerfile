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
    ccache && \
    # Clean up APT when done, and remove unnecessary intermediate tar files
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install libssl version 1.10 (that contains also libcrypto 1.10)
RUN wget https://www.openssl.org/source/openssl-1.1.0.tar.gz && \
    tar -zxvf openssl-1.1.0.tar.gz && \
    cd openssl-1.1.0 && \
    ./config && \
    make && \
    make install && \
    cd .. && \
    rm -rf openssl-1.1.0.tar.gz && \
    rm -rf openssl-1.1.0

# Install zlib version 1.2.11
RUN wget https://zlib.net/zlib-1.2.11.tar.gz && \
    tar -zxvf zlib-1.2.11.tar.gz && \
    cd zlib-1.2.11 && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm -rf zlib-1.2.11.tar.gz && \
    rm -rf zlib-1.2.11

# Install a recent version of CMake.
RUN wget http://www.cmake.org/files/v3.11/cmake-3.11.0.tar.gz && \
    tar xf cmake-3.11.0.tar.gz && \
    cd cmake-3.11.0 && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm -rf cmake-3.11.0.tar.gz && \
    rm -rf cmake-3.11.0

# Install LibUnknownEcho
RUN git clone https://github.com/swasun/LibUnknownEcho.git && \
    cd LibUnknownEcho && \
    ./build_release.sh && \
    ./install.sh && \
    cd ..

VOLUME /LibUnknownEcho/out

EXPOSE 5001 5002
