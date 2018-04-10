# Download base image ubuntu 16.04
FROM ubuntu:16.04

MAINTAINER Charly Lamothe

# Update Ubuntu Software repository and install some dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    git

# Install libssl version 1.10 (that contains also libcrypto 1.10)
RUN wget https://www.openssl.org/source/openssl-1.1.0.tar.gz \
    && tar -zxvf openssl-1.1.0.tar.gz \
    && cd openssl-1.1.0 \
    && ./config \
    && make \
    && make install \
    && cd ..

# Install zlib version 1.2.11
RUN wget https://zlib.net/zlib-1.2.11.tar.gz \
    && tar -zxvf zlib-1.2.11.tar.gz \
    && cd zlib-1.2.11 \
    && ./configure \
    && make \
    && make install \
    && cd ..

# Install a recent version of CMake.
RUN wget http://www.cmake.org/files/v3.11/cmake-3.11.0.tar.gz \
    && tar xf cmake-3.11.0.tar.gz \
    && cd cmake-3.11.0 \
    && ./configure \
    && make \
    && cd ..

# Install LibUnknownEcho
RUN git clone https://github.com/swasun/LibUnknownEcho.git \
    && cd LibUnknownEcho \
    && ./build_release.sh \
    && ./install.sh \
    && cd ..

ADD LibUnknownEcho/bin/channel_server_protocol_example /app/

EXPOSE 5001 5002

WORKDIR /app

CMD ./channel_server_protocol_example

# Clean up APT when done, and remove unnecessary intermediate tar files
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
