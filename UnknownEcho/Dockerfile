# Download base image ubuntu 16.04
FROM ubuntu:16.04

MAINTAINER Charly Lamothe

# Update Ubuntu Software repository and install some dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    wget \
    git \
    automake \
    ccache && \
    # Clean up APT when done, and remove unnecessary intermediate tar files
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Clone LibUnknownEcho and go to the install folder
RUN git clone https://github.com/swasun/LibUnknownEcho.git && \
    cd LibUnknownEcho &&
    ./build_release.sh && \
    ./install.sh

VOLUME /LibUnknownEcho/out

EXPOSE 5001 5002
