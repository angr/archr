FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y build-essential \
                       python-is-python3 \
                       python3-dev \
                       python3-pip \
                       curl \
                       wget \
                       tcpdump \
                       tshark \
                       inotify-tools
