from ubuntu:focal

RUN apt-get update -y && apt-get install -y socat

entrypoint []

cmd socat tcp-l:1337,reuseaddr exec:cat
expose 1337
