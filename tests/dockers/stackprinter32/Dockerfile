from ubuntu:bionic
RUN dpkg --add-architecture i386 && apt update && apt install -y libc6:i386
copy stackprinter /
entrypoint [ "/stackprinter", "AAAAAAAA", "BBBBBBBBB" ]
