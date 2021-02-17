from ubuntu:focal
RUN dpkg --add-architecture i386 && apt update && apt install -y libc6:i386 -o APT::Immediate-Configure=0
copy offsetprinter /
entrypoint [ "/offsetprinter" ]
