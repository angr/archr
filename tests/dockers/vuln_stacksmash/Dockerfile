from ubuntu:18.04

RUN dpkg --add-architecture i386 && apt update && apt install -y libc6:i386

copy vuln_stacksmash /
entrypoint [ "/vuln_stacksmash" ]
