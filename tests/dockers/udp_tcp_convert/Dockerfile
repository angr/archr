FROM ubuntu:focal

RUN apt-get update && apt-get install -y build-essential make
COPY . /udp_tcp_convert
WORKDIR udp_tcp_convert
RUN make
CMD ["./udp_server"]
