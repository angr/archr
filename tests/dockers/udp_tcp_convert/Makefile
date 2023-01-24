SHELL = /bin/sh

OBJS =
CFLAG = -Wall -g
CC = gcc
INCLUDES =
LIBS =

all:
	${CC} ${CFLAGS} ${INCLUDES} udp_client.c -o udp_client ${OBJS} ${LIBS}
	${CC} ${CFLAGS} ${INCLUDES} tcp_client.c -o tcp_client ${OBJS} ${LIBS}
	${CC} ${CFLAGS} ${INCLUDES} udp_server.c -o udp_server ${OBJS} ${LIBS}

clean:
	rm udp_client udp_server tcp_client
