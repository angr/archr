#define _GNU_SOURCE

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>

#define DEBUG 1

#define PREENY_MAX_FD 8192

//
// originals
//
int (*original_socket)(int, int, int);
int (*original_close)(int);
int (*original_select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int (*original_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int (*original_sendto)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen);

struct sockaddr_in *addrs[PREENY_MAX_FD] = {0};
int fds[PREENY_MAX_FD] = {0};
int udp_fds[PREENY_MAX_FD] = {0};
fd_set r_fds;

__attribute__((destructor)) void preeny_desock_shutdown()
{
	int i;

	if (DEBUG)
		printf("shutting down desock...\n");

	for (i = 0; i < PREENY_MAX_FD; i++)
	{
		if (addrs[i] != NULL)
		{
			free(addrs[i]);
			original_close(fds[i]);
		}
	}

	if (DEBUG)
		printf("... shutdown complete!\n");
}
__attribute__((constructor)) void preeny_desock_orig()
{
	original_socket = dlsym(RTLD_NEXT, "socket");
	original_close = dlsym(RTLD_NEXT, "close");
	original_sendto = dlsym(RTLD_NEXT, "sendto");
	original_select = dlsym(RTLD_NEXT, "select");
	original_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
}

void log_bytes(char *buf, int len)
{
	printf("String: %s\n", buf);
	if (len > 0)
	{
		char new_buf[(len * 2) + 1];
		for (int i = 0; i < len; i++)
		{
			sprintf(new_buf + (i * 2), "%02hhx", buf[i]);
		}
		new_buf[len * 2] = 0;
		printf("Bytes: 0x%s\n", new_buf);
	}
}
int get_fd(struct sockaddr_in *addr)
{
	if (DEBUG && addr->sin_addr.s_addr != NULL)
		printf("Getting fd for: %s:%d\n", inet_ntoa(addr->sin_addr), addr->sin_port);
	for (int i = 0; i < PREENY_MAX_FD; i++)
	{
		if (addrs[i] == NULL)
			continue;

		if (DEBUG && addr->sin_addr.s_addr != NULL)
			printf("Looking at: %s:%d with FD %d\n", inet_ntoa(addrs[i]->sin_addr), addrs[i]->sin_port, fds[i]);
		if (addrs[i]->sin_addr.s_addr == addr->sin_addr.s_addr && addrs[i]->sin_port == addr->sin_port)
		{
			return fds[i];
		}
	}

	return -1;
}

void set_fd(struct sockaddr_in *addr, int fd, int udp_fd)
{
	if (DEBUG)
		printf("setting fd %d and udp_fd %d for: %s:%d\n", fd, udp_fd, inet_ntoa(addr->sin_addr), addr->sin_port);
	if (addrs[fd] != NULL)
		free(addrs[fd]);

	struct sockaddr_in *peer_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(peer_addr, '0', sizeof(struct sockaddr_in));
	// Set the contents in the peer's sock_addr.
	// Make sure the contents will simulate a real client that connects with the intercepted server, as the server may depend on the contents to make further decisions.
	// The followings set-up should be fine with Nginx.
	peer_addr->sin_family = AF_INET;
	peer_addr->sin_addr.s_addr = addr->sin_addr.s_addr;
	peer_addr->sin_port = addr->sin_port;

	addrs[fd] = peer_addr;
	fds[udp_fd] = fd;
	udp_fds[fd] = udp_fd;
	FD_SET(fd, &r_fds);
}

int socket(int domain, int type, int protocol)
{
	if (DEBUG)
		printf(" --------------------- Calling socket ---------------------\n");
	if (type == SOCK_DGRAM)
	{
		type = SOCK_STREAM;
		if (DEBUG)
			printf("Setting socket to SOCK_STREAM\n");
	}

	return original_socket(domain, type, protocol);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	if (DEBUG)
		printf(" --------------------- Calling recvfrom ---------------------\n");
	if (fds[sockfd] > 0 || get_fd(src_addr) > 0)
	{
		original_close(fds[sockfd]);
		free(addrs[fds[sockfd]]);
		addrs[fds[sockfd]] = NULL;
		fds[sockfd] = -1;
		udp_fds[fds[sockfd]] = -1;
	}

	if (listen(sockfd, PREENY_MAX_FD) != 0)
	{
		return -1;
	}
	if (DEBUG)
		printf("Listening on socket: %d\n", sockfd);

	int new_fd = accept(sockfd, src_addr, addrlen);
	if (DEBUG)
	{
		printf("Accepting on socket: %d\n", sockfd);
		printf("Returned fd: %d\n", new_fd);
	}
	if (new_fd < 0)
	{
		return -1;
	}
	set_fd(src_addr, new_fd, sockfd);
	// initialize a sockaddr_in for the peer
	if (DEBUG)
		printf("Max read amount: %d\n", len);
	int read_amount = read(new_fd, buf, len);

	if (DEBUG)
	{
		printf("Read Amount: %d\n", read_amount);
		log_bytes(buf, read_amount);
	}

	return read_amount;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dst_addr, socklen_t addrlen)
{
	if (DEBUG)
	{
		printf(" --------------------- Calling sendto ---------------------\n");
		printf("Sending: %d\n", len);
		printf("Sent: %s\n", buf);
	}
	int send_fd = fds[sockfd];
	if (send_fd <= 0)
		send_fd = get_fd(dst_addr);
	if (DEBUG)
		printf("Send fd: %d\n", send_fd);
	if (send_fd <= 0)
	{
		return -1;
	}
	int amount_written = write(send_fd, buf, len);
	if (DEBUG)
	{
		printf("Amount Sent: %d\n", amount_written);
		log_bytes(buf, len);
	}
	return amount_written;
}

int close(int sockfd)
{
	if (DEBUG)
	{
		printf(" --------------------- Calling close ---------------------\n");
		printf("Closing FD: %d\n", sockfd);
	}
	if (fds[sockfd] > 0)
	{
		int old_fd = fds[sockfd];
		original_close(fds[sockfd]);
		addrs[old_fd] = NULL;
		return original_close(udp_fds[old_fd]);
	}

	return original_close(sockfd);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
	if (DEBUG)
		printf(" --------------------- Calling select ---------------------\n");
	int ready_fds = original_select(nfds, readfds, writefds, exceptfds, timeout);
	if (DEBUG)
		printf("READY FDS: %d\n", ready_fds);
	return ready_fds;
}
