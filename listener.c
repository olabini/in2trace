#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <errno.h>
#include <stdio.h>

#include <in2trace.h>

static uint32_t listener_get_packet(intrace_t * intrace, int sock, uint8_t * buf, uint32_t buflen, struct msghdr *msg)
{
	bzero(msg, sizeof(struct msghdr));

	struct iovec iov;
	iov.iov_len = buflen;
	iov.iov_base = buf;

	char addrbuf[4096];
	char ansbuf[4096];
	msg->msg_name = addrbuf;
	msg->msg_namelen = sizeof(addrbuf);
	msg->msg_iov = &iov;
	msg->msg_iovlen = 1;
	msg->msg_control = ansbuf;
	msg->msg_controllen = sizeof(ansbuf);
	msg->msg_flags = 0;

	if (recvmsg(sock, msg, MSG_WAITALL) == -1) {
		return 0;
	}

	return msg->msg_controllen;
}

static void listener_tcp_sock_ready(intrace_t * intrace, int sock)
{
	struct msghdr msg;
	uint8_t buf[4096];
	if (listener_get_packet(intrace, sock, buf, sizeof(buf), &msg) == 0) {
		debug_printf(dlError, "Cannot get TCP packet\n");
		return;
	}

    ipv4_tcp_sock_ready(intrace, &msg);
}

static void listener_icmp_sock_ready(intrace_t * intrace, int sock)
{
	struct msghdr msg;
	uint8_t buf[4096];
	if (listener_get_packet(intrace, sock, buf, sizeof(buf), &msg) == 0) {
		debug_printf(dlError, "Cannot get ICMP packet\n");
		return;
	}

    ipv4_icmp_sock_ready(intrace, &msg);
}

static void listener_process(intrace_t * intrace)
{
	for (;;) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(intrace->rcvSocketTCP, &fds);
		FD_SET(intrace->rcvSocketICMP, &fds);
		int maxFd = intrace->rcvSocketTCP > intrace->rcvSocketICMP ? intrace->rcvSocketTCP : intrace->rcvSocketICMP;

		if (select(maxFd + 1, &fds, NULL, NULL, NULL) < 1)
			continue;

		if (FD_ISSET(intrace->rcvSocketTCP, &fds))
			listener_tcp_sock_ready(intrace, intrace->rcvSocketTCP);

		if (FD_ISSET(intrace->rcvSocketICMP, &fds))
			listener_icmp_sock_ready(intrace, intrace->rcvSocketICMP);
	}
}

int listener_init(intrace_t * intrace)
{
	char errbuf[512];

	intrace->rcvSocketTCP = socket(_IT_AF(intrace), SOCK_RAW, IPPROTO_TCP);
	if (intrace->rcvSocketTCP < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "listener: Cannot open raw TCP socket, '%s'\n", errbuf);
		return errSocket;
	}

	intrace->rcvSocketICMP = socket(_IT_AF(intrace), SOCK_RAW, _IT_ICMPPROTO(intrace));
	if (intrace->rcvSocketTCP < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "listener: Cannot open raw ICMPv6 socket, '%s'\n", errbuf);
		return errSocket;
	}

	int on = 1;
	if (setsockopt(intrace->rcvSocketTCP, _IT_IPPROTO(intrace), _IT_PKTINFO(intrace), &on, sizeof(on)) == -1) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "listener: Cannot set IPV6_RECVPKTINFO on TCP socket, '%s'\n", errbuf);
		return errSocket;
	}
	if (setsockopt(intrace->rcvSocketICMP, _IT_IPPROTO(intrace), _IT_PKTINFO(intrace), &on, sizeof(on)) == -1) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "listener: Cannot set IPV6_RECVPKTINFO on ICMP socket, '%s'\n", errbuf);
		return errSocket;
	}

	return errNone;
}

void *listener_thr(void *arg)
{
	listener_process((intrace_t *) arg);

	return NULL;
}
