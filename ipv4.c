#include <config.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include <in2trace.h>

static inline int ipv4_checkTcp(intrace_t * intrace, ip4pkt_t * pkt, uint32_t pktlen) {
	if (pktlen < sizeof(struct ip)) {
		return errPkt;
    }

	if (pktlen < ((pkt->iph.ip_hl * 4) + sizeof(struct tcphdr))) {
		return errPkt;
    }

	return errNone;
}

trace_entry_t *createOrFindTrace(intrace_t *intrace, struct in_addr *src, uint32_t seq) {
    char addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, src, addr, sizeof(addr));
    printf("Looking for: %-41s with seq: 0x%08x\n", addr, seq);
    return NULL;
}

void ipv4_tcp_sock_ready(intrace_t *intrace, struct msghdr *msg) {
	ip4pkt_t *pkt = msg->msg_iov->iov_base;
	uint32_t pktlen = msg->msg_iov->iov_len;

	if (ipv4_checkTcp(intrace, pkt, pktlen) < 0)
		return;

	while (pthread_mutex_lock(&intrace->mutex)) ;
    struct tcphdr *tcph = (struct tcphdr *)((uint8_t *) & pkt->iph + ((uint32_t) pkt->iph.ip_hl * 4));

    //    trace_entry_t *current_trace =
    createOrFindTrace(intrace, &pkt->iph.ip_src, ntohl(tcph->th_seq));

	while (pthread_mutex_unlock(&intrace->mutex)) ;
}

void ipv4_icmp_sock_ready(intrace_t * intrace, struct msghdr *msg) {
}
