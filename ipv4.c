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

static inline unsigned short ipv4_cksum_tcp(u_int16_t * h, u_int16_t * d, int dlen) {
	unsigned int cksum;
	unsigned short answer = 0;

	cksum = h[0];
	cksum += h[1];
	cksum += h[2];
	cksum += h[3];
	cksum += h[4];
	cksum += h[5];

	cksum += d[0];
	cksum += d[1];
	cksum += d[2];
	cksum += d[3];
	cksum += d[4];
	cksum += d[5];
	cksum += d[6];
	cksum += d[7];
	cksum += d[8];
	cksum += d[9];

	dlen -= 20;
	d += 10;

	while (dlen >= 32) {
		cksum += d[0];
		cksum += d[1];
		cksum += d[2];
		cksum += d[3];
		cksum += d[4];
		cksum += d[5];
		cksum += d[6];
		cksum += d[7];
		cksum += d[8];
		cksum += d[9];
		cksum += d[10];
		cksum += d[11];
		cksum += d[12];
		cksum += d[13];
		cksum += d[14];
		cksum += d[15];
		d += 16;
		dlen -= 32;
	}

	while (dlen >= 8) {
		cksum += d[0];
		cksum += d[1];
		cksum += d[2];
		cksum += d[3];
		d += 4;
		dlen -= 8;
	}

	while (dlen > 1) {
		cksum += *d++;
		dlen -= 2;
	}

	if (dlen == 1) {
		*(unsigned char *)(&answer) = (*(unsigned char *)d);
		cksum += answer;
	}

	cksum = (cksum >> 16) + (cksum & 0x0000ffff);
	cksum += (cksum >> 16);

	return (unsigned short)(~cksum);
}

static inline int ipv4_check_tcp(ip4pkt_t * pkt, uint32_t pktlen) {
	if (pktlen < sizeof(struct ip)) {
		return errPkt;
    }

	if (pktlen < ((pkt->iph.ip_hl * 4) + sizeof(struct tcphdr))) {
		return errPkt;
    }

	return errNone;
}

trace_host_entry_t *create_host_entry(intrace_t *intrace, struct in_addr *src) {
    trace_host_entry_t *created = (trace_host_entry_t *)malloc(sizeof(trace_host_entry_t));
    bzero(created, sizeof(trace_host_entry_t));
    memcpy(&created->rip, src, sizeof(struct in_addr));
    created->next = intrace->traces;
    intrace->traces = created;
    return created;
}

trace_host_entry_t *find_host_entry(intrace_t *intrace, struct in_addr *src) {
    trace_host_entry_t *current = intrace->traces;
    while(current != NULL) {
        if(current->rip.s_addr == src->s_addr) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}


trace_entry_t *create_trace_entry(trace_host_entry_t *host_entry, uint32_t seq) {
    trace_entry_t *created = (trace_entry_t *)malloc(sizeof(trace_entry_t));
    bzero(created, sizeof(trace_entry_t));
    created->seq = seq;
    created->next = host_entry->traces;
    created->host_entry = host_entry;
    created->last_touch = time(NULL);
    host_entry->traces = created;
    return created;
}

trace_entry_t *find_trace_entry(trace_host_entry_t *host_entry, uint32_t seq) {
    trace_entry_t *current = host_entry->traces;
    while(current != NULL) {
        if(current->seq == seq) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

trace_entry_t *find_or_create_trace_entry(trace_host_entry_t *host_entry, uint32_t seq) {
    trace_entry_t *entry = find_trace_entry(host_entry, seq);
    if (entry == NULL) {
        entry = create_trace_entry(host_entry, seq);
    }
    return entry;
}

trace_host_entry_t *find_or_create_host_entry(intrace_t *intrace, struct in_addr *src) {
    trace_host_entry_t *hentry = find_host_entry(intrace, src);
    if (hentry == NULL) {
        hentry = create_host_entry(intrace, src);
    }
    return hentry;
}

trace_entry_t *create_or_find_trace(intrace_t *intrace, struct in_addr *src, uint32_t seq) {
    trace_host_entry_t *hentry = find_or_create_host_entry(intrace, src);
    return find_or_create_trace_entry(hentry, seq);
}

bool is_local(in_addr_t addr) {
    return addr == 1331776701;
}

bool should_process_packet(intrace_t *intrace, struct tcphdr *tcph, ip4pkt_t *pkt) {
    // here we can restrict based on port or ip number for example

    if(is_local(pkt->iph.ip_dst.s_addr) &&
       is_local(pkt->iph.ip_src.s_addr)) {
        return false;
    } else {
        return true;
    }
}

bool is_ack(trace_entry_t *trace, struct tcphdr *tcph) {
    return
        (tcph->th_flags & TH_ACK) &&
        ((trace->ack + 1 == ntohl(tcph->th_ack)) ||
         (trace->ack + 2 == ntohl(tcph->th_ack))) &&
        (trace->cnt > 0) &&
        (trace->cnt < MAX_HOPS);
}

bool is_rst(trace_entry_t *trace, struct tcphdr *tcph, ip4pkt_t *pkt) {
    return
        (tcph->th_flags & TH_RST) &&
        (trace->host_entry->lip.s_addr == pkt->iph.ip_dst.s_addr) &&
        (trace->lport == ntohs(tcph->th_dport)) &&
        (trace->rport == ntohs(tcph->th_sport)) &&
        (trace->cnt > 0) &&
        (trace->cnt < MAX_HOPS);
}

void process_ack(trace_entry_t *trace, ip4pkt_t *pkt) {
    int hop = trace->cnt - 1;
    trace->last_touch = time(NULL);
    trace->listener.proto[hop] = IPPROTO_TCP;
    memcpy(&trace->listener.ip_trace[hop].s_addr, &pkt->iph.ip_src, sizeof(pkt->iph.ip_src));
    trace->maxhop = hop;
    trace->cnt = MAX_HOPS;
}

void process_rst(trace_entry_t *trace, ip4pkt_t *pkt) {
    int hop = trace->cnt - 1;
    trace->last_touch = time(NULL);
    memcpy(&trace->listener.ip_trace[hop].s_addr, &pkt->iph.ip_src, sizeof(pkt->iph.ip_src));
    trace->listener.proto[hop] = -1;
    trace->maxhop = hop;
    trace->cnt = MAX_HOPS;
    // should we mention that something is done here?
}

void process_regular_packet(trace_entry_t *trace, struct tcphdr *tcph, ip4pkt_t *pkt) {
    memcpy(&trace->host_entry->lip, &pkt->iph.ip_dst, sizeof(pkt->iph.ip_dst));
    trace->last_touch = time(NULL);
    trace->rport = ntohs(tcph->th_sport);
    trace->lport = ntohs(tcph->th_dport);
    if (ntohl(tcph->th_seq)) {
        trace->seq = ntohl(tcph->th_seq);
    }
    if (ntohl(tcph->th_ack)) {
        trace->ack = ntohl(tcph->th_ack);
    }
}

struct tcphdr *tcp_header_from(struct msghdr *msg) {
	ip4pkt_t *pkt = msg->msg_iov->iov_base;
	uint32_t pktlen = msg->msg_iov->iov_len;
	if (ipv4_check_tcp(pkt, pktlen) < 0) {
		return NULL;
    }
    return (struct tcphdr *)((uint8_t *) & pkt->iph + ((uint32_t) pkt->iph.ip_hl * 4));
}


void ipv4_sendpkt(intrace_t * intrace, trace_entry_t *current_trace, int seq_skew, int ack_skew) {
	tcppkt4_t pkt;
	uint16_t pktSz = sizeof(pkt) - MAX_PAYL_SZ + 1;

	struct sockaddr_in raddr;
	struct {
		uint32_t saddr;
		uint32_t daddr;
		uint8_t zero;
		uint8_t protocol;
		uint16_t tcp_len;
	} __attribute__ ((__packed__)) pseudoh;

	raddr.sin_family = AF_INET;
	raddr.sin_port = htons(current_trace->rport);
	memcpy(&raddr.sin_addr.s_addr, &current_trace->host_entry->rip.s_addr, sizeof(raddr.sin_addr.s_addr));

	bzero(&pkt, pktSz);

	pkt.iph.ip_v = 0x4;
	pkt.iph.ip_hl = sizeof(pkt.iph) / 4;
	pkt.iph.ip_len = htons(pktSz);
	pkt.iph.ip_id = htons(current_trace->cnt);
	pkt.iph.ip_off = htons(IP_DF | (0 & IP_OFFMASK));
	pkt.iph.ip_ttl = current_trace->cnt;
	pkt.iph.ip_p = IPPROTO_TCP;
	memcpy(&pkt.iph.ip_src, &current_trace->host_entry->lip.s_addr, sizeof(pkt.iph.ip_src));
	memcpy(&pkt.iph.ip_dst, &current_trace->host_entry->rip.s_addr, sizeof(pkt.iph.ip_dst));

	pkt.tcph.th_sport = htons(current_trace->lport);
	pkt.tcph.th_dport = htons(current_trace->rport);
	pkt.tcph.th_seq = htonl(current_trace->ack + seq_skew);
	pkt.tcph.th_ack = htonl(current_trace->seq + ack_skew);
	pkt.tcph.th_off = sizeof(pkt.tcph) / 4;
	pkt.tcph.th_flags = TH_ACK | TH_PUSH;
	pkt.tcph.th_win = htons(0xFFFF);
	pkt.tcph.th_urp = htons(0x0);

	memset(&pkt.payload, '\0', 1);

	uint16_t l4len = pktSz - sizeof(pkt.iph);
	pseudoh.saddr = pkt.iph.ip_src.s_addr;
	pseudoh.daddr = pkt.iph.ip_dst.s_addr;
	pseudoh.zero = 0x0;
	pseudoh.protocol = pkt.iph.ip_p;
	pseudoh.tcp_len = htons(l4len);

	pkt.tcph.th_sum = ipv4_cksum_tcp((u_int16_t *) & pseudoh, (u_int16_t *) & pkt.tcph, l4len);

	sendto(intrace->sender.sndSocket, &pkt, pktSz, MSG_NOSIGNAL, (struct sockaddr *)&raddr, sizeof(struct sockaddr));
}

void ipv4_tcp_sock_ready(intrace_t *intrace, struct msghdr *msg) {
	ip4pkt_t *pkt = msg->msg_iov->iov_base;
    struct tcphdr *tcph = tcp_header_from(msg);
	if (tcph == NULL) {
		return;
    }

    if(should_process_packet(intrace, tcph, pkt)) {
        while (pthread_mutex_lock(&intrace->mutex)) ;

        intrace->hasChange = true;

        trace_entry_t *current_trace = create_or_find_trace(intrace, &pkt->iph.ip_src, ntohl(tcph->th_seq));

        if(is_ack(current_trace, tcph)) {
            process_ack(current_trace, pkt);
        } else if(is_rst(current_trace, tcph, pkt)) {
            process_rst(current_trace, pkt);
        } else {
            process_regular_packet(current_trace, tcph, pkt);
        }

        while (pthread_mutex_unlock(&intrace->mutex)) ;
    }
}

void ipv4_icmp_sock_ready(intrace_t * intrace, struct msghdr *msg) {
}
