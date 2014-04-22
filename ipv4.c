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

bool should_process_packet(intrace_t *intrace, struct tcphdr *tcph) {
    // here we can restrict based on port or ip number for example
    return true;
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
    trace->listener.proto[hop] = IPPROTO_TCP;
    trace->listener.printed[hop] = false;
    memcpy(&trace->listener.ip_trace[hop].s_addr, &pkt->iph.ip_src, sizeof(pkt->iph.ip_src));
    trace->maxhop = hop;
    trace->cnt = MAX_HOPS;
}

void process_rst(trace_entry_t *trace, ip4pkt_t *pkt) {
    int hop = trace->cnt - 1;
    memcpy(&trace->listener.ip_trace[hop].s_addr, &pkt->iph.ip_src, sizeof(pkt->iph.ip_src));
    trace->listener.printed[hop] = false;
    trace->listener.proto[hop] = -1;
    trace->maxhop = hop;
    trace->cnt = MAX_HOPS;
    // should we mention that something is done here?
}

void process_regular_packet(trace_entry_t *trace, struct tcphdr *tcph, ip4pkt_t *pkt) {
    memcpy(&trace->host_entry->lip, &pkt->iph.ip_dst, sizeof(pkt->iph.ip_dst));
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

void ipv4_tcp_sock_ready(intrace_t *intrace, struct msghdr *msg) {
	ip4pkt_t *pkt = msg->msg_iov->iov_base;
    struct tcphdr *tcph = tcp_header_from(msg);
	if (tcph == NULL) {
		return;
    }

    if(should_process_packet(intrace, tcph)) {
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
