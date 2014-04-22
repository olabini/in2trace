
#ifndef _IN2TRACE_H_
#define _IN2TRACE_H_

#include <config.h>

#include <sys/param.h>
#include <sys/types.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

typedef struct trace_entry_t {
	uint16_t rport;
	uint16_t lport;
	uint32_t seq;
	uint32_t ack;
    time_t last_touch;

	int maxhop;
	int cnt;

	struct {
		struct in_addr ip_trace[MAX_HOPS + 1];
		struct in_addr icmp_trace[MAX_HOPS + 1];
		int16_t proto[MAX_HOPS + 1];
	} listener;

    struct trace_host_entry_t *host_entry;
    struct trace_entry_t *next;
} trace_entry_t;

typedef struct trace_host_entry_t {
	struct in_addr rip;
	struct in_addr lip;
    trace_entry_t *traces;
    struct trace_host_entry_t *next;
} trace_host_entry_t;

typedef struct intrace_t {
	pthread_mutex_t mutex;
    bool hasChange;
    void (*display_function)(void *);

	struct {
		int sndSocket;
	} sender;

    int rcvSocketTCP;
    int rcvSocketICMP;

    trace_host_entry_t *traces;
} intrace_t;

#define _IT_AF(i) AF_INET
#define _IT_IPPROTO(i) IPPROTO_IP
#define _IT_PKTINFO(i) IP_PKTINFO
#define _IT_ICMPPROTO(i) IPPROTO_ICMP

#include <debug.h>
#include <threads.h>
#include <errors.h>
#include <listener.h>
#include <sender.h>
#include <display.h>
#include <ipv4.h>

#endif
