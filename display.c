#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>

#include <in2trace.h>

void count_entries_in(intrace_t *intrace, int counts[]) {
    counts[0] = 0;
    counts[1] = 0;

    trace_entry_t *current_trace;
    trace_host_entry_t *current = intrace->traces;
    while(current != NULL) {
        counts[0]++;
        current_trace = current->traces;
        while(current_trace != NULL) {
            counts[1]++;
            current_trace = current_trace->next;
        }
        current = current->next;
    }
}

#define REAPING_CUTOFF 10.0

void reap_old(intrace_t *intrace) {
    double diff;
    time_t current_time = time(NULL);

    trace_entry_t *current_trace;
    trace_entry_t *previous_trace;
    trace_entry_t *next_trace;
    trace_host_entry_t *previous = NULL;
    trace_host_entry_t *next;
    trace_host_entry_t *current = intrace->traces;
    while(current != NULL) {
        current_trace = current->traces;
        previous_trace = NULL;
        while(current_trace != NULL) {
            diff = difftime(current_time, current_trace->last_touch);
            if(diff > REAPING_CUTOFF) {
                next_trace = current_trace->next;
                if(previous_trace == NULL) {
                    current->traces = next_trace;
                } else {
                    previous_trace->next = next_trace;
                }
                free(current_trace);
                current_trace = next_trace;
            } else {
                previous_trace = current_trace;
                current_trace = current_trace->next;
            }
        }
        if(current->traces == NULL) {
            next = current->next;
            if(previous == NULL) {
                intrace->traces = next;
            } else {
                previous->next = next;
            }
            free(current);
            current = next;
        } else {
            previous = current;
            current = current->next;
        }
    }
}

void display_process_counter(void *intrace) {
    int counts[] = {0,0};
    count_entries_in((intrace_t *)intrace, counts);

    printf("\033[H\033[2J");
    printf("\033[%u;%uH", 0, 0);
    printf("separate hosts: %d -> separate traces: %d\n", counts[0], counts[1]);
}

void display_process_traces(void *_intrace) {
    intrace_t *intrace = (intrace_t *)_intrace;
    char locAddr[INET_ADDRSTRLEN], rmtAddr[INET_ADDRSTRLEN];
    trace_entry_t *current_trace;
    trace_host_entry_t *current = intrace->traces;

    while(current != NULL) {
        current_trace = current->traces;
        while(current_trace != NULL) {
            inet_ntop(AF_INET, (void*)&current->lip.s_addr, locAddr, sizeof(locAddr));
            inet_ntop(AF_INET, (void*)&current->rip.s_addr, rmtAddr, sizeof(rmtAddr));

            if (current_trace->cnt >= MAX_HOPS) {
                current_trace->cnt = 0;
            }
            //            printf("have stuff: %-15.15s   %-15.15s   and maxhops: %d and cnt: %d\n", locAddr, rmtAddr, current_trace->maxhop, current_trace->cnt);
            for (int i = 1; i <= current_trace->maxhop; i++) {
                const char *pktType = "NO REPLY";

                if (current_trace->listener.proto[i] == IPPROTO_TCP) {
                    pktType = "TCP";
                } else if (current_trace->listener.proto[i] == IPPROTO_ICMP) {
                    if(memcmp((void *)&current_trace->listener.ip_trace[i].s_addr, (void*)&current->rip.s_addr, 4)) {
                        pktType = "ICMP_TIMXCEED";
                    } else {
                        pktType = "ICMP_TIMXCEED NAT";
                    }
                } else if (current_trace->listener.proto[i] == -1) {
                    pktType = "TCP_RST";
                }

                char ipPktAddr[] = "  ---                                  ";
                if(memcmp((void *)&current_trace->listener.ip_trace[i].s_addr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 4)) {
                    inet_ntop(AF_INET, (void*)&current_trace->listener.ip_trace[i].s_addr, ipPktAddr, strlen(ipPktAddr));
                }

                char icmpPktAddr[] = "  ---                                  ";
                if(memcmp((void *)&current_trace->listener.icmp_trace[i].s_addr,  "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 4)) {
                    inet_ntop(AF_INET, (void*)&current_trace->listener.icmp_trace[i].s_addr, icmpPktAddr, strlen(icmpPktAddr));
                }

                printf("[Seq: 0x%08x, Ack: 0x%08x][L: %s/%d R: %s/%d] %2d. [<- %s] [%s]\n", current_trace->seq, current_trace->ack, locAddr, current_trace->lport, rmtAddr, current_trace->rport, i, ipPktAddr, pktType);
                fflush(stdout);
            }

            if (current_trace->cnt == 0 && current_trace->seq > 0) {
                current_trace->cnt = 1;
                current_trace->maxhop = 0;
                bzero(current_trace->listener.ip_trace, sizeof(current_trace->listener.ip_trace));
                bzero(current_trace->listener.icmp_trace, sizeof(current_trace->listener.icmp_trace));
            }

            current_trace = current_trace->next;
        }
        current = current->next;
    }
}

int display_process(intrace_t *intrace) {
    printf("\033[H\033[2J");
    fflush(stdout);
	for (;;) {
		/* Lock mutex */
		while (pthread_mutex_lock(&intrace->mutex)) ;

        if(intrace->hasChange) {
            intrace->display_function(intrace);
            intrace->hasChange = false;
        }

        reap_old(intrace);

		/* UnLock mutex */
		while (pthread_mutex_unlock(&intrace->mutex)) ;
		usleep(200000);
	}

	return errNone;
}
