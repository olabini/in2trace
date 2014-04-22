#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <in2trace.h>

static void sender_process(intrace_t * intrace) {
    trace_entry_t *current_trace;
    trace_host_entry_t *current;

	for (;;) {
		while (pthread_mutex_lock(&intrace->mutex)) ;

        current = intrace->traces;
        while(current != NULL) {
            current_trace = current->traces;
            while(current_trace != NULL) {

                if ((current_trace->cnt > 0) && (current_trace->cnt < MAX_HOPS)) {
                    ipv4_sendpkt(intrace, current_trace, 0, 0);
                    ipv4_sendpkt(intrace, current_trace, -1, 0);
                    ipv4_sendpkt(intrace, current_trace, 0, 1);
                    ipv4_sendpkt(intrace, current_trace, -1, 1);
                }

                current_trace->cnt++;
                current_trace = current_trace->next;
            }
            current = current->next;
        }

		while (pthread_mutex_unlock(&intrace->mutex)) ;
		usleep(750000);
	}
}

int sender_init(intrace_t * intrace) {
	char errbuf[256];
	int tmp = 1;

	intrace->sender.sndSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (intrace->sender.sndSocket < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "sender: Cannot open raw socket, %s\n", errbuf);
		return errSocket;
	}

	if (setsockopt(intrace->sender.sndSocket, IPPROTO_IP, IP_HDRINCL, (char *)&tmp, sizeof(tmp))) {
		debug_printf(dlError, "sender: Cannot setsockopt on socket\n");
		close(intrace->sender.sndSocket);
		return errSocket;
	}

	return errNone;
}

void *sender_thr(void *arg) {
	sender_process((intrace_t *) arg);
	return NULL;
}
