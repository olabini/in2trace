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

int display_process(intrace_t *intrace) {
    int counts[] = {0,0};
	for (;;) {
		/* Lock mutex */
		while (pthread_mutex_lock(&intrace->mutex)) ;

        if(intrace->hasChange) {
            count_entries_in(intrace, counts);

            printf("-----------------------------------------------------------\n");
            printf("separate hosts: %d -> separate traces: %d\n", counts[0], counts[1]);
            printf("\n");

            intrace->hasChange = false;
        }

		/* UnLock mutex */
		while (pthread_mutex_unlock(&intrace->mutex)) ;
		usleep(200000);
	}

	return errNone;
}
