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

int display_process(intrace_t * intrace) {
	for (;;) {
		/* Lock mutex */
		while (pthread_mutex_lock(&intrace->mutex)) ;

		/* UnLock mutex */
		while (pthread_mutex_unlock(&intrace->mutex)) ;
		usleep(200000);
	}

	return errNone;
}
