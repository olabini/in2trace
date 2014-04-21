
#ifndef _IN2TRACE_H_
#define _IN2TRACE_H_

#include <sys/param.h>
#include <sys/types.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
	pthread_mutex_t mutex;

	struct {
		int sndSocket;
	} sender;

    int rcvSocketTCP;
    int rcvSocketICMP;
} intrace_t;


#include <debug.h>
#include <threads.h>
#include <errors.h>

#endif
