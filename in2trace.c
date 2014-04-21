#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <string.h>

#include <in2trace.h>

extern char *optarg;

int main(int argc, char **argv)
{
	int c;
	int dl = dlInfo, err;
	intrace_t intrace;

	bzero(&intrace, sizeof(intrace_t));

	printf("In2Trace, version 0.1\n");

	for (;;) {
		c = getopt(argc, argv, "d:");
		if (c < 0)
			break;

		switch (c) {
		case 'd':
			dl = atoi(optarg);
			break;
		default:
			break;
		}
	}

	/* Initialize subsystems */
	if ((err = _debug_init(dl, NULL)) < 0) {
		fprintf(stderr, "Can't initialize debug, err=%d!\n", err);
		return err;
	}

	return threads_process(&intrace);
}
