#ifndef _SENDER_H_
#define _SENDER_H_

#define MAX_PAYL_SZ 256

extern int sender_init(intrace_t * intrace);
extern void *sender_thr(void *arg);

#endif
