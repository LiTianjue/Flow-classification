#ifndef REPORT_THREAD_H
#define REPORT_THREAD_H


typedef struct _report_thread_info{
	char report_ip[32];
	int  report_port;
}r_thread_info_t;

void *report_thread(void *arg);


#endif /* REPORT_THREAD_H */
