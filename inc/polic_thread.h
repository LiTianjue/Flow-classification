#ifndef POLIC_THREAD_H
#define POLIC_THREAD_H


typedef struct _polic_thread_info{
	char polic_ip[32];
	int  polic_port;
}p_thread_info_t;

void *polic_thread(void *arg);

int prase_polic_file(char *polic_file);

#endif /* POLIC_THREAD_H */
