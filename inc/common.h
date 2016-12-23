#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "lock.h"
#include "queue.h"
#include "net_buff_queue.h"

#define MAX_KEY_LEN	512
#define MAX_BPF_LEN	1024

typedef struct _prog_info_g
{
	MUTEX_TYPE lock;		//全局的线程锁

	int isset;
	char bpf[MAX_BPF_LEN];
	int updata_flag;
}prog_info_t;

//一个用于发送缓冲的队列
extern net_buff_queue_t *g_net_queue;

extern prog_info_t *g_info;
extern int g_debug;

static inline void GLOBAL_LOCK(prog_info_t* info)
{
	MUTEX_LOCK(info->lock);
}

static inline void GLOBAL_UNLOCK(prog_info_t* info)
{
	MUTEX_UNLOCK(info->lock);
}


static inline int move_string_common(char *str)
{
	char tmp[512]={'\0'};
	if(str[0]=='\"')
	{
		strcpy(tmp,str+1);
		if(tmp[strlen(tmp)-1]=='\"') {
			tmp[strlen(tmp)-1]='\0';
		} else {
			strcpy(str,tmp);
			return 1;
		}
		
		strcpy(str,tmp);
		return 0;
	}
	return 2;
}

int check_polic_ready();
int get_polic(char *out);

#endif
