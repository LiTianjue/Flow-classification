#ifndef NET_BUFF_QUEUE
#define NET_BUFF_QUEUE

#include "queue.h"
#include "lock.h"

typedef struct _net_buff_queue
{
	MUTEX_TYPE lock;
	int max_size;
	int ref;
	Queue *netbuff_q;
}net_buff_queue_t;


typedef struct _net_buff
{
	int size;
	unsigned char *buff;
}net_buff_t;




net_buff_t *new_net_buff(int size);
void del_net_buff(net_buff_t *buff);

net_buff_queue_t *net_new_queue(int max_size);
void net_del_queue(net_buff_queue_t *q);

int net_add_buff(net_buff_queue_t *q,net_buff_t *buff);
net_buff_t * net_get_buff(net_buff_queue_t *q);



#endif
