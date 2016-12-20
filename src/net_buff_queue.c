#include <stdio.h>
#include "net_buff_queue.h"




net_buff_t *new_net_buff(int size)
{
	net_buff_t *b = NULL;
	b = (net_buff_t *)malloc(sizeof(net_buff_t));
	if(b !=  NULL)
	{
		b->size = size;
		b->buff = NULL;
		b->buff = (unsigned char *)malloc(size);
		if(b->buff == NULL)
		{
			free(b);
			b = NULL;
		}
	}
	return b;
}


void del_net_buff(net_buff_t *buff)
{
	if(!buff)
		return;
	if(buff->buff)
		free(buff->buff);

	free(buff);
}

/******************************************************/

net_buff_queue_t *net_new_queue(int max_size)
{
	net_buff_queue_t *q = NULL;
	q = (net_buff_queue_t *)malloc(sizeof(net_buff_queue_t));

	if(q != NULL)
	{
		MUTEX_SETUP(q->lock);
		q->max_size = max_size;
		q->netbuff_q = initQueue(max_size);
		q->ref = 0;
	}

	return q;
}

void net_del_queue(net_buff_queue_t *q)
{
	if(q->ref != 0)
		return ;
	net_buff_t *b = NULL;


	//free all left buff
	while(QUEUE_SIZE(q->netbuff_q) >0)
	{
		b = front(q->netbuff_q);
		if(b != NULL)
		{
			dequeue(q->netbuff_q);
			del_net_buff(b);
			b = NULL;
		}
	}
		
	// clean up lock			
	MUTEX_CLEANUP(q->lock);
	free(q);
}




int net_add_buff(net_buff_queue_t *q,net_buff_t *buff)
{
	int ret = 0;
	if(buff== NULL || q == NULL){
		return -1;
	}

	MUTEX_LOCK(q->lock);
	if(QUEUE_SIZE(q->netbuff_q) >= q->max_size){
		MUTEX_UNLOCK(q->lock);
		return -2;
	}
	ret = enqueue(q->netbuff_q,(void *)buff);
	MUTEX_UNLOCK(q->lock);

	return ret;
}

net_buff_t * net_get_buff(net_buff_queue_t *q)
{
	net_buff_t *ret = NULL;

	if(q == NULL)
		return NULL;

	MUTEX_LOCK(q->lock);

	if(QUEUE_SIZE(q->netbuff_q) <= 0)
	{
		MUTEX_UNLOCK(q->lock);
		return NULL;
	}

	ret = front(q->netbuff_q);

	dequeue(q->netbuff_q);
	MUTEX_UNLOCK(q->lock);

	return ret;
}










