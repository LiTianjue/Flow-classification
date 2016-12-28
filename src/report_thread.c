#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "common.h"
#include "handler_packet.h"
#include "report_thread.h"
#include "socket_helper.h"

#define DF_TIMEOUT	5


int reconnect(char *ip,int port,int timeout)
{
	return 0;
}

int get_a_pack_by_timeout()
{
	return 1;
}

int send_pack_by_timeout(int remote_sock,char *data,int data_len,int timeout)
{
	return 0;
}

void *report_thread(void *arg)
{
	pthread_detach(pthread_self());

	r_thread_info_t *r_info;
	r_info = (r_thread_info_t *)arg;

	int ret=0;
	char ip[32] ={0};
	int port = 0;


	strcpy(ip,r_info->report_ip);
	port = r_info->report_port;

	char data[4096] = {0};
	int data_len;
	int remote_sock = -1;
	net_buff_t *current_pack = NULL;
	int is_empty = 0;

	//  start a loop to receive netPacket
	//printf("[Report Thread]------------------>\n");
	while(1)
	{
		if(is_empty)
			usleep(200);

		// [1] Create a tcp client to server
		if(remote_sock <=0 ){
			remote_sock = mite_sock_openSocketByTimeout(ip,port,DF_TIMEOUT);
			if(g_debug)
				printf("open remote[%s:%d] socket %d\n",ip,port,remote_sock);
			if(remote_sock == -3)
				sleep(DF_TIMEOUT);
			continue;
		}


		current_pack = net_get_buff(g_net_queue);
		if(current_pack == NULL)
		{
			//fprintf(stderr,"Error on Get buff.\n");
			is_empty = 1;
			continue;
		}else
			is_empty = 0;

		
		/*
		 *	send tcp packet
		 *
		 *
		 *
		 */


		if(0)	//debug
		{
			struct mt_pkthdr *mtpkt;
			mtpkt = (struct mt_pkthdr *)(current_pack->buff);
			if(g_debug){
				printf("version :%02x\n",mtpkt->version);
				printf("total_len :%04x\n",mtpkt->total_len);
				printf("src :%08x\n",mtpkt->src_ip);
				printf("src_port :%0tx\n",mtpkt->src_port);
				printf("timestamp : %d\n",mtpkt->timestamp);
			}

		}

		// ---------------- send --------------------------

		if(g_debug)
			printf("write to reomot %d bytes\n",current_pack->size);
		ret = mite_sock_writeWithTimeout(remote_sock,current_pack->buff,current_pack->size,DF_TIMEOUT);

		if(ret != 0)	//handle error
		{	
			if(g_debug)
				printf("Close it \n");
			close(remote_sock);
			remote_sock = -1;
		}

		del_net_buff(current_pack);
	}
}
