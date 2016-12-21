#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "common.h"


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
	int ret=0;
	char *ip = "127.0.0.1";
	int port = 9199;

	char data[4096] = {0};
	int data_len;
	// [1] Create a tcp client to server
	int remote_sock = reconnect(ip,port,5);
	// [2] start a loop to receive netPacket
	net_buff_t *current_pack = NULL;
	while(1)
	{
		usleep(200);
		//printf("[Report Thread]------------------>\n");
		
		// [2.1] 从队列中取出一个数据包
		// [2.2] 解析数据包并按协议格式封装数据 src dst time_stamp
		ret = get_a_pack_by_timeout();
		if(ret < 0)
		{
			//handle error;
		}
		// [2.3]
		ret = send_pack_by_timeout(remote_sock,data,data_len,5);
		if(ret < 0)	//handle error
		{	
			if(ret == -1)
			{
			 	//如果tcp连接断开就需要不断的重连
				close(remote_sock);
				remote_sock = -1;
				while(remote_sock < 0)
				{
					remote_sock = reconnect(ip,port,5);
				}
			}else
			{
				//处理其他发送错误
			}

		}
		current_pack = net_get_buff(g_net_queue);
		if(current_pack == NULL)
		{
			//fprintf(stderr,"Error on Get buff.\n");
		}
		else
		{
			printf("buff size[%d] --> %s\n",current_pack->size,current_pack->buff);
			del_net_buff(current_pack);
		}
	}
	
}
