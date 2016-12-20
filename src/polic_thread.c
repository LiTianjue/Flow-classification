#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "socket_helper.h"
#include "common.h"


void *polic_thread(void *arg)
{
	int ret=0;
	char *ip = "127.0.0.1";
	int port = 9199;

	char data[4096] = {0};
	int data_len;
	// [1] Create a tcp server for receiving polic
	int listen_sock  = 0;
	int client_sock = 0;

	// [2] start a loop to receive polic
	while(1)
	{
		sleep(10);
		printf("[Polic Thread]================>\n");
		
		// [2.2] 解析数据包并按协议格式封装数据 src dst time_stamp
		//client_sock  = accept(listen_sock,NULL,NULL);
		if(client_sock  < 0)
		{
			//handle error;
		}
		// [2.3] 读取策略信息
		//ret = recv_data_by_timeout(client_sock,data,5);
		if(ret < 0 )
		{
			if(0) //timeout
			{
				close(client_sock);
			}
			continue;
		}

		// [2.4] 提取策略数据，整理为BPF格式，
		// [2.5] 更新BPF，设置数据更新标志


	}
	
}
