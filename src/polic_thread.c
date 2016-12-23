#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>


#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include<sys/wait.h>
#include <string.h>
#include <errno.h>
#include <time.h>



#include "socket_helper.h"
#include "common.h"
#include "polic_thread.h"
#include "json_handler.h"

int polic_prase(int sockfd);
int update_bpf(char *updata);

void *polic_thread(void *arg)
{
	pthread_detach(pthread_self());

	p_thread_info_t *p_info;
	p_info = (p_thread_info_t *)arg;

	int ret=0;
	char ip[32] = {0};
	int port = 0;

	char data[4096] = {0};
	int data_len;
	// [1] Create a tcp server for receiving polic
	int listen_sock  = 0;
	int client_sock = 0;

	strcpy(ip,p_info->polic_ip);
	port = p_info->polic_port;



	// Create listen socket ==================================
	listen_sock = mite_sock_createListenSocket(ip,port);
	if(listen_sock <0)
	{
		printf("Create polic listensocket error.\n");
		pthread_exit(NULL);
	}



	
	
	// [2] start a loop to receive polic
	printf("[Polic Thread]================>\n");
	while(1)
	{
		if((client_sock = accept(listen_sock,NULL,NULL))== -1) {
			perror("accept");
			pthread_exit(NULL);
		} 
		
		polic_prase(client_sock);

		close(client_sock);
		
	}
	
}

int polic_prase(int sockfd)
{
	char src_ip[32] = {0};
	char src_port[32] = {0};
	char dst_ip[32] = {0};
	char dst_port[32] = {0};

	char host[32] = {0};
	char port[32] = {0};

	char bfp[64] = {0};

	char data[1024];
	int ret;
	ret = mite_sock_readWithTimeout(sockfd,data,5);

	if(ret < 0)
	{
		return -1;
	}

	printf("read data:%s\n",data);

	//解析json格式的策略文件
	JSON_INFO *polic_info = NULL;

	polic_info = json_ParseString(data);
	if(polic_info == NULL)
	{
		printf("prase json error.\n");
		return -2;
	}

	//json_Print(polic_info);
#if 0
	strcpy(src_ip,json_getString(polic_info,"src_ip"));
	strcpy(src_port,json_getString(polic_info,"src_port"));
	strcpy(dst_ip,json_getString(polic_info,"dst_ip"));
	strcpy(dst_port,json_getString(polic_info,"dst_ip"));
	
	move_string_common(src_ip);
	move_string_common(src_port);
	move_string_common(dst_ip);
	move_string_common(dst_port);
#endif

	strcpy(host,json_getString(polic_info,"host"));
	strcpy(port,json_getString(polic_info,"port"));

	move_string_common(host);
	move_string_common(port);
	printf("--------------> [%s:%s]\n",host,port);

	if(strlen(host) >=4)
	{
		strcat(bfp,"host ");
		strcat(bfp,host);
	}
	if(atoi(port) > 0 && atoi(port) < 65535)
	{
		strcat(bfp," and port ");
		strcat(bfp,port);
	}

	printf("bfp [%s] \n",bfp);

	json_Delete(polic_info);

	
	//updata BPF;
	update_bpf(bfp);

	return 0;	
}

int update_bpf(char *updata)
{

	GLOBAL_LOCK(g_info);

	g_info->isset = 1;
	g_info->updata_flag =1;

	strcpy(g_info->bpf,updata);

	GLOBAL_UNLOCK(g_info);


	return 0;
}
