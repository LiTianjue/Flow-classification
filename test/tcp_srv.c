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
#include <openssl/evp.h>

#define MAX_BUFFER  4096
#define DATA_BASE_FILE	"./data.dat"

#include "handler_packet.h"

void echo_srv(int fd);
int main(int argc, char ** argv)
{ 
	int sockfd,new_fd;
	struct sockaddr_in my_addr; /* 本机地址信息 */ 
	struct sockaddr_in their_addr; /* 客户地址信息 */ 
	unsigned int sin_size, myport, lisnum; 

	if(argv[1])  myport = atoi(argv[1]); 
	else myport = 8800; 

	if(argv[2])  lisnum = atoi(argv[2]); 
	else lisnum = 2; 

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) { 
		perror("socket"); 
		exit(1); 
	} 
        int opt = SO_REUSEADDR;
        setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

	printf("socket %d ok \n",myport);

	my_addr.sin_family=PF_INET; 
	my_addr.sin_port=htons(myport); 
	my_addr.sin_addr.s_addr = INADDR_ANY; 
	bzero(&(my_addr.sin_zero), 0); 
	if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) { 
		perror("bind"); 
		exit(1); 
	} 
	printf("bind ok \n");

	if (listen(sockfd, lisnum) == -1) { 
		perror("listen"); 
		exit(1); 
	}
	printf("listen ok \n");

	/*
	   while(1) { 
	   sin_size = sizeof(struct sockaddr_in); 
	   if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size)) == -1) { 
	   perror("accept"); 
	   continue; 
	   }

	   printf("server: got connection from %s\n",inet_ntoa(their_addr.sin_addr)); 
	   if (!fork()) { //子进程代码段 
	   if (send(new_fd, "Hello, world!\n", 14, 0) == -1) { 
	   perror("send"); 
	   close(new_fd); 
	   exit(0); 
	   } 
	   } 
	   close(new_fd); //父进程不再需要该socket
	   waitpid(-1,NULL,WNOHANG);//等待子进程结束，清除子进程所占用资源
	   } 
	   */

	sin_size = sizeof(struct sockaddr_in); 
        while(1){
            if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size)) == -1) {
                perror("accept");
                exit(0);
            }
            printf("server: got connection from %s\n",inet_ntoa(their_addr.sin_addr));

            echo_srv(new_fd);
        }

        exit(0);
}

void echo_srv(int fd)
{
	int file_out = 1;
	FILE *fp = NULL;
	fp = fopen(DATA_BASE_FILE,"wb");
	if(fp == NULL)
		file_out=0;
    char buffer[MAX_BUFFER] = {0};
    int hr;
	char base64_str[4096];
	int base64_len = 0;
	struct mt_pkthdr *pkt;

	char src[32] = {0};
	char dst[32] = {0};
	int  src_port = 0;
	int  dst_port = 0;
    while(1) {

        hr = read(fd,buffer,MAX_BUFFER);
        if(hr <= 0)
        {
            int err = errno;
            if(err == EAGAIN)
                continue;
            //printf("recvfrom error.\n");
			fclose(fp);
            close(fd);
            return ;
		}

		pkt = (struct mt_pkthdr *)buffer;
		inet_ntop(AF_INET,(char *)&(pkt->dst_ip),dst,INET_ADDRSTRLEN);
		inet_ntop(AF_INET,(char *)&(pkt->src_ip),src,INET_ADDRSTRLEN);
		src_port = ntohs(pkt->src_port);
		dst_port = ntohs(pkt->dst_port);
		//
		if(file_out == 0){
			printf("====  get packet ====\n");
			printf("version : %02x\n",pkt->version);
			printf("total_len: %d\n",pkt->total_len);
			printf("src_ip : %08x\n",pkt->src_ip);
			printf("src_port : %02x\n",pkt->src_port);
			printf("dst_ip : %08x\n",pkt->dst_ip);
			printf("dst_port : %02x\n",pkt->dst_port);
			printf("timestamp : %d\n",pkt->timestamp);
			printf("-------------------------\n");
		}
		else {
			fprintf(fp,"====  get packet ====\n");
			fprintf(fp,"version : %02x -- ",pkt->version);
			fprintf(fp,"total_len: %d\n",pkt->total_len);
			fprintf(fp,"timestamp : %s\n",ctime((const time_t *)&(pkt->timestamp)));
			fprintf(fp,"[%s:%d] ---> ",src,src_port);
			fprintf(fp,"[%s:%d]\n",dst,dst_port);
			base64_len = EVP_EncodeBlock(base64_str,buffer+sizeof(struct mt_pkthdr)+2,hr - sizeof(struct mt_pkthdr) - 2);
			if(base64_len > 0)
				fprintf(fp,"%s\n",base64_str);

			fprintf(fp,"-------------------------\n");
			fflush(NULL);
		}
    }
}
