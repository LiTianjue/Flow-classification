#include <stdio.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <time.h>

#include "mite_pcap_netheadr.h"
#include "net_buff_queue.h"

#include "handler_packet.h"

#include "common.h"


#include <pcap.h>


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

net_buff_t *parse_pkt(const struct pcap_pkthdr* pkthdr, const u_char* packet);



int mt_pcap_capture(char *devname,char *rule)
{
	pcap_t *pcap_handler;


	char error_content[PCAP_ERRBUF_SIZE];

	struct bpf_program bpf_filter;

	bpf_u_int32 net_mask;
	bpf_u_int32 net_ip;

	if(pcap_lookupnet(devname,&net_ip,&net_mask,error_content) < 0)
	{
		printf("Can not select dev %s [%s]\n",devname,error_content);
		return -1;
	}

	//混杂模式，无超时
	pcap_handler = pcap_open_live(devname,BUFSIZ,1,0,error_content);
	if(pcap_handler == NULL)
	{
		fprintf(stderr,"Open Dev :%s Error[%s]\n",devname,error_content);
		return -2;
	}


	 //编译过滤规则
	if(pcap_compile(pcap_handler,&bpf_filter,rule,0,net_ip) < 0){
		pcap_perror(pcap_handler,"Rule:");
		return -3;
	}

	pcap_setfilter(pcap_handler,&bpf_filter);
	
	pcap_loop(pcap_handler ,-1,packetHandler,NULL);

	pcap_close(pcap_handler);


	return 0;
}






void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
#if 0

    const struct ether_header* ethernetHeader;  // 以太网头
    const struct ip* ipHeader;                  // ip头
    const struct tcphdr* tcpHeader;             // tcp 头
    char sourceIp[INET_ADDRSTRLEN];             // 源地址
    char destIp[INET_ADDRSTRLEN];               // 目的地址
    u_int sourcePort, destPort;                 // 端口

    u_char *data;
    int dataLength = 0;
    char dataStr[1450] = {0};


    //取出以太网头，看是不是IP协议包
    ethernetHeader = (struct ether_header*)packet;
    if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
    //取出IP头，源地址，目的地址
        ipHeader = (struct ip*)(packet+sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

    //取出TCP头，截取源端口，目标端口
        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);

            //只取应用数据
            /*
            if(tcpHeader->th_flags & TH_SYN)
            {
                printf("SYN-");
            }
            if(tcpHeader->th_flags & TH_ACK){
                printf("ACK-");
            }
            if(tcpHeader->th_flags & TH_FIN){
                printf("FIN-");
            }
            if(tcpHeader->th_flags & TH_PUSH){
                printf("PUSH-");
            }
            */
			//取出data offset ;
			/*
			printf("th_off = %02x\n",tcpHeader->th_off);
			printf("th_x2 = %02x\n",tcpHeader->th_x2);
			printf("flag = %02x\n",tcpHeader->th_flags);
			printf("pcak_head->cap_len = %d\n",pkthdr->caplen);
			printf("pcak_head->len = %d\n",pkthdr->len);
			*/



            //取出ip 包头的长度
            data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

            if(dataLength >0 && (tcpHeader->th_flags & TH_PUSH))
            {
                 //取出可打印字符
                int i = 0;
                for(i = 0;i < dataLength;i++) {
                    if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
                        dataStr[i] = (char)data[i];
                    } else {
                        dataStr[i] = '.';
                     }

                }
                dataStr[i+1] = '\0';

                printf("[%s:%d]-->[%s:%d][%d] : %s\n",
                       sourceIp,sourcePort,destIp,destPort,dataLength,dataStr);
            }

        }
    }
#endif 

	parse_pkt(pkthdr,packet);
}


net_buff_t *parse_pkt(const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	net_buff_t *ret = NULL;
	/*	| version | tatal_len | src_ip | src_port | dst_ip | dst_port | timestamp | data_len | data |
	 *		1			2			4		2		  4        2             4			2		n
	 *
	 *	so the total len = 21 + n 
	 *
	 */

    const struct ether_header* ethernetHeader;  // 以太网头
    const struct ip* ipHeader;                  // ip头
    const struct tcphdr* tcpHeader;             // tcp 头
    char sourceIp[INET_ADDRSTRLEN];             // 源地址
    char destIp[INET_ADDRSTRLEN];               // 目的地址
    u_int sourcePort, destPort;                 // 端口

    u_char *data;
    int dataLength = 0;

	//取出以太网头，看是不是IP协议包
	ethernetHeader = (struct ether_header*)packet;

	if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
		//取出IP头，源地址，目的地址
		ipHeader = (struct ip*)(packet+sizeof(struct ether_header));
		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

		//取出TCP头，截取源端口，目标端口
		if (ipHeader->ip_p == IPPROTO_TCP) {
			tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			sourcePort = ntohs(tcpHeader->source);
			destPort = ntohs(tcpHeader->dest);

			//只取应用数据
			if((tcpHeader->th_flags & TH_PUSH)) {
				data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
				dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
				if(dataLength >0)
				{

					printf("[%s:%d]-->[%s:%d]  datalen=[%d]\n",
							sourceIp,sourcePort,destIp,destPort,dataLength);
					/*
					 *
					 *	the really work here
					 *
					 */

					//使用常用的网络地址结构，4字节表示ip地址，2字节表示端口号
					//inet_addr() 转换后是网络字节序
					struct mt_pkthdr mt_hd;

					mt_hd.version = MT_VERSION;
					mt_hd.total_len = pkthdr->len+21;
					mt_hd.src_ip = inet_addr(sourceIp);
					mt_hd.src_port = tcpHeader->source;
					mt_hd.dst_ip = inet_addr(destIp);
					mt_hd.dst_port = tcpHeader->dest;
					mt_hd.timestamp = pkthdr->ts.tv_sec;


					//printf("sizeof mt_hd is [%d] %02x %d\n ,",sizeof(mt_hd),mt_hd.version,mt_hd.total_len);
					/*
					   int timestamp = pkthdr->ts.tv_sec;
					   printf("time stamp : %d [%d]\n",timestamp,sizeof(timestamp));
					   int src_ip = inet_addr(sourceIp);
					   printf("src_ip %08X\n",src_ip);
					   */

					ret = new_net_buff(pkthdr->len + sizeof(mt_hd) +2 );
					//printf("packet len %d - %d - 2\n\n",pkthdr->len , sizeof(mt_hd));
					if(ret == NULL)
						return ret;

					sprintf(ret->buff,"hello [%d]\n", pkthdr->len);
					u_int16_t data_len = pkthdr->len;

					//组装数据包
					memcpy(ret->buff,&mt_hd,sizeof(mt_hd));
					memcpy(ret->buff+sizeof(mt_hd),&data_len,2);
					memcpy(ret->buff+sizeof(mt_hd)+2,packet,pkthdr->len);



					if(net_add_buff(g_net_queue,ret) != 0 )
					{
						fprintf(stderr,"add net buff error.\n");
					}
				}
			}

		}
	}
	
	return ret;
	
}
