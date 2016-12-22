#ifndef HANDLER_PACKET_H
#define HANDLER_PACKET_H

#include <pcap/pcap.h>
#include <stdint.h>

#define MT_VERSION	0x01


struct mt_pkthdr
{
	u_int8_t	version;
	u_int16_t	total_len;
	
	u_int32_t   src_ip;
	u_int16_t	src_port;
	u_int32_t   dst_ip;
	u_int16_t	dst_port;

	u_int32_t	timestamp;
}__attribute__((packed));


//typedef void (*pcap_handler)(u_char *user,const struct pcap_pkthdr *h,const u_char *bytes)

int mt_pcap_capture(char *devname,char *rule);







#endif	/* HANDLER_PACKET_H*/
