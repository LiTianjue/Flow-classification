#ifndef HANDLER_PACKET_H
#define HANDLER_PACKET_H

#include <pcap/pcap.h>


//typedef void (*pcap_handler)(u_char *user,const struct pcap_pkthdr *h,const u_char *bytes)

int mt_pcap_capture(char *devname,char *rule);







#endif	/* HANDLER_PACKET_H*/
