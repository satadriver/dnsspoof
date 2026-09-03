/*
 * pcap_example.h
 *
 *  Created on: Apr 28, 2016
 *      Author: jiaziyi
 */

#ifndef PCAP_EXAMPLE_H_
#define PCAP_EXAMPLE_H_

#include<pcap.h>




#define LINKTYPE_NULL	0
#define LINKTYPE_ETH	1
#define LINKTYPE_WIFI	127
#define LINKTYPE_IP		12


int spoof(char* card,char* target, char* ip, char* dns, int count);

void process_packet(pcap_t* handle, const struct pcap_pkthdr* header, const u_char* packet);


#endif /* PCAP_EXAMPLE_H_ */
