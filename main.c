

#include "main.h"

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#include<pcap.h>

#include "spoof.h"
#include "config.h"

#ifdef __linux__
#include <unistd.h>
#endif

int main(int argc, char* argv[]) {

	int ret = 0;
	char* card = 0;
	char* fn = 0;
	char* dns = 0;
	char* ip = 0;
	int list = 0;
	char* target = 0;
	if(argc < 2)
	{
		printf("Usage: %s [--d dns] [--f file] [--n card] [--a address] [--l list]\n", argv[0]);
		return -1;
	}

	for (int seq = 1; seq < argc; seq++) {
		
		if (strcmp(argv[seq], "--d") == 0 || strcmp(argv[seq], "--dns") == 0) {
			if (seq + 1 < argc) {
				dns = argv[seq + 1];
				seq++;
			}
		}
		else if (strcmp(argv[seq], "--f") == 0 || strcmp(argv[seq], "--file") == 0) {
			if (seq + 1 < argc) {
				fn = argv[seq + 1];
				seq++;
			}
		}
		else if (strcmp(argv[seq], "--n") == 0 || strcmp(argv[seq], "--name") == 0) {
			if (seq + 1 < argc) {
				card = argv[seq + 1];
				seq++;
			}
		}
		else if (strcmp(argv[seq], "--a") == 0|| strcmp(argv[seq], "--address") == 0) {
			if (seq + 1 < argc) {
				ip = argv[seq + 1];
				seq++;
			}
		}
		else if (strcmp(argv[seq], "--l") == 0 || strcmp(argv[seq], "--list") == 0) {
			list = 1;
		}
		else if (strcmp(argv[seq], "--t") == 0 || strcmp(argv[seq], "--target") == 0) {
			target = argv[seq + 1];
			seq++;
		}
	}
	if (list)
	{
		listdev();
		return 0;
	}
	if(ip == 0){
		printf("Please specify the target IP address using --a or --address option.\n");
		return -1;
	}

	if(fn == 0 && dns == 0)
	{
		printf("Please specify the target DNS using --d or --dns option, or specify a configuration file using --f or --file option.\n");
		return -1;
	}

	char* config = malloc(DNS_SNIFFER_MAX * DNS_SIZE_LIMIT);
	if (config == 0)
	{
		return -1;
	}
	memset(config, 0, DNS_SNIFFER_MAX * DNS_SIZE_LIMIT);
	int cnt = 0;
	if (fn)
	{
		cnt = parseCfg(fn, config);
		if (cnt <= 0) {
			return -1;
		}
	}
	else {
		
		if (dns) {
			char tmp[DNS_SIZE_LIMIT];
			host2Dns(dns, tmp);
			strcpy(config, tmp);
			cnt = 1;
		}
		else {
			return -1;
		}
	}

	//isTargetDns("\x03\x63\x6f\x6d", config, cnt);
#ifdef _WIN32
	WSADATA wsa;
	ret = WSAStartup(0x0202, &wsa);
	if (ret) {
		return -1;
	}
#endif

#ifdef __linux
	pthread_t tid;
	int args = DNS_PORT;
	if (pthread_create(&tid, NULL, udpServer, args) != 0) {
		perror("pthread_create failed");
		return -1;
	}

	args = SSL_PORT;
	if (pthread_create(&tid, NULL, tcpServer, args) != 0) {
		perror("pthread_create failed");
		return -1;
	}
	args = HTTP_PORT;
	if (pthread_create(&tid, NULL, tcpServer, args) != 0) {
		perror("pthread_create failed");
		return -1;
	}
	//pthread_join(thread, NULL);
#endif

	ret = spoof(card,target,ip,config,cnt);

	return 0;
}