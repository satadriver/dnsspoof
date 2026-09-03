

#include "utils.h"
#include <stdio.h>
#include <string.h>
#include "main.h"
#include <pcap.h>

#define FALSE	0
#define TRUE	1



int getFileSize(char* filename) {
	FILE* fp = fopen(filename, "rb");
	if (fp <= 0)
	{
		return FALSE;
	}

	fseek(fp, 0, SEEK_END);
	int filesize = ftell(fp);

	fclose(fp);
	return filesize;
}







int fileReader(char* filename, char** lpbuf, int* lpfs) {
	if (lpbuf == 0 || lpfs == 0) {
		return FALSE;
	}
	int ret = 0;

	FILE* fp = fopen(filename, "rb");
	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename);
		return FALSE;
	}

	ret = fseek(fp, 0, 2);

	unsigned long filesize = ftell(fp);

	ret = fseek(fp, 0, 0);

	if (*lpbuf == 0 || *lpfs == 0) {
		*lpfs = filesize;
		*lpbuf = malloc(filesize + 64);
		ret = fread(*lpbuf, 1, (size_t)filesize, fp);
		*(*lpbuf + filesize) = 0;
	}
	else {
		ret = fread(*lpbuf, 1, (size_t)*lpfs - 1, fp);
		lpbuf[*lpfs - 1] = 0;
	}

	fclose(fp);

	return filesize;
}






int fileWriter(char* filename, const char* data, int datasize, int clear) {
	int ret = 0;

	FILE* fp = 0;
	if (clear) {
		fp = fopen(filename, "wb");
	}
	else {
		fp = fopen(filename, "ab+");
	}

	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename);
		return FALSE;
	}

	ret = fwrite(data, 1, datasize, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return datasize;
}



void printdata(unsigned char* data, int size) {
	for (int i = 0; i < size; i++) {
		printf("%02x ", data[i]);
		if ((i + 1) % 16 == 0) {
			printf("\r\n");
		}
	}
	printf("\r\n");
}


int dns2Host(char* dns,char * host) {

	int dnslen = strlen(dns);
	if (dnslen >= 256)
	{
		return 0;
	}

	for (int i = 0, j = 0; i < dnslen;)
	{
		int partlen = dns[i];
		if (partlen > 0 && partlen < 64)
		{
			memcpy(host + j, dns + i + 1, partlen);

			i += (partlen + 1);

			j += partlen;

			*(host + j) = '.';

			j++;
		}
		else {
			break;
		}
	}

	int hostlen = strlen(host);
	if (hostlen > 0)
	{
		*(host + hostlen - 1) = 0;
	}

	return hostlen;
}



int host2Dns(char* host,char * dns) {
	int len = strlen(host);
	char* ptr = host;
	int p = 0;
	while(ptr < host + len){
		char* pos = strstr(ptr, ".");
		if (pos == ptr) {
			ptr++;
		}
		else if (pos) {
			int subl = pos - ptr;
			dns[p++] = subl;
			memcpy(dns + p, ptr, subl);
			ptr = pos + 1;
			p += subl;
			dns[p] = 0;
		}
		else {
			int subl = strlen(ptr);
			dns[p++] = subl;
			memcpy(dns + p, ptr, subl);
			p += subl;
			ptr += subl;
			dns[p] = 0;
			break;
		}
	}

	return p;
}

int isTargetDns(char* obj, char* dns, int count) {

	for (int i = 0; i < count; i++) {
		char* p = strstr(obj, dns + i*256);
		if (p) {
			return 1;
		}
	}
	return 0;
}


int isTarget(char* obj,char * dns,int count) {
	int len = strlen(obj)+1;
	for (int i = 0; i < count; i++) {
		int k = 0;
		for ( k = 0; k < len; k++) {
			if (obj[k] != dns[i * 256 + k]) {
				break;
				//return 0;
			}
		}
		if (k == len)
			return 1;
	}
	return 0;
}


int isNumber(char* str) {
	int len = strlen(str);
	if (len == 0) {
		return 0;
	}
	for (int i = 0; i < len; i++) {
		if (str[i] >= '0' && str[i] <= '9') {

		}
		else {
			return 0;
		}
	}
	return 1;
}



int listdev() {

	pcap_if_t* all_dev, * dev;

	char err_buf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(1);
	}

	if (all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
		exit(1);
	}

	printf("Available devices list: \n");
	int c = 1;

	for (dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);

		c++;
	}
	pcap_freealldevs(all_dev);
	return c;
}



