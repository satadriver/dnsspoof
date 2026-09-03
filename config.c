
#include "config.h"
#include "utils.h"
#include <memory.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

int parseCfg(char* fn,char *dnses) {
	int fs = 0;
	char* data = 0;
	int ret = 0;
	ret = fileReader(fn, &data, &fs);
	if (ret <= 0) {
		return 0;
	}
	char* hdr = "[";
	char* end = "]\r\n";
	char* end2 = "]\n";
	int cnt = 0;

	char* ptr = data;
	while (ptr < data + fs) {
		ptr = strstr(ptr, hdr);
		if (ptr) {
			ptr += strlen(hdr);

			char* pos = strstr(ptr, end);
			if (pos == 0) {
				pos = strstr(ptr, end2);
				if (pos == 0)
					break;
			}
            
			int len = pos - ptr;

			pos += strlen(end);

			if (len < 256)
			{
				char host[256];
				memcpy(host, ptr, len);
				host[len] = 0;
                printf("config host:%s\r\n", host);

				char dns[256];
				host2Dns(host, dns);
					
				strcpy(dnses + cnt*256, dns);
				cnt++;
			}
						
			ptr = pos;	
		}
		else {
			break;
		}
	}
	return cnt;
}



#ifdef __linux

void* tcpServer(void* param)
{
    int ret = 0;

    int port = (int)param;

    struct sockaddr_in servaddr;

    char buffer[0x1000];

    ssize_t n;

    int sl = socket(AF_INET, SOCK_STREAM, 0);
    if (sl < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }


    int opt = 1;
    if (setsockopt(sl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sl);
        exit(EXIT_FAILURE);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);

    ret = bind(sl, (struct sockaddr*)&servaddr, sizeof(servaddr));
    if (ret < 0) {
        perror("bind");
        close(sl);
        exit(EXIT_FAILURE);
    }
    ret = listen(sl, 16);

    printf("Listening on tcp port %d ...\n", port);

    while (1) {
        struct sockaddr_in ca;
        int casize = sizeof(struct sockaddr_in);
        int sc = accept(sl, (struct sockaddr*)&ca,&casize );
        if (sc != -1) {

            n = recv(sc, buffer, sizeof(buffer) - 1, 0);
            if (n <= 0) {
                close(sc);
                perror("recv");
                continue;
               
            }

            buffer[n] = '\0';

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ca.sin_addr, client_ip, sizeof(client_ip));
            printf("port:%d Received %d bytes from %s:%d\r\n",port, n, client_ip, ntohs(ca.sin_port));
            
            printdata(buffer, n);

            close(sc);
        }
        else {
            printf("%d accept error\r\n", port);
        }
    }

    close(sl);

    return 0;
}

void* udpServer(void * param)
{
	int port = (int)param;
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len;
    char buffer[BUFFER_SIZE];

    ssize_t n;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }


    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }


    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Listening on UDP port %d ...\n", port);

    while (1) {
        len = sizeof(cliaddr);
        n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&cliaddr, &len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        buffer[n] = '\0';

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cliaddr.sin_addr, client_ip, sizeof(client_ip));

        //printf("port:%d Received %d bytes from %s:%d\r\n",port,n, client_ip, ntohs(cliaddr.sin_port));

        //printdata(buffer, n);

        //if (sendto(sockfd, reply, reply_len, 0,(struct sockaddr*)&cliaddr, len) < 0) {
        //    perror("sendto");
        //    continue;
        //}
    }

    close(sockfd);

    return 0;
}
#endif

