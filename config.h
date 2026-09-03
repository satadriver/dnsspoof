#pragma once

#define SSL_PORT        443
#define HTTP_PORT       80
#define DNS_PORT        53
#define BUFFER_SIZE     1024

int parseCfg(char* fn, char* dns);

void* tcpServer(void* param);

void* udpServer(void* param);