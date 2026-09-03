#pragma once


int fileReader(char* filename, char** lpbuf, int* lpfs);

int fileWriter(char* filename, const char* data, int datasize, int clear);

int getFileSize(char* filename);

void printdata(unsigned char* data, int size);

int host2Dns(char* host, char* dns);

int dns2Host(char* dns, char* host);

int isTargetDns(char* obj, char* dns,int count);

int isNumber(char* str);

int listdev();