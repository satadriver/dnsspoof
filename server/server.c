/*
 * udp53_hello.c
 *
 * 编译: gcc -o udp53_hello udp53_hello.c
 * 运行: sudo ./udp53_hello
 *
 * 监听 UDP 53 端口，收到任意数据后向来源地址回复 "hello"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define LISTEN_PORT 53
#define BUFFER_SIZE 1024

int main(void)
{
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len;
    char buffer[BUFFER_SIZE];
    const char* reply = "hello";
    size_t reply_len = strlen(reply);
    ssize_t n;

    /* 1. 创建 UDP 套接字 */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* 2. 允许地址重用（方便调试重启） */
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    /* 3. 绑定到 0.0.0.0:53 */
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(LISTEN_PORT);

    if (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Listening on UDP port %d ...\n", LISTEN_PORT);

    /* 4. 循环接收并回复 */
    while (1) {
        len = sizeof(cliaddr);
        n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
            (struct sockaddr*)&cliaddr, &len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        buffer[n] = '\0';

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cliaddr.sin_addr, client_ip, sizeof(client_ip));
        printf("Received %zd bytes from %s:%d\r\n",
            n, client_ip, ntohs(cliaddr.sin_port));

        //sleep(1);

        /* 回复 "hello" */
        //if (sendto(sockfd, reply, reply_len, 0,
        //    (struct sockaddr*)&cliaddr, len) < 0) {
        //    perror("sendto");
        //    continue;
        //}
        //printf("  -> Sent '%s' back\n", reply);
    }

    close(sockfd);
    return 0;
}