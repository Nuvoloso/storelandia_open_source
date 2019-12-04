/*
 * Quick utility to get an ephemeral port and leave it wait state.
 *
 * Inspired by yelps ephemeral, but that's in python.
 * so I'm reimplementing to understand and because, python.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <errno.h>

int main() {
    uint16_t port_no;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = 0;   // bind to 0.0.0.0

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "Could not create listen socket");
        return -1;
    }
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        fprintf(stderr, "setsockopt failed");
    }

    int ret = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret != 0)
    {
        fprintf(stderr, "Could not bind socket");
        return -1;
    }

    ret = listen(sockfd, 1);
    if (ret != 0)
    {
        fprintf(stderr, "Could not listen socket");
        return -1;
    }

    socklen_t len = sizeof(addr);
    if (getsockname(sockfd, (struct sockaddr *)&addr, &len) == -1)
    {
        fprintf(stderr, "Could not get port number");
    }
    else
    {
        port_no = ntohs(addr.sin_port);
    }
    int sockfd2 = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd2 < 0)
    {
        fprintf(stderr, "Could not create connect socket");
        return -1;
    }
    if (connect(sockfd2, (struct sockaddr*)&addr, len))
    {
        fprintf(stderr, "Could not connect to socket");
        return -1;
    }
    len = sizeof(addr);
    if (-1 == accept(sockfd, (struct sockaddr*)&addr, &len))
    {
        fprintf(stderr, "Accept failed %d", errno);
        return -1;
    }
    printf("%d\n", port_no);
}
