#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 5000
#define BUF_SIZE 1024

int main() {
    int sockfd;
    char buffer[BUF_SIZE];
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len = sizeof(cliaddr);

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;  // Listen on all network interfaces
    servaddr.sin_port = htons(PORT);

    // Bind socket to address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("[+] Listening for packets on port %d...\n", PORT);

    while (1) {
        int n = recvfrom(sockfd, (char *)buffer, BUF_SIZE, 0,
                         (struct sockaddr *)&cliaddr, &len);
        buffer[n] = '\0';
        printf("[+] Received from %s:%d: %s\n",
               inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), buffer);

        const char *reply = "Hello from Device B!";
        sendto(sockfd, reply, strlen(reply), 0,
               (const struct sockaddr *)&cliaddr, len);
        printf("[+] Sent reply to %s:%d\n",
               inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));
    }

    close(sockfd);
    return 0;
}
