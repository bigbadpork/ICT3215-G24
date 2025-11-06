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
    struct sockaddr_in servaddr;

    // Replace this with Device B's IP address
    const char *DEVICE_B_IP = "192.168.8.128"; // Change to attacker IP

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = inet_addr(DEVICE_B_IP);

    const char *message = "Hello from Device A!";
    sendto(sockfd, message, strlen(message), 0,
           (const struct sockaddr *)&servaddr, sizeof(servaddr));
    printf("[+] Sent message to Device B (%s:%d)\n", DEVICE_B_IP, PORT);

    // Receive response
    socklen_t len = sizeof(servaddr);
    int n = recvfrom(sockfd, (char *)buffer, BUF_SIZE, 0,
                     (struct sockaddr *)&servaddr, &len);
    buffer[n] = '\0';
    printf("[+] Received reply from Device B: %s\n", buffer);

    close(sockfd);
    return 0;
}
