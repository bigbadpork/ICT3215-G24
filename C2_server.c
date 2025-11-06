#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define BUFFER_SIZE 1024
#define PORT 8080
#define FRAGMENT_SIZE 512  // Size of each fragment

// Define your payload here
const char *PAYLOAD = "This is a test payload that will be sent in fragments from Device B to Device A. "
                     "You can replace this with any data you want to transfer between the devices. "
                     "The data will be split into multiple fragments and sent sequentially to Device A.";

void send_fragmented_payload(const char *requester_ip) {
    int sock;
    struct sockaddr_in client_addr;
    const char *payload = PAYLOAD;
    int payload_size = strlen(payload);
    int fragments_count = (payload_size + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE;
    
    printf("Sending payload (%d bytes) to %s in %d fragments\n", 
           payload_size, requester_ip, fragments_count);
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return;
    }
    
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(PORT + 1);
    
    if (inet_pton(AF_INET, requester_ip, &client_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return;
    }
    
    // Connect to Device A on the fragment receiving port
    if (connect(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return;
    }
    
    printf("Connected to Device A, sending fragments...\n");
    
    // Send payload in fragments
    for (int i = 0; i < fragments_count; i++) {
        int offset = i * FRAGMENT_SIZE;
        int current_fragment_size = (payload_size - offset) > FRAGMENT_SIZE ? 
                                    FRAGMENT_SIZE : (payload_size - offset);
        
        // Send current fragment
        send(sock, payload + offset, current_fragment_size, 0);
        
        printf("Sent fragment %d of %d (%d bytes)\n", 
               i + 1, fragments_count, current_fragment_size);
        
        // Small delay between fragments (optional)
        usleep(100000);  // 100ms
    }
    
    // Send end of transmission marker
    send(sock, "END_OF_TRANSMISSION", 19, 0);
    printf("Payload transmission complete\n");
    
    // Close connection
    close(sock);
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    char buffer[BUFFER_SIZE];
    
    // Create socket
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(server_sock);
        return 1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return 1;
    }
    
    // Listen for connections
    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        return 1;
    }
    
    printf("Device B listening on port %d...\n", PORT);
    
    while (1) {
        // Accept connection from Device A
        if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len)) < 0) {
            perror("Accept failed");
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Connection from %s\n", client_ip);
        
        // Receive request
        memset(buffer, 0, BUFFER_SIZE);
        recv(client_sock, buffer, BUFFER_SIZE, 0);
        
        char requester_ip[INET_ADDRSTRLEN];
        if (sscanf(buffer, "REQUEST_PAYLOAD %s", requester_ip) == 1) {
            printf("Received payload request from %s\n", requester_ip);
            
            // Close this connection
            close(client_sock);
            
            // Send payload in fragments in a new connection
            send_fragmented_payload(requester_ip);
        } else {
            printf("Unknown request: %s\n", buffer);
            close(client_sock);
        }
    }
    
    close(server_sock);
    return 0;
}