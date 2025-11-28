#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define BUFFER_SIZE 1024
#define PORT 8080
#define FRAGMENT_SIZE 512  // Larger fragment size for binary data

// Path to your pre-compiled executable
#define PAYLOAD_FILE "message.exe"

void send_fragmented_payload(const char *requester_ip) {
    int sock;
    struct sockaddr_in client_addr;
    FILE *payload_file;
    unsigned char *payload_data;
    long payload_size;
    int fragments_count;
    
    // Read the executable file
    payload_file = fopen(PAYLOAD_FILE, "rb");
    if (!payload_file) {
        perror("Failed to open payload file");
        return;
    }
    
    // Get file size
    fseek(payload_file, 0, SEEK_END);
    payload_size = ftell(payload_file);
    fseek(payload_file, 0, SEEK_SET);
    
    // Allocate memory and read file
    payload_data = (unsigned char*)malloc(payload_size);
    if (!payload_data) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(payload_file);
        return;
    }
    
    fread(payload_data, 1, payload_size, payload_file);
    fclose(payload_file);
    
    fragments_count = (payload_size + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE;
    
    printf("Sending executable (%ld bytes) to %s in %d fragments\n", 
           payload_size, requester_ip, fragments_count);
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        free(payload_data);
        return;
    }
    
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(PORT + 1);
    
    if (inet_pton(AF_INET, requester_ip, &client_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        free(payload_data);
        return;
    }
    
    // Connect to Device A
    if (connect(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        free(payload_data);
        return;
    }
    
    printf("Connected to Device A, sending fragments...\n");
    
    // Send payload in fragments
    for (int i = 0; i < fragments_count; i++) {
        int offset = i * FRAGMENT_SIZE;
        int current_fragment_size = (payload_size - offset) > FRAGMENT_SIZE ? 
                                    FRAGMENT_SIZE : (payload_size - offset);
        
        send(sock, payload_data + offset, current_fragment_size, 0);
        
        printf("Sent fragment %d of %d (%d bytes)\n", 
               i + 1, fragments_count, current_fragment_size);
        
        usleep(50000);  // 50ms delay
    }
    
    // Send end of transmission marker
    send(sock, "END_OF_TRANSMISSION", 19, 0);
    printf("Payload transmission complete\n");
    
    free(payload_data);
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
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return 1;
    }
    
    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        return 1;
    }
    
    printf("Device B listening on port %d...\n", PORT);
    
    while (1) {
        if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len)) < 0) {
            perror("Accept failed");
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Connection from %s\n", client_ip);
        
        memset(buffer, 0, BUFFER_SIZE);
        recv(client_sock, buffer, BUFFER_SIZE, 0);
        
        char requester_ip[INET_ADDRSTRLEN];
        if (sscanf(buffer, "REQUEST_PAYLOAD %s", requester_ip) == 1) {
            printf("Received payload request from %s\n", requester_ip);
            close(client_sock);
            send_fragmented_payload(requester_ip);
        } else {
            printf("Unknown request: %s\n", buffer);
            close(client_sock);
        }
    }
    
    close(server_sock);
    return 0;
}