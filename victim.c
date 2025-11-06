#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#define BUFFER_SIZE 1024
#define MAX_FRAGMENTS 1000
#define PORT 8080
#define DEVICE_B_IP "192.168.8.128"  // Hardcoded IP address for Device B

// Function to get the local IP address
char* get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    static char ip[INET_ADDRSTRLEN];
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            
            // Skip loopback addresses
            if (inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN) != NULL &&
                strncmp(ip, "127.", 4) != 0) {
                freeifaddrs(ifaddr);
                return ip;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return "127.0.0.1"; // Return loopback if no other interface found
}

// Function to request payload from Device B and receive fragments
int main() {
    int sock, server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr, listen_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    char buffer[BUFFER_SIZE];
    char *local_ip;
    char request[BUFFER_SIZE];
    char *fragments[MAX_FRAGMENTS];
    int fragment_sizes[MAX_FRAGMENTS];
    int num_fragments = 0;
    int total_size = 0;
    
    // Get the local IP address
    local_ip = get_local_ip();
    if (!local_ip) {
        fprintf(stderr, "Failed to get local IP address\n");
        return 1;
    }
    printf("Device A IP: %s\n", local_ip);
    
    printf("Using Device B IP address: %s\n", DEVICE_B_IP);
    
    // Create socket for sending request
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, DEVICE_B_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return 1;
    }
    
    // Connect to Device B
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }
    
    // Send request with our IP
    snprintf(request, BUFFER_SIZE, "REQUEST_PAYLOAD %s", local_ip);
    send(sock, request, strlen(request), 0);
    printf("Request sent to Device B (%s)\n", DEVICE_B_IP);
    
    // Close initial socket
    close(sock);
    
    // Create socket for receiving fragments
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
    
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(PORT + 1);
    
    if (bind(server_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return 1;
    }
    
    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        return 1;
    }
    
    printf("Listening for fragments on port %d...\n", PORT + 1);
    
    // Accept connection from Device B
    if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len)) < 0) {
        perror("Accept failed");
        close(server_sock);
        return 1;
    }
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("Connection from %s\n", client_ip);
    
    // Receive fragments
    while (1) {
        int bytes_received = recv(client_sock, buffer, BUFFER_SIZE, 0);
        
        if (bytes_received <= 0) {
            break; // Connection closed or error
        }
        
        if (strncmp(buffer, "END_OF_TRANSMISSION", 19) == 0) {
            printf("End of transmission received\n");
            break;
        }
        
        // Allocate memory for this fragment and store it
        fragments[num_fragments] = malloc(bytes_received);
        if (!fragments[num_fragments]) {
            perror("Memory allocation failed");
            break;
        }
        
        memcpy(fragments[num_fragments], buffer, bytes_received);
        fragment_sizes[num_fragments] = bytes_received;
        total_size += bytes_received;
        
        printf("Received fragment %d of size %d bytes\n", num_fragments + 1, bytes_received);
        
        num_fragments++;
        if (num_fragments >= MAX_FRAGMENTS) {
            printf("Maximum number of fragments reached\n");
            break;
        }
    }
    
    // Combine fragments into complete payload
    char *complete_payload = malloc(total_size + 1);
    if (!complete_payload) {
        perror("Memory allocation for complete payload failed");
    } else {
        int offset = 0;
        for (int i = 0; i < num_fragments; i++) {
            memcpy(complete_payload + offset, fragments[i], fragment_sizes[i]);
            offset += fragment_sizes[i];
        }
        complete_payload[total_size] = '\0'; // Null-terminate in case it's text
        
        printf("Complete payload received: %d bytes total\n", total_size);
        // You can process the payload here as needed
        
        // Print a preview of the payload (first 100 chars)
        printf("Payload preview: %.100s%s\n", complete_payload, 
               (total_size > 100) ? "..." : "");
    }
    
    // Clean up
    for (int i = 0; i < num_fragments; i++) {
        free(fragments[i]);
    }
    free(complete_payload);
    close(client_sock);
    close(server_sock);
    
    return 0;
}