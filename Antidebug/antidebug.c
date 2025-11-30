#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_API_CALLS 50
#define THRESHOLD_SECONDS 3.0

typedef struct {
    char apiName[64];
    DWORD lastCallTick;
    int callCount;
} ApiCallRecord;

ApiCallRecord g_apiTracker[MAX_API_CALLS];
int g_trackerCount = 0;

// Forward declarations
void TriggerCountermeasures(const char* apiName);

BOOL MonitorApiCall(const char* apiName) {
    DWORD currentTick = GetTickCount();
    
    for (int i = 0; i < g_trackerCount; i++) {
        if (strcmp(g_apiTracker[i].apiName, apiName) == 0) {
            double timeDiff = (currentTick - g_apiTracker[i].lastCallTick) / 1000.0;
            
            if (timeDiff < THRESHOLD_SECONDS) {
                printf("[ALERT] Suspicious behavior detected!\n");
                printf("[ALERT] API '%s' called twice within %.2f seconds\n", 
                       apiName, timeDiff);
                printf("[ALERT] Possible reverse engineering attempt detected!\n");
                
                TriggerCountermeasures(apiName);
                return FALSE;
            }
            
            g_apiTracker[i].lastCallTick = currentTick;
            g_apiTracker[i].callCount++;
            return TRUE;
        }
    }
    
    if (g_trackerCount < MAX_API_CALLS) {
        strncpy(g_apiTracker[g_trackerCount].apiName, apiName, 63);
        g_apiTracker[g_trackerCount].apiName[63] = '\0';
        g_apiTracker[g_trackerCount].lastCallTick = currentTick;
        g_apiTracker[g_trackerCount].callCount = 1;
        g_trackerCount++;
    }
    
    return TRUE;
}

void TriggerCountermeasures(const char* apiName) {
    printf("\n[COUNTERMEASURE] Activating defense mechanisms...\n");
    printf("[COUNTERMEASURE] Injecting false data streams...\n");
    Sleep(500);
    printf("[COUNTERMEASURE] Introducing execution delays...\n");
    Sleep(2000);
    printf("[COUNTERMEASURE] Terminating application...\n");
    Sleep(1000);
    exit(-1);
}

// Real API wrappers
void SafeGetSystemTime() {
    if (!MonitorApiCall("GetSystemTime")) return;
    SYSTEMTIME st;
    GetSystemTime(&st);
    printf("[API] GetSystemTime: %02d:%02d:%02d\n", st.wHour, st.wMinute, st.wSecond);
}

void SafeGetModuleHandle() {
    if (!MonitorApiCall("GetModuleHandle")) return;
    HMODULE hModule = GetModuleHandle(NULL);
    printf("[API] GetModuleHandle: 0x%p\n", hModule);
}

void SafeIsDebuggerPresent() {
    if (!MonitorApiCall("IsDebuggerPresent")) return;
    BOOL isDebugged = IsDebuggerPresent();
    printf("[API] IsDebuggerPresent: %s\n", isDebugged ? "DETECTED" : "Not detected");
}

void SafeGetTickCount() {
    if (!MonitorApiCall("GetTickCount")) return;
    DWORD ticks = GetTickCount();
    printf("[API] GetTickCount: %lu ms\n", ticks);
}

void SafeGetCurrentProcessId() {
    if (!MonitorApiCall("GetCurrentProcessId")) return;
    DWORD pid = GetCurrentProcessId();
    printf("[API] GetCurrentProcessId: %lu\n", pid);
}

void SafeGetComputerName() {
    if (!MonitorApiCall("GetComputerName")) return;
    char computerName[256];
    DWORD size = sizeof(computerName);
    GetComputerName(computerName, &size);
    printf("[API] GetComputerName: %s\n", computerName);
}

void SafeCreateFile() {
    if (!MonitorApiCall("CreateFile")) return;
    
    static int callNumber = 0;
    callNumber++;
    
    HANDLE hFile = CreateFile("test.txt", GENERIC_WRITE, 0, NULL, 
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        // Move file pointer to end for appending
        SetFilePointer(hFile, 0, NULL, FILE_END);
        
        char data[256];
        SYSTEMTIME st;
        GetSystemTime(&st);
        sprintf(data, "[Call #%d] Written at %02d:%02d:%02d\n", 
                callNumber, st.wHour, st.wMinute, st.wSecond);
        
        DWORD written;
        WriteFile(hFile, data, strlen(data), &written, NULL);
        printf("[API] CreateFile: Successfully wrote call #%d to test.txt\n", callNumber);
        CloseHandle(hFile);
    } else {
        printf("[API] CreateFile: Failed to create file\n");
    }
}

void SafeRegQueryValue() {
    if (!MonitorApiCall("RegQueryValue")) return;
    HKEY hKey;
    char value[256];
    DWORD size = sizeof(value);
    
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueEx(hKey, "ProductName", NULL, NULL, (LPBYTE)value, &size);
        printf("[API] RegQueryValue: %s\n", value);
        RegCloseKey(hKey);
    }
}

void SafeGetVersionEx() {
    if (!MonitorApiCall("GetVersionEx")) return;
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    printf("[API] GetVersionEx: %lu.%lu\n", osvi.dwMajorVersion, osvi.dwMinorVersion);
}

// Test scenarios
void TestNormalBehavior() {
    printf("\n========== TEST 1: Normal Behavior ==========\n");
    SafeGetSystemTime();
    Sleep(4000);  // Wait longer than threshold
    SafeGetSystemTime();
    printf("[TEST] Normal behavior completed successfully\n");
}

void TestRapidAPICalls() {
    printf("\n========== TEST 2: Rapid API Calls (Should Trigger) ==========\n");
    SafeGetModuleHandle();
    Sleep(1000);  // Less than threshold
    SafeGetModuleHandle();  // This will trigger countermeasures
    printf("[TEST] This line should not execute\n");
}

void TestMultipleAPIs() {
    printf("\n========== TEST 3: Multiple Different APIs ==========\n");
    SafeGetTickCount();
    Sleep(500);
    SafeGetCurrentProcessId();
    Sleep(500);
    SafeGetComputerName();
    printf("[TEST] Multiple APIs called successfully\n");
}

void TestFileOperations() {
    printf("\n========== TEST 4: File Operations ==========\n");
    SafeCreateFile();
    Sleep(4000);
    SafeCreateFile();
    printf("[TEST] File operations completed\n");
}

int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf("Anti-Debugging Demonstration - Enhanced\n");
    printf("API Call Frequency Monitoring POC\n");
    printf("===========================================\n");
    
    if (argc < 2) {
        printf("\nUsage: %s <test_number>\n", argv[0]);
        printf("Tests:\n");
        printf("  1 - Normal behavior (should pass)\n");
        printf("  2 - Rapid API calls (should trigger countermeasures)\n");
        printf("  3 - Multiple different APIs (should pass)\n");
        printf("  4 - File operations test\n");
        printf("  5 - All APIs demo\n");
        return 0;
    }
    
    int testNum = atoi(argv[1]);
    
    switch(testNum) {
        case 1:
            TestNormalBehavior();
            break;
        case 2:
            TestRapidAPICalls();
            break;
        case 3:
            TestMultipleAPIs();
            break;
        case 4:
            TestFileOperations();
            break;
        case 5:
            printf("\n========== All APIs Demo ==========\n");
            SafeGetSystemTime();
            SafeGetModuleHandle();
            SafeIsDebuggerPresent();
            SafeGetTickCount();
            SafeGetCurrentProcessId();
            SafeGetComputerName();
            SafeRegQueryValue();
            SafeGetVersionEx();
            printf("[TEST] All APIs called successfully\n");
            break;
        case 6:
            printf("\n========== All APIs Demo ==========\n");
            SafeGetSystemTime();
            SafeGetModuleHandle();
            SafeIsDebuggerPresent();
            SafeGetTickCount();
            SafeGetCurrentProcessId();
            SafeGetComputerName();
            SafeRegQueryValue();
            SafeGetVersionEx();
            Sleep(500);
            SafeGetVersionEx();
            printf("[TEST] All APIs called successfully\n");
            break;
        default:
            printf("Invalid test number\n");
    }
    
    return 0;
}