#ifndef ANTIDEBUG_H
#define ANTIDEBUG_H

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

// Global variables (extern declarations)
extern ApiCallRecord g_apiTracker[MAX_API_CALLS];
extern int g_trackerCount;

// Core monitoring functions
void TriggerCountermeasures(const char* apiName);
BOOL MonitorApiCall(const char* apiName);
void InitAntiDebug();
void PrintAntiDebugStats();

// Safe API wrappers
void SafeGetSystemTime();
void SafeGetModuleHandle();
void SafeIsDebuggerPresent();
void SafeGetTickCount();
void SafeGetCurrentProcessId();
void SafeGetComputerName();
void SafeCreateFile();
void SafeRegQueryValue();
void SafeGetVersionEx();

#endif // ANTIDEBUG_H