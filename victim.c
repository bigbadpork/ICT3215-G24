
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <intrin.h>
#include <wbemidl.h>
#include <comdef.h>
#include <winreg.h>
#include <ctype.h>
#include <shlwapi.h>
int vm_score = 0;  

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#define BUFFER_SIZE 1024
#define MAX_FRAGMENTS 1000
#define PORT 8080
#define DEVICE_B_IP "192.168.8.128"  // Hardcoded IP address for Device B

/* ---------------------- Shared helpers ------------------------- */

/* case-insensitive substring (safe) */
static const char *strcasestr_safe(const char *hay, const char *needle) {
    if (!hay || !needle) return nullptr;
    size_t nlen = strlen(needle);
    if (nlen == 0) return hay;
    for (; *hay; ++hay) {
        if (tolower((unsigned char)*hay) == tolower((unsigned char)*needle)) {
            if (_strnicmp(hay, needle, (int)nlen) == 0) return hay;
        }
    }
    return nullptr;
}

/* Convert wide (WCHAR*) FriendlyName to UTF-8 safely */
static void WideToUtf8OrAnsi(const WCHAR *w, char *out, size_t outlen) {
    if (!w || !out || outlen == 0) return;
    int req = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)outlen, NULL, NULL);
    if (req == 0) {
        out[0] = '\0';
    }
}

/* ------------------- VM detection (Windows) ------------------- */

/* CPUID checks: hypervisor bit and hypervisor vendor (leaf 0x40000000) */
static void check_cpuid_virtualization_windows() {
    printf("\n=== CPU / CPUID checks ===\n");
    int cpuInfo[4] = {0};
#if defined(_MSC_VER)
    __cpuid(cpuInfo, 1);
#else
    // Fallback zeroed values if no MSVC intrinsic (best-effort)
    cpuInfo[0] = cpuInfo[1] = cpuInfo[2] = cpuInfo[3] = 0;
#endif
    int ecx = cpuInfo[2];
    int hypervisor_present = (ecx >> 31) & 1;
    int vmx = (ecx >> 5) & 1; // VMX
    printf("Hypervisor present bit (CPUID.1:ECX[31]): %d\n", hypervisor_present);
    printf("VMX (Intel VT-x) reported: %d\n", vmx);


#if defined(_MSC_VER)
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13];
    memcpy(vendor + 0, &cpuInfo[1], 4); // EBX
    memcpy(vendor + 4, &cpuInfo[2], 4); // ECX
    memcpy(vendor + 8, &cpuInfo[3], 4); // EDX
    vendor[12] = '\0';
    printf("Hypervisor vendor id (CPUID 0x40000000): %s\n", vendor);
    const char *known[] = { "KVMKVMKVM", "Microsoft Hv", "VMwareVMware", "VBoxVBoxVBox", "XenVMMXenVMM", NULL };
    for (int i = 0; known[i]; ++i) {
        if (strcasestr_safe(vendor, known[i])) {
            printf("  -> Matches known hypervisor vendor substring: %s\n", known[i]);
            vm_score++;
        }
    }
#endif
}

/* MAC prefix checks using GetAdaptersAddresses */
static void check_mac_prefixes_windows() {
    printf("\n=== MAC prefix & network adapter checks ===\n");
    const char *vm_prefixes[] = { "00:05:69", "00:0C:29", "00:50:56", "08:00:27", "00:1C:42", "52:54:00", NULL };

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (!pAddresses) { printf("Memory allocation failed for GetAdaptersAddresses\n"); return; }
    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (!pAddresses) return;
        ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
    }
    if (ret != NO_ERROR) {
        printf("GetAdaptersAddresses failed: %lu\n", ret);
        if (pAddresses) free(pAddresses);
        return;
    }
    for (PIP_ADAPTER_ADDRESSES p = pAddresses; p; p = p->Next) {
        if (p->PhysicalAddressLength) {
            char mac[64] = {0};
            for (ULONG i = 0; i < p->PhysicalAddressLength; ++i) {
                char part[8];
                sprintf(part, "%02X%s", p->PhysicalAddress[i], (i + 1 < p->PhysicalAddressLength) ? ":" : "");
                strcat(mac, part);
            }
            char friendly[512] = {0};
            if (p->FriendlyName) {
                WideToUtf8OrAnsi(p->FriendlyName, friendly, sizeof(friendly));
            }
            printf("Adapter: %s, MAC: %s\n", (friendly[0] ? friendly : "<unknown>"), mac);
            for (int i = 0; vm_prefixes[i]; ++i) {
                if (_strnicmp(mac, vm_prefixes[i], (int)strlen(vm_prefixes[i])) == 0) {
                    printf("  -> MAC prefix matches VM vendor: %s\n", vm_prefixes[i]);
                }
            }
        }
    }
    free(pAddresses);
}
// merged_vm_net_windows.cpp  (PART 2/4)
// Continued

/* Check for known VM driver files in System32\\drivers */
static void check_driver_files_windows() {
    printf("\n=== Known VM driver files check ===\n");
    const char *drivers[] = { "vmmouse.sys", "vmhgfs.sys", "VBoxGuest.sys", "vmware.sys", "vboxdrv.sys", NULL };
    char windir[MAX_PATH];
    if (GetWindowsDirectoryA(windir, MAX_PATH) == 0) strncpy(windir, "C:\\Windows", MAX_PATH);
    for (int i = 0; drivers[i]; ++i) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\System32\\drivers\\%s", windir, drivers[i]);
        DWORD attr = GetFileAttributesA(path);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            printf("Found VM driver file: %s\n", path);
        }
    }
}

/* WMI queries for BIOS and Disk model */
static void query_wmi_bios_and_disks_windows() {
    printf("\n=== WMI BIOS / Disk checks ===\n");
    HRESULT hr;
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) { printf("CoInitializeEx failed: 0x%08X\n", (unsigned)hr); return; }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) { printf("CoInitializeSecurity failed: 0x%08X\n", (unsigned)hr); CoUninitialize(); return; }

    IWbemLocator *pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hr) || !pLoc) { printf("CoCreateInstance WbemLocator failed: 0x%08X\n", (unsigned)hr); CoUninitialize(); return; }

    IWbemServices *pSvc = NULL;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr) || !pSvc) { printf("ConnectServer failed: 0x%08X\n", (unsigned)hr); pLoc->Release(); CoUninitialize(); return; }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) { printf("CoSetProxyBlanket failed: 0x%08X\n", (unsigned)hr); pSvc->Release(); pLoc->Release(); CoUninitialize(); return; }

    // Win32_BIOS
    IEnumWbemClassObject *pEnum = NULL;
    hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT Manufacturer, SerialNumber, Caption FROM Win32_BIOS"),
                         WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
    if (SUCCEEDED(hr) && pEnum) {
        IWbemClassObject *pObj = NULL;
        ULONG ret;
        if (pEnum->Next(WBEM_INFINITE, 1, &pObj, &ret) == S_OK) {
            VARIANT v;
            if (SUCCEEDED(pObj->Get(L"Manufacturer", 0, &v, 0, 0)) && v.vt == VT_BSTR) {
                wprintf(L"BIOS Manufacturer: %s\n", v.bstrVal);
            if (wcsstr(v.bstrVal, L"VBOX") || wcsstr(v.bstrVal, L"VMWARE") || wcsstr(v.bstrVal, L"QEMU"))
                vm_score++;
            }
            VariantClear(&v);
            if (SUCCEEDED(pObj->Get(L"SerialNumber", 0, &v, 0, 0)) && v.vt == VT_BSTR) {
                wprintf(L"BIOS SerialNumber: %s\n", v.bstrVal);
            }
            VariantClear(&v);
            if (SUCCEEDED(pObj->Get(L"Caption", 0, &v, 0, 0)) && v.vt == VT_BSTR) {
                wprintf(L"BIOS Caption: %s\n", v.bstrVal);
            }
            VariantClear(&v);
            pObj->Release();
        }
        pEnum->Release();
    }

    // Win32_DiskDrive models
    pEnum = NULL;
    hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT Model, Manufacturer FROM Win32_DiskDrive"),
                         WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
    if (SUCCEEDED(hr) && pEnum) {
        IWbemClassObject *pObj = NULL;
        ULONG ret;
        while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &ret) == S_OK) {
            VARIANT v;
            if (SUCCEEDED(pObj->Get(L"Model", 0, &v, 0, 0)) && v.vt == VT_BSTR) {
                wprintf(L"Disk Model: %s\n", v.bstrVal);
                if (wcsstr(v.bstrVal, L"VIRTUAL") || wcsstr(v.bstrVal, L"VBOX") ||
                    wcsstr(v.bstrVal, L"VMWARE") || wcsstr(v.bstrVal, L"QEMU"))
{
                wprintf(L"  -> Disk model implies virtual disk\n");
                vm_score++;   // Requirement #2
}

            }
            VariantClear(&v);
            pObj->Release();
        }
        pEnum->Release();
    }

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
}

/* Registry checks for known VM keys */
static void check_registry_vm_keys_windows() {
    printf("\n=== Registry VM key checks ===\n");
    const char *keys[] = {
        "HARDWARE\\ACPI\\DSDT\\VBOX__", 
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
        "SYSTEM\\CurrentControlSet\\Services\\vmtools",
        NULL
    };
    for (int i = 0; keys[i]; ++i) {
        HKEY hKey;
        LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &hKey);
        if (rc == ERROR_SUCCESS) {
            printf("Registry key exists: %s\n", keys[i]);
            vm_score++;
            RegCloseKey(hKey);
        }
    }
}

/* Process / service checks: look for vmtoolsd, VBoxService, vboxtray */
static int is_process_running_windows(const char *procname) {
    BOOL found = FALSE;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; memset(&pe, 0, sizeof(pe)); pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procname) == 0) { found = TRUE; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found ? 1 : 0;
}

static void check_processes_and_services_windows() {
    printf("\n=== Process & service checks ===\n");
    const char *procs[] = { "vmtoolsd.exe", "VBoxService.exe", "vboxtray.exe", "vmwaretray.exe", NULL };
    for (int i = 0; procs[i]; ++i) {
        int running = is_process_running_windows(procs[i]);
        printf("Process %s running: %s\n", procs[i], running ? "YES" : "NO");
        if (running) vm_score++; 

    }

    // Check services as well
    SC_HANDLE sc = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc) { printf("OpenSCManager failed\n"); return; }
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded = 0;
    const char *svcs[] = { "VBoxService", "vmtools", "VMTools", NULL };
    for (int i = 0; svcs[i]; ++i) {
        SC_HANDLE svc = OpenServiceA(sc, svcs[i], SERVICE_QUERY_STATUS);
        if (svc) {
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                printf("Service %s exists (state=%lu)\n", svcs[i], ssp.dwCurrentState);
                vm_score++;
            } else {
                printf("Service %s exists (Query failed)\n", svcs[i]);
            }
            CloseServiceHandle(svc);
        }
    }
    CloseServiceHandle(sc);
}
// merged_vm_net_windows.cpp  (PART 3/4)
// Continued

/* Network gateway & hostname heuristics (GetAdaptersAddresses) */
static void check_network_and_hostname_windows() {
    printf("\n=== Network & hostname checks ===\n");
    char hostname[256];
    DWORD sz = (DWORD)sizeof(hostname);
    if (GetComputerNameA(hostname, &sz)) {
        printf("Hostname: %s\n", hostname);
        if (strcasestr_safe(hostname, "VM") || strcasestr_safe(hostname, "VBOX") ||
            strcasestr_safe(hostname, "VIRTUAL") || strcasestr_safe(hostname, "QEMU")) {
            printf("  -> Hostname suggests VM\n");
        }
    }

    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (!pAddresses) return;
    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (!pAddresses) return;
        ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
    }
    if (ret == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES p = pAddresses; p; p = p->Next) {
            PIP_ADAPTER_GATEWAY_ADDRESS_LH g = p->FirstGatewayAddress;
            if (g && g->Address.lpSockaddr) {
                char gw[INET6_ADDRSTRLEN] = {0};
                if (getnameinfo(g->Address.lpSockaddr, (int)g->Address.iSockaddrLength, gw, sizeof(gw), NULL, 0, NI_NUMERICHOST) == 0) {
                    char adapterName[256] = {0};
                    if (p->AdapterName) strncpy(adapterName, p->AdapterName, sizeof(adapterName)-1);
                    printf("Adapter %s default gateway: %s\n", adapterName[0] ? adapterName : "?", gw);
                    if (strcmp(gw, "10.0.2.2") == 0) {
                        printf("  -> Gateway 10.0.2.2 suggests VirtualBox/Android emulator NAT\n");
                    }
                }
            }
        }
    }
    free(pAddresses);
}

/* Run all Windows-compatible VM checks and print findings */
static void run_all_vm_checks_windows() {
    check_cpuid_virtualization_windows();
    check_mac_prefixes_windows();
    check_driver_files_windows();
    check_registry_vm_keys_windows();
    query_wmi_bios_and_disks_windows();
    check_processes_and_services_windows();
    check_network_and_hostname_windows();
}

/* ------------------- Environment Info (from file 2) ------------------- */

/* Helper: retrieve first non-loopback IPv4 addr of this machine using GetAdaptersAddresses */
static const char *get_local_ip_windows() {
    static char ip[INET_ADDRSTRLEN] = "127.0.0.1";
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES) malloc(outBufLen);
    if (!pAddresses) return ip;
    ULONG ret = GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &outBufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES) malloc(outBufLen);
        if (!pAddresses) return ip;
        ret = GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &outBufLen);
    }
    if (ret == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES p = pAddresses; p; p = p->Next) {
            if (p->OperStatus != IfOperStatusUp) continue;
            for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = p->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *sa = (struct sockaddr_in *)pUnicast->Address.lpSockaddr;
                    inet_ntop(AF_INET, &sa->sin_addr, ip, INET_ADDRSTRLEN);
                    if (strncmp(ip, "127.", 4) != 0) {
                        free(pAddresses);
                        return ip;
                    }
                }
            }
        }
    }
    free(pAddresses);
    return ip;
}


void get_motherboard_info() {
    HRESULT hres;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;

    printf("\n=== Motherboard Info ===\n");
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return;

    CoInitializeSecurity(NULL, -1, NULL, NULL,
                         RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         NULL, EOAC_NONE, NULL);

    if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator, (LPVOID*)&pLoc))) {
        CoUninitialize();
        return;
    }

    if (FAILED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc))) {
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    if (SUCCEEDED(pSvc->ExecQuery(bstr_t("WQL"),
                                  bstr_t("SELECT Manufacturer, Product FROM Win32_BaseBoard"),
                                  WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                  NULL, &pEnumerator))) {
        IWbemClassObject* pObj = NULL;
        ULONG uRet = 0;
        while (pEnumerator && pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uRet) == S_OK) {
            VARIANT vt;
            if (SUCCEEDED(pObj->Get(L"Manufacturer", 0, &vt, 0, 0)) && vt.vt == VT_BSTR) {
                wprintf(L"Manufacturer: %s\n", vt.bstrVal ? vt.bstrVal : L"Unknown");
            }
            VariantClear(&vt);

            if (SUCCEEDED(pObj->Get(L"Product", 0, &vt, 0, 0)) && vt.vt == VT_BSTR) {
                wprintf(L"Product: %s\n", vt.bstrVal ? vt.bstrVal : L"Unknown");
                if (vt.bstrVal && wcsstr(vt.bstrVal, L"DESKTOP REFERENCE PLATFORM"))
                    vm_score++;   
            }
            VariantClear(&vt);

            pObj->Release();
        }
        pEnumerator->Release();
    }
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
}
void get_cpu_frequency() {
    printf("\n=== CPU Frequency ===\n");

    // Try reading from CPUID brand string first
    int cpuInfo[4] = {0};
    char brand[0x40] = {0};

    __cpuid(cpuInfo, 0x80000000);
    unsigned int maxExtId = cpuInfo[0];

    if (maxExtId >= 0x80000004) {
        __cpuid((int*)(brand + 0), 0x80000002);
        __cpuid((int*)(brand + 16), 0x80000003);
        __cpuid((int*)(brand + 32), 0x80000004);
        printf("CPU Brand: %s\n", brand);
    }

    // QueryPerformanceFrequency gives base timer frequency (NOT CPU clock!)
    // But we can display it for diagnostics
    LARGE_INTEGER freq;
    if (QueryPerformanceFrequency(&freq)) {
        printf("High-precision timer frequency: %lld Hz\n", freq.QuadPart);
    }

    // Windows registry sometimes stores the CPU MHz
    HKEY hKey;
    DWORD mhz = 0, size = sizeof(mhz);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        if (RegQueryValueExA(hKey, "~MHz", NULL, NULL, (LPBYTE)&mhz, &size) == ERROR_SUCCESS) {
            printf("CPU Clock Speed: %lu MHz (%.2f GHz)\n", mhz, mhz / 1000.0);
        }
        RegCloseKey(hKey);
    } else {
        printf("CPU Clock Speed: (Unable to determine)\n");
    }
}
void get_cpu_core_count() {
    printf("\n=== CPU Core / Processor Info ===\n");

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    DWORD logical = sysInfo.dwNumberOfProcessors;
    printf("Logical processors: %lu\n", logical);

    // Try to detect physical core count using GetLogicalProcessorInformationEx
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);

    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX buffer =
        (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)malloc(len);

    if (buffer && GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, &len)) {
        int physical_cores = 0;

        BYTE *ptr = (BYTE *)buffer;
        BYTE *end = ptr + len;

        while (ptr < end) {
            PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX info =
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)ptr;

            if (info->Relationship == RelationProcessorCore) {
                physical_cores++;
            }

            ptr += info->Size;
        }

        printf("Physical cores: %d\n", physical_cores);
        if (physical_cores == (int)logical) {
        printf("Logical == Physical cores → VM indicator\n");
        vm_score++;   // Requirement #7
}

    } else {
        printf("Physical cores: (Unable to determine)\n");
    }

    if (buffer) free(buffer);
}

/* ------------------- Networking (Windows sockets) ------------------- */

/* Function to request payload from Device B and receive fragments (Windows sockets) */
int network_request_and_receive_fragments(const char *local_ip) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    printf("Device A IP: %s\n", local_ip ? local_ip : "unknown");
    printf("Using Device B IP address: %s\n", DEVICE_B_IP);

    // Create socket for sending request
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { perror("socket"); WSACleanup(); return 1; }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, DEVICE_B_IP, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid DEVICE_B_IP\n");
        closesocket(sock); WSACleanup(); return 1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Connection failed: %d\n", WSAGetLastError());
        closesocket(sock); WSACleanup(); return 1;
    }

    char request[BUFFER_SIZE];
    snprintf(request, BUFFER_SIZE, "REQUEST_PAYLOAD %s", local_ip ? local_ip : "127.0.0.1");
    send(sock, request, (int)strlen(request), 0);
    printf("Request sent to Device B (%s)\n", DEVICE_B_IP);
    closesocket(sock);

    // Create socket for receiving fragments
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) { perror("socket"); WSACleanup(); return 1; }

    BOOL opt = TRUE;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_addr.sin_port = htons(PORT + 1);

    if (bind(listen_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed: %d\n", WSAGetLastError());
        closesocket(listen_sock); WSACleanup(); return 1;
    }

    if (listen(listen_sock, 5) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed: %d\n", WSAGetLastError());
        closesocket(listen_sock); WSACleanup(); return 1;
    }

    printf("Listening for fragments on port %d...\n", PORT + 1);

    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    SOCKET client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &addr_len);
    if (client_sock == INVALID_SOCKET) {
        fprintf(stderr, "Accept failed: %d\n", WSAGetLastError());
        closesocket(listen_sock); WSACleanup(); return 1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("Connection from %s\n", client_ip);

    char buffer[BUFFER_SIZE];
    char *fragments[MAX_FRAGMENTS] = {0};
    int fragment_sizes[MAX_FRAGMENTS] = {0};
    int num_fragments = 0;
    int total_size = 0;

    while (1) {
        int bytes_received = (int)recv(client_sock, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) break;

        if (bytes_received >= 19 && strncmp(buffer, "END_OF_TRANSMISSION", 19) == 0) {
            printf("End of transmission received\n");
            break;
        }

        fragments[num_fragments] = (char*)malloc(bytes_received);
        if (!fragments[num_fragments]) { perror("malloc"); break; }
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
    char *complete_payload = (char*)malloc((size_t)total_size + 1);
    if (!complete_payload) {
        perror("malloc");
    } else {
        int offset = 0;
        for (int i = 0; i < num_fragments; ++i) {
            memcpy(complete_payload + offset, fragments[i], fragment_sizes[i]);
            offset += fragment_sizes[i];
        }
        complete_payload[total_size] = '\0';
        printf("Complete payload received: %d bytes total\n", total_size);
        printf("Payload preview: %.100s%s\n", complete_payload, (total_size > 100) ? "..." : "");
    }

    for (int i = 0; i < num_fragments; ++i) {
        if (fragments[i]) free(fragments[i]);
    }
    if (complete_payload) free(complete_payload);

    closesocket(client_sock);
    closesocket(listen_sock);
    WSACleanup();

    return 0;
}

/* ------------------- main ------------------- */
int main() {
    /* ---------- RUN VM DETECTION FIRST (print-only) ---------- */
    run_all_vm_checks_windows(); // prints results but does not exit

    /* ---------- ENVIRONMENT INFO ---------- */
    printf("\n=== ENVIRONMENT SPECS ===\n");
    const char *local_ip = get_local_ip_windows();
    printf("Local IP: %s\n", local_ip);
    get_motherboard_info();
    get_cpu_frequency();  
    get_cpu_core_count();
    printf("\n=============================\n");
printf(" VM Suspicion Score: %d /7 \n ", vm_score);

if (vm_score >= 2) {
    printf(" RESULT: This system **IS LIKELY A VIRTUAL MACHINE**\n");
} else {
    printf(" RESULT: This system **is NOT likely a virtual machine**\n");
}
printf("=============================\n\n");


    /* ---------- NETWORKING: request + receive fragments ---------- */
    int net_rc = network_request_and_receive_fragments(local_ip);
    if (net_rc != 0) {
        fprintf(stderr, "Networking routine returned %d\n", net_rc);
        return net_rc;
    }

    return 0;
}
