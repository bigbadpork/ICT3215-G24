#ifndef CHECKSANDBOX_H
#define CHECKSANDBOX_H

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#include <tlhelp32.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

#pragma comment(lib, "advapi32.lib")

#else
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

// Function prototypes
int check_sandbox();
void get_motherboard_info(int *score);

#ifdef _WIN32
void check_cpuid_virtualization(int *score);
void check_processes_services(int *score);
void check_forensic_tools(int *score);
void check_injected_dlls(int *score);
void check_forensic_activity(int *score);
void check_timing_anomalies(int *score);
#endif

// jin ann just reference this then delete once u integrate
// int main() {
//     printf("=== System Environment Checker ===\n\n");
    
//     int sandbox_detected = check_sandbox();
//     printf("Sandbox detection result: %s\n", 
//            sandbox_detected ? "SANDBOX DETECTED!" : "No sandbox detected");
    
//     return 0;
// }

#ifdef _WIN32

void check_cpuid_virtualization(int *score) {
    printf("\n--- CPUID Virtualization Checks ---\n");
    
#ifdef _MSC_VER
    int cpuInfo[4] = {0};
    
    __cpuid(cpuInfo, 1);
    int ecx = cpuInfo[2];
    int hypervisor_present = (ecx >> 31) & 1;
    
    printf("Hypervisor present bit: %d\n", hypervisor_present);
    
    __cpuid(cpuInfo, 0x40000000);
    
    char vendor[13];
    memcpy(vendor + 0, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    vendor[12] = '\0';
    
    printf("Hypervisor vendor: %s\n", vendor);
    
    const char *known_hvs[] = {"KVMKVMKVM", "VMwareVMware", 
                                "VBoxVBoxVBox", "XenVMMXenVMM", NULL};
    
    // Only increment score if hypervisor detected AND it's not just Hyper-V on host
    if (hypervisor_present) {
        for (int i = 0; known_hvs[i]; i++) {
            if (strstr(vendor, known_hvs[i])) {
                printf("[+] Known VM hypervisor detected: %s\n", known_hvs[i]);
                (*score)++;
                return;
            }
        }
        // If hypervisor bit set but vendor is "Microsoft Hv", likely just Hyper-V enabled on host
        if (strstr(vendor, "Microsoft Hv")) {
            printf("[*] Hyper-V detected - likely host with virtualization enabled\n");
        }
    }
    
#elif defined(__GNUC__)
    // GCC/MinGW version
    unsigned int eax, ebx, ecx, edx;
    
    // CPUID leaf 1
    eax = 1;
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
    );
    
    int hypervisor_present = (ecx >> 31) & 1;
    printf("Hypervisor present bit: %d\n", hypervisor_present);
    
    // CPUID leaf 0x40000000 for hypervisor vendor
    eax = 0x40000000;
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
    );
    
    char vendor[13];
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    vendor[12] = '\0';
    
    printf("Hypervisor vendor: %s\n", vendor);
    
    const char *known_hvs[] = {"KVMKVMKVM", "VMwareVMware", 
                                "VBoxVBoxVBox", "XenVMMXenVMM", NULL};
    
    // Only increment score if hypervisor detected AND it's not just Hyper-V on host
    if (hypervisor_present) {
        for (int i = 0; known_hvs[i]; i++) {
            if (strstr(vendor, known_hvs[i])) {
                printf("[+] Known VM hypervisor detected: %s\n", known_hvs[i]);
                (*score)++;
                return;
            }
        }
        // If hypervisor bit set but vendor is "Microsoft Hv", likely just Hyper-V enabled on host
        if (strstr(vendor, "Microsoft Hv")) {
            printf("[*] Hyper-V detected - likely host with virtualization enabled\n");
        }
    }
#else
    printf("CPUID checks not supported with this compiler\n");
#endif
}

void check_processes_services(int *score) {
    printf("\n--- Process/Service Checks ---\n");
    
    const char *vm_processes[] = {"vmtoolsd.exe", "VBoxService.exe", "vboxtray.exe", 
                                   "vmwaretray.exe", "vmwareuser.exe", NULL};
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        memset(&pe, 0, sizeof(pe));
        pe.dwSize = sizeof(pe);
        
        if (Process32First(snap, &pe)) {
            do {
                for (int i = 0; vm_processes[i]; i++) {
                    if (_stricmp(pe.szExeFile, vm_processes[i]) == 0) {
                        printf("[+] VM process detected: %s\n", vm_processes[i]);
                        (*score)++;
                        break;
                    }
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    
    SC_HANDLE sc = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (sc) {
        const char *vm_services[] = {"VBoxService", "vmtools", "VMTools", NULL};
        
        for (int i = 0; vm_services[i]; i++) {
            SC_HANDLE svc = OpenServiceA(sc, vm_services[i], SERVICE_QUERY_STATUS);
            if (svc) {
                printf("[+] VM service detected: %s\n", vm_services[i]);
                (*score)++;
                CloseServiceHandle(svc);
            }
        }
        CloseServiceHandle(sc);
    }
}

void check_forensic_tools(int *score) {
    printf("\n--- Forensic Tool Detection ---\n");
    
    const char *forensic_processes[] = {
        "hxd.exe", "hxd64.exe",
        "autopsy.exe", "autopsy64.exe",
        "FTKImager.exe", "FTK Imager.exe",
        "EnCase.exe", "EnCaseForensic.exe",
        "x64dbg.exe", "x32dbg.exe",
        "ollydbg.exe", "windbg.exe",
        "ida.exe", "ida64.exe", "idag.exe", "idag64.exe",
        "processhacker.exe", "procexp.exe", "procexp64.exe",
        "wireshark.exe", "dumpcap.exe",
        "pestudio.exe", "peview.exe",
        "regshot.exe", "regshot-x64.exe",
        "procmon.exe", "procmon64.exe",
        NULL
    };
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(snap, &pe)) {
            do {
                for (int i = 0; forensic_processes[i]; i++) {
                    if (_stricmp(pe.szExeFile, forensic_processes[i]) == 0) {
                        printf("[!] FORENSIC TOOL DETECTED: %s (PID: %lu)\n", 
                               pe.szExeFile, pe.th32ProcessID);
                        (*score)++;
                    }
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
}

void check_injected_dlls(int *score) {
    printf("\n--- DLL Injection Detection ---\n");
    
    const char *suspicious_dlls[] = {
        "vmwarebase.dll", "vboxhook.dll",
        "dbghelp.dll",
        "sbiedll.dll",
        "api_log.dll",
        "dir_watch.dll",
        NULL
    };
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 
                                          GetCurrentProcessId());
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me;
        me.dwSize = sizeof(me);
        
        if (Module32First(snap, &me)) {
            do {
                for (int i = 0; suspicious_dlls[i]; i++) {
                    if (_stricmp(me.szModule, suspicious_dlls[i]) == 0) {
                        printf("[!] SUSPICIOUS DLL LOADED: %s\n", me.szModule);
                        (*score)++;
                    }
                }
            } while (Module32Next(snap, &me));
        }
        CloseHandle(snap);
    }
}

void check_forensic_activity(int *score) {
    printf("\n--- Forensic Activity Detection ---\n");
    
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    
    UINT driveType = GetDriveTypeA(path);
    if (driveType == DRIVE_REMOVABLE || driveType == DRIVE_CDROM) {
        printf("[!] RUNNING FROM REMOVABLE/CD: Drive type %u\n", driveType);
        (*score)++;
    }
    
    printf("Executable path: %s\n", path);
    printf("Drive type: %u (2=Removable, 5=CD-ROM)\n", driveType);
}

void check_timing_anomalies(int *score) {
    printf("\n--- Timing Analysis ---\n");
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    
    QueryPerformanceCounter(&start);
    Sleep(100);
    QueryPerformanceCounter(&end);
    
    double elapsed = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    
    printf("Sleep(100) took: %.2f ms\n", elapsed);
    
    if (elapsed > 150.0) {
        printf("[!] TIMING ANOMALY: Execution slower than expected\n");
        (*score)++;
    }
}

void get_motherboard_info(int *score) {
    printf("\n=== Motherboard Information ===\n");

    HKEY hKey;
    char manufacturer[1024] = "Unknown";
    char systemManufacturer[1024] = "Unknown";
    char product[1024] = "Unknown";
    char serialNumber[1024] = "Unknown";
    char biosVendor[1024] = "Unknown";
    char biosVersion[1024] = "Unknown";
    char biosDate[1024] = "Unknown";
    DWORD size;
    
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
                     "HARDWARE\\DESCRIPTION\\System\\BIOS", 
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        size = sizeof(manufacturer);
        RegQueryValueEx(hKey, "BaseBoardManufacturer", NULL, NULL, (LPBYTE)manufacturer, &size);
        
        size = sizeof(product);
        RegQueryValueEx(hKey, "BaseBoardProduct", NULL, NULL, (LPBYTE)product, &size);
        
        size = sizeof(serialNumber);
        RegQueryValueEx(hKey, "BaseBoardSerialNumber", NULL, NULL, (LPBYTE)serialNumber, &size);
        
        size = sizeof(biosVendor);
        RegQueryValueEx(hKey, "BIOSVendor", NULL, NULL, (LPBYTE)biosVendor, &size);
        
        size = sizeof(biosVersion);
        RegQueryValueEx(hKey, "BIOSVersion", NULL, NULL, (LPBYTE)biosVersion, &size);
        
        size = sizeof(biosDate);
        RegQueryValueEx(hKey, "BIOSReleaseDate", NULL, NULL, (LPBYTE)biosDate, &size);
        
        size = sizeof(systemManufacturer);
        RegQueryValueEx(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)systemManufacturer, &size);
        
        RegCloseKey(hKey);
    }
    
    printf("System Manufacturer: %s\n", systemManufacturer);
    printf("Motherboard Manufacturer: %s\n", manufacturer);
    printf("Motherboard Model: %s\n", product);
    printf("Motherboard Serial: %s\n", serialNumber);
    printf("BIOS Vendor: %s\n", biosVendor);
    printf("BIOS Version: %s\n", biosVersion);
    printf("BIOS Date: %s\n", biosDate);
    
    HKEY hKeyCPU;
    char cpuName[1024] = "Unknown";
    
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
                     "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 
                     0, KEY_READ, &hKeyCPU) == ERROR_SUCCESS) {
        
        size = sizeof(cpuName);
        RegQueryValueEx(hKeyCPU, "ProcessorNameString", NULL, NULL, (LPBYTE)cpuName, &size);
        RegCloseKey(hKeyCPU);
    }
    
    printf("CPU: %s\n", cpuName);
    
    // VM detection via hardware info
    if (strstr(systemManufacturer, "VMware") || 
        strstr(systemManufacturer, "QEMU") ||
        strstr(systemManufacturer, "VirtualBox") ||
        strstr(systemManufacturer, "Xen") ||
        strstr(systemManufacturer, "innotek") ||
        strstr(manufacturer, "VMware") ||
        strstr(manufacturer, "VirtualBox") ||
        strstr(biosVendor, "VMware") ||
        strstr(biosVendor, "VirtualBox") ||
        strstr(product, "Virtual") ||
        strstr(product, "VMware")) {
        printf("[+] VM detected via BIOS/Motherboard hardware info\n");
        if (score) (*score)++;
    }

    printf("\n=== End of Motherboard Info ===\n\n");
}

#endif

int check_sandbox() {
    int sandbox_detected = 0;
    
#ifdef _WIN32
    check_cpuid_virtualization(&sandbox_detected);
    check_processes_services(&sandbox_detected);
    check_forensic_tools(&sandbox_detected);
    check_injected_dlls(&sandbox_detected);
    check_forensic_activity(&sandbox_detected);
    check_timing_anomalies(&sandbox_detected);
    
    printf("\n--- System Resource Checks ---\n");
    
    SYSTEM_INFO sysInfo;
    MEMORYSTATUSEX memInfo;
    DWORD procNum;
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) {
        printf("[+] Low memory detected (< 4GB): %llu bytes\n", memInfo.ullTotalPhys);
        sandbox_detected++;
    }
    
    GetSystemInfo(&sysInfo);
    procNum = sysInfo.dwNumberOfProcessors;
    if (procNum < 2) {
        printf("[+] Single processor detected\n");
        sandbox_detected++;
    }
    
    GetComputerNameA(computerName, &size);
    printf("Computer name: %s\n", computerName);
    if (strstr(computerName, "SANDBOX") != NULL ||
        strstr(computerName, "VIRUS") != NULL ||
        strstr(computerName, "MALWARE") != NULL ||
        strstr(computerName, "SAMPLE") != NULL ||
        strstr(computerName, "VM") != NULL) {
        printf("[+] Suspicious computer name detected\n");
        sandbox_detected++;
    }
    
    printf("\n--- Registry Checks ---\n");
    
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
                    "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 
                    0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char data[1024];
        DWORD dataSize = sizeof(data);
        DWORD type;
        if (RegQueryValueEx(hKey, "0", NULL, &type, (LPBYTE)data, &dataSize) == ERROR_SUCCESS) {
            printf("Disk hardware: %s\n", data);
            if (strstr(data, "VMWARE") != NULL || 
                strstr(data, "VBOX") != NULL ||
                strstr(data, "QEMU") != NULL ||
                strstr(data, "VIRTUAL") != NULL) {
                printf("[+] Virtual disk hardware detected\n");
                sandbox_detected++;
            }
        }
        RegCloseKey(hKey);
    }
    
    // Call motherboard info with score tracking
    get_motherboard_info(&sandbox_detected);
#else
    // Linux sandbox detection, should not trigger, was used for edge case testing
    FILE *fp;
    char line[1024];
    
    // Check for common VM modules
    printf("Checking for virtualization modules...\n");
    fp = popen("lsmod 2>/dev/null", "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (strstr(line, "vmw_") != NULL || 
                strstr(line, "vbox") != NULL ||
                strstr(line, "virtualbox") != NULL ||
                strstr(line, "parallels") != NULL ||
                strstr(line, "qemu") != NULL ||
                strstr(line, "kvm") != NULL) {
                printf("[+] VM module detected: %s", line);
                sandbox_detected++;
            }
        }
        pclose(fp);
    }
    
    // Check for QEMU/KVM CPU
    fp = popen("grep -i -E 'qemu|kvm|virtual|vmware|hypervisor' /proc/cpuinfo 2>/dev/null", "r");
    if (fp != NULL) {
        if (fgets(line, sizeof(line), fp) != NULL) {
            printf("[+] Virtual CPU detected: %s", line);
            sandbox_detected++;
        }
        pclose(fp);
    }
    
    // Check for Docker or container environment
    if (access("/.dockerenv", F_OK) != -1) {
        printf("[+] Docker environment detected (/.dockerenv exists)\n");
        sandbox_detected++;
    }
    
    if (access("/proc/self/cgroup", F_OK) != -1) {
        FILE *cgroup = fopen("/proc/self/cgroup", "r");
        if (cgroup != NULL) {
            while (fgets(line, sizeof(line), cgroup) != NULL) {
                if (strstr(line, "docker") != NULL || 
                    strstr(line, "lxc") != NULL || 
                    strstr(line, "container") != NULL) {
                    printf("[+] Container detected in cgroups: %s", line);
                    sandbox_detected++;
                    break;
                }
            }
            fclose(cgroup);
        }
    }
    
    // Check system memory
    fp = popen("free -m | grep Mem", "r");
    if (fp != NULL) {
        if (fgets(line, sizeof(line), fp) != NULL) {
            int mem;
            if (sscanf(line, "%*s %d", &mem) == 1) {
                printf("System memory: %d MB\n", mem);
                if (mem < 4000) {
                    printf("[+] Low memory detected (< 4GB)\n");
                    sandbox_detected++;
                }
            }
        }
        pclose(fp);
    }
    
    // Check number of CPUs
    fp = popen("nproc 2>/dev/null", "r");
    if (fp != NULL) {
        if (fgets(line, sizeof(line), fp) != NULL) {
            int cpus = atoi(line);
            printf("Number of CPUs: %d\n", cpus);
            if (cpus < 2) {
                printf("[+] Single CPU detected\n");
                sandbox_detected++;
            }
        }
        pclose(fp);
    }
    
    // Check for common VM MAC addresses
    fp = popen("ip addr 2>/dev/null | grep -i 'link/ether' | grep -i -E '00:50:56|00:0C:29|00:05:69|08:00:27|52:54:00'", "r");
    if (fp != NULL) {
        if (fgets(line, sizeof(line), fp) != NULL) {
            printf("[+] VM MAC address detected: %s", line);
            sandbox_detected++;
        }
        pclose(fp);
    }    
#endif

    printf("\nSandbox indicators found: %d\n\n", sandbox_detected);
    return sandbox_detected > 1;  // Raised threshold
}
#endif