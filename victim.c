#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>

#include <cpuid.h> // for __get_cpuid

#define BUFFER_SIZE 1024
#define MAX_FRAGMENTS 1000
#define PORT 8080
#define DEVICE_B_IP "192.168.8.128"  // Hardcoded IP address for Device B

/* ----------- Helper: case-insensitive substring ----------- */
static char *strcasestr_safe(const char *hay, const char *needle) {
    if (!hay || !needle) return NULL;
    size_t nlen = strlen(needle);
    if (nlen == 0) return (char*)hay;
    for (; *hay; ++hay) {
        if (tolower((unsigned char)*hay) == tolower((unsigned char)*needle)) {
            if (strncasecmp(hay, needle, nlen) == 0) return (char*)hay;
        }
    }
    return NULL;
}

/* ------------- VM detection (Linux-only) ------------- */

/* CPUID checks: hypervisor bit and hypervisor vendor (leaf 0x40000000) */
static void check_cpuid_virtualization_linux() {
    printf("\n=== CPU / CPUID checks ===\n");
    unsigned int eax, ebx, ecx, edx;
    // leaf 1 => ECX bit 31 is hypervisor present
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        int hypervisor_present = (ecx >> 31) & 1;
        printf("Hypervisor present bit (CPUID.1:ECX[31]): %d\n", hypervisor_present);
        int vmx = (ecx >> 5) & 1; // Intel VMX
        printf("VMX (Intel VT-x) reported: %d\n", vmx);
    } else {
        printf("CPUID leaf 1 not available\n");
    }
    // leaf 0x40000000 => hypervisor vendor id string in EBX, ECX, EDX
    if (__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
        char vendor[13];
        memcpy(vendor + 0, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);
        vendor[12] = '\0';
        printf("Hypervisor vendor id (CPUID 0x40000000): %s\n", vendor);
        const char *known[] = { "KVMKVMKVM", "Microsoft Hv", "VMwareVMware", "VBoxVBoxVBox", "XenVMMXenVMM", NULL };
        for (int i = 0; known[i]; ++i) {
            if (strcasestr_safe(vendor, known[i])) {
                printf("  -> Matches known hypervisor vendor substring: %s\n", known[i]);
            }
        }
    } else {
        printf("CPUID leaf 0x40000000 not available (no hypervisor vendor id available)\n");
    }

    /* As a fallback also inspect /proc/cpuinfo for hypervisor keyword */
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[512];
        int found = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strcasestr_safe(line, "hypervisor")) found = 1;
        }
        fclose(f);
        printf("/proc/cpuinfo contains 'hypervisor' keyword: %s\n", found ? "YES" : "NO");
    }
}

/* MAC prefix checks: read /sys/class/net/ */
static void check_mac_prefixes_linux() {
    printf("\n=== MAC prefix & network adapter checks ===\n");
    const char *vm_prefixes[] = { "00:05:69", "00:0C:29", "00:50:56", "08:00:27", "00:1C:42", NULL };
    DIR *d = opendir("/sys/class/net");
    if (!d) {
        perror("opendir /sys/class/net");
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", ent->d_name);
        FILE *fa = fopen(path, "r");
        if (!fa) continue;
        char mac[128];
        if (fgets(mac, sizeof(mac), fa)) {
            char *nl = strchr(mac, '\n'); if (nl) *nl = 0;
            printf("Interface: %s, MAC: %s\n", ent->d_name, mac);
            for (int i = 0; vm_prefixes[i]; ++i) {
                if (strncasecmp(mac, vm_prefixes[i], strlen(vm_prefixes[i])) == 0) {
                    printf("  -> MAC prefix matches VM vendor: %s\n", vm_prefixes[i]);
                }
            }
        }
        fclose(fa);
    }
    closedir(d);
}

/* Kernel module check: read /proc/modules */
static void check_kernel_modules_linux() {
    printf("\n=== Kernel modules / drivers check ===\n");
    FILE *f = fopen("/proc/modules", "r");
    if (!f) {
        perror("fopen /proc/modules");
        return;
    }
    char buf[512];
    int found_vm_module = 0;
    const char *modnames[] = { "vboxguest", "vboxsf", "vboxvideo", "vmhgfs", "vmw_balloon", "kvm", "virtio", "vboxguest", "vboxdrv", NULL };
    while (fgets(buf, sizeof(buf), f)) {
        for (int i = 0; modnames[i]; ++i) {
            if (strcasestr_safe(buf, modnames[i])) {
                printf("Found kernel module related to VM: %s", buf);
                found_vm_module = 1;
            }
        }
    }
    fclose(f);
    if (!found_vm_module) printf("No obvious VM kernel module names found in /proc/modules\n");
}

/* DMI / BIOS checks via /sys/class/dmi/id */
static void check_dmi_and_disk_linux() {
    printf("\n=== DMI / BIOS / Disk checks ===\n");
    const char *dmi_files[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/product_version",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_name",
        "/sys/class/dmi/id/board_vendor",
        NULL
    };
    for (int i = 0; dmi_files[i]; ++i) {
        FILE *f = fopen(dmi_files[i], "r");
        if (!f) continue;
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            char *nl = strchr(line, '\n'); if (nl) *nl = 0;
            printf("%s: %s\n", dmi_files[i], line);
            if (strcasestr_safe(line, "vbox") || strcasestr_safe(line, "virtual") ||
                strcasestr_safe(line, "vmware") || strcasestr_safe(line, "qemu") ||
                strcasestr_safe(line, "kvm") ) {
                printf("  -> DMI string implies virtualization\n");
            }
        }
        fclose(f);
    }

    // Disk model checks via /sys/block/device/model
    DIR *b = opendir("/sys/block");
    if (!b) return;
    struct dirent *e;
    while ((e = readdir(b)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char modelpath[512];
        snprintf(modelpath, sizeof(modelpath), "/sys/block/%s/device/model", e->d_name);
        FILE *fm = fopen(modelpath, "r");
        if (!fm) continue;
        char model[256];
        if (fgets(model, sizeof(model), fm)) {
            char *nl = strchr(model, '\n'); if (nl) *nl = 0;
            printf("Block device %s model: %s\n", e->d_name, model);
            if (strcasestr_safe(model, "vbox") || strcasestr_safe(model, "vmware") ||
                strcasestr_safe(model, "virtual") || strcasestr_safe(model, "qemu")) {
                printf("  -> Disk model implies virtual disk\n");
            }
        }
        fclose(fm);
    }
    closedir(b);
}

/* Filesystem checks for common VM tools */
static void check_filesystem_vmtools_linux() {
    printf("\n=== Filesystem checks for VM tools ===\n");
    const char *paths[] = {
        "/usr/bin/vmtoolsd",
        "/usr/sbin/VBoxService",
        "/usr/bin/VBoxService",
        "/usr/bin/qemu-ga",
        "/usr/bin/virt-what",
        NULL
    };
    for (int i = 0; paths[i]; ++i) {
        if (access(paths[i], F_OK) == 0) {
            printf("Found VM-related file: %s\n", paths[i]);
        }
    }
}

/* Process checks: scan /proc/ */
static int is_process_running_posix(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        char cmdpath[512];
        snprintf(cmdpath, sizeof(cmdpath), "/proc/%s/cmdline", ent->d_name);
        FILE *f = fopen(cmdpath, "r");
        if (!f) continue;
        char cmd[512];
        size_t r = fread(cmd, 1, sizeof(cmd)-1, f);
        fclose(f);
        if (r > 0) {
            cmd[r] = '\0';
            // cmdline is NUL-separated; treat as string
            if (strcasestr_safe(cmd, name)) { closedir(d); return 1; }
        }
    }
    closedir(d);
    return 0;
}

static void check_processes_linux() {
    printf("\n=== Process checks ===\n");
    const char *procs[] = { "vmtoolsd", "VBoxService", "VBoxClient", "vboxadd", "qemu-ga", "virtlogd", "virtlogd-qemu", "vboxtray", NULL };
    for (int i = 0; procs[i]; ++i) {
        printf("Process %s running: %s\n", procs[i], is_process_running_posix(procs[i]) ? "YES" : "NO");
    }
}

/* Network gateway & hostname heuristics */
static void check_network_and_hostname_linux() {
    printf("\n=== Network & hostname checks ===\n");
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        printf("Hostname: %s\n", hostname);
        if (strcasestr_safe(hostname, "vm") || strcasestr_safe(hostname, "vbox") ||
            strcasestr_safe(hostname, "virtual") || strcasestr_safe(hostname, "qemu")) {
            printf("  -> Hostname suggests VM\n");
        }
    }
    // Default gateway heuristic (look for 10.0.2.2)
    FILE *p = popen("ip route 2>/dev/null | grep default | awk '{print $3}'", "r");
    if (p) {
        char gw[128];
        if (fgets(gw, sizeof(gw), p)) {
            char *nl = strchr(gw, '\n'); if (nl) *nl = 0;
            printf("Default gateway: %s\n", gw);
            if (strcmp(gw, "10.0.2.2") == 0) {
                printf("  -> Gateway 10.0.2.2 suggests VirtualBox/Android emulator NAT\n");
            }
        }
        pclose(p);
    }
}

/* Run all Linux-compatible VM checks and print findings */
static void run_all_vm_checks_linux() {
    check_cpuid_virtualization_linux();
    check_mac_prefixes_linux();
    check_kernel_modules_linux();
    check_dmi_and_disk_linux();
    check_filesystem_vmtools_linux();
    check_processes_linux();
    check_network_and_hostname_linux();
}

/* ------------------- Original networking code (kept as-is) ------------------- */

/* Function to get the local IP address */
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

/* Function to request payload from Device B and receive fragments */
int main() {
    /* ---------- RUN VM DETECTION FIRST (print-only) ---------- */
    run_all_vm_checks_linux(); // detection prints results but DOES NOT exit

    /* ---------- Then proceed with original networking logic ---------- */
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
    printf("\nDevice A IP: %s\n", local_ip);
    
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
