#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <arpa/inet.h>

#define SOCKET_PATH "/tmp/cengine.sock"
#define BACKLOG 5

// OPCodes
#define OP_UPLOAD_START  0x01
#define OP_UPLOAD_CHUNK  0x02
#define OP_UPLOAD_FINISH 0x03
#define OP_DOWNLOAD_START 0x10

int server_fd = -1; // Socket Not Created Yet

// Interrupt Signal
void handle_signal(int sig) {
    if (server_fd != -1){
        close(server_fd);
    } 

    // Deleting The Socket File
    unlink(SOCKET_PATH);
    printf("\n[Info] Server shutting down.\n");
    exit(0);
}

int read_n_bytes(int fd, void *buffer, int n) {
    int total_read = 0;
    char *buf_ptr = (char *)buffer;
    while (total_read < n) {
        int bytes_read = read(fd, buf_ptr + total_read, n - total_read);
        if (bytes_read <= 0) return bytes_read; // Error
        total_read += bytes_read;
    }
    return total_read;
}

void handle_client(int client_fd) {
    unsigned char opcode;
    uint32_t payload_len_net; 
    uint32_t payload_len;

    while (1) {
        // Reading 1 Byte OPCode
        int res = read_n_bytes(client_fd, &opcode, 1);
        if (res <= 0) break; 

        // Reading 4 Byte Message
        res = read_n_bytes(client_fd, &payload_len_net, 4);
        if (res <= 0) break;

        payload_len = ntohl(payload_len_net);

        printf("[Recv] Opcode: 0x%02X, Length: %d\n", opcode, payload_len);

        // Reading Payload
        char *payload = NULL;
        if (payload_len > 0) {
            payload = malloc(payload_len + 1); 
            if (!payload) {
                perror("[Error] Malloc failed");
                break;
            }
            res = read_n_bytes(client_fd, payload, payload_len);
            if (res <= 0) {
                free(payload);
                break;
            }
            payload[payload_len] = '\0';
        }

        switch (opcode) {
            case OP_UPLOAD_START:
                // Payload: filename, total_size, ...

                printf(" -> CMD: UPLOAD_START\n");
                // TO DO: Parse JSON payload later...
                break;

            case OP_UPLOAD_CHUNK:
                printf(" -> CMD: UPLOAD_CHUNK (Size: %d bytes)\n", payload_len);
                break;
                
            case OP_UPLOAD_FINISH:
                printf(" -> CMD: UPLOAD_FINISH\n");
                break;

            default:
                printf(" -> Unknown Opcode: 0x%02X\n", opcode);
        }

        if (payload) free(payload);
    }
    close(client_fd);
    printf("[Info] Client disconnected.\n");
}

int main() {
    struct sockaddr_un server_addr;
    struct sigaction sa;

    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    // Creating Socket 
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1){ 
        perror("Socket error"); 
        exit(1); 
    }

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Deleting The Socket File
    unlink(SOCKET_PATH);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1) {
        perror("Bind error"); 
        exit(1);
    }
    if (listen(server_fd, BACKLOG) == -1) {
        perror("Listen error"); exit(1);
    }

    printf("[Info] Engine ready (Phase 2). Listening on %s...\n", SOCKET_PATH);

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1) continue;
        
        printf("[Info] Client connected.\n");        
        handle_client(client_fd);
    }
    return 0;
}
