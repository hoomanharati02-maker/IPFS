#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/cengine.sock"
#define BACKLOG 5

int server_fd = -1; // Socket Not Created Yet

// Interrupt Signal
void handle_signal(int sig) {
    if (server_fd != -1) {
        close(server_fd);
    }

    // Deleting The Socket File
    unlink(SOCKET_PATH);
    printf("\n[Info] Server shutting down. Socket removed.\n");
    exit(0);
}

// Setting The Signals (For Crystal Clear Output)
void setup_signal_handling() {
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

int main() {
    struct sockaddr_un server_addr;
    struct sockaddr_un client_addr;
    socklen_t client_len;
    int client_fd;

    setup_signal_handling();

    // Creating Socket 
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Deleting The Socket File
    unlink(SOCKET_PATH);

    // Bind The Socket To The Server Address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1) {
        perror("[Error] Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listening... 
    if (listen(server_fd, BACKLOG) == -1) {
        perror("[Error] Listen failed");
        close(server_fd);
        unlink(SOCKET_PATH);
        exit(EXIT_FAILURE);
    }

    printf("[Info] c_engine started. Listening on %s...\n", SOCKET_PATH);

    while (1) {
        client_len = sizeof(struct sockaddr_un);
        
        // Waiting For Client To Connect
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_fd == -1) {
            perror("[Error] Accept failed");
            continue; 
        }

        printf("[Info] New connection accepted! (FD: %d)\n", client_fd);
        close(client_fd);
    }
    return 0;
}
