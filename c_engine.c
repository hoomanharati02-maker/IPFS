// Build: gcc -O2 -pthread -o c_engine c_engine.c
// Run:   ./c_engine /tmp/cengine.sock

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef OP_UPLOAD_START
#define OP_UPLOAD_START   0x01
#define OP_UPLOAD_CHUNK   0x02
#define OP_UPLOAD_FINISH  0x03
#define OP_UPLOAD_DONE    0x81

#define OP_DOWNLOAD_START 0x11
#define OP_DOWNLOAD_CHUNK 0x91
#define OP_DOWNLOAD_DONE  0x92
#endif

#ifndef STORE_DIR
#define STORE_DIR "./store"
#endif

// Simple FNV-1a 64-bit for temporary deterministic CID
static inline uint64_t fnv1a64_init(void) {
    return 0xcbf29ce484222325ULL;
}
static inline uint64_t fnv1a64_update(uint64_t h, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char*)data;
    while (len--) {
        h ^= *p++;
        h *= 0x100000001b3ULL;
    }
    return h;
}
static int ensure_dir(const char *path) {
    // mkdir if not exists
    if (mkdir(path, 0755) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}


static const char* g_sock_path = NULL;

ssize_t read_n(int fd, void* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char*)buf + got, n - got);
        if (r == 0) return 0;
        if (r < 0) { if (errno == EINTR) continue; perror("read"); return -1; }
        got += r;
    }
    return (ssize_t)got;
}

int write_all(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w < 0) { if (errno == EINTR) continue; perror("write"); return -1; }
        sent += (size_t)w;
    }
    return 0;
}

int send_frame(int fd, uint8_t op, const void* payload, uint32_t len) {
    uint8_t header[5];
    header[0] = op;
    uint32_t be_len = htonl(len);
    memcpy(header + 1, &be_len, 4);
    if (write_all(fd, header, 5) < 0) return -1;
    if (len && write_all(fd, payload, len) < 0) return -1;
    return 0;
}

void handle_connection(int cfd) {
    FILE *up_fp = NULL;           // current upload temp file
    char up_tmp_path[512] = {0};  // path to temp file
    uint64_t up_hash = fnv1a64_init();
    size_t up_bytes = 0;          // number of uploaded bytes

    for (;;) {
        uint8_t header[5];
        ssize_t r = read_n(cfd, header, 5);
        if (r == 0) break;
        if (r < 0) { break; }
        uint8_t op = header[0];
        uint32_t len;
        memcpy(&len, header + 1, 4);
        len = ntohl(len);
        uint8_t* payload = NULL;
        if (len) {
            payload = (uint8_t*)malloc(len);
            if (!payload) { perror("malloc"); break; }
            if (read_n(cfd, payload, len) <= 0) { free(payload); break; }
        }

        if (op == OP_UPLOAD_START) {
            printf("[ENGINE] UPLOAD_START: name=\"%.*s\"\n", (int)len, (char*)payload);
            fflush(stdout);
            // TODO: initialize upload state
            // reset previous state
            if (up_fp) { 
                fclose(up_fp); 
                up_fp = NULL; 
                if (up_tmp_path[0]) unlink(up_tmp_path); up_tmp_path[0] = '\0'; 
            }
            up_hash = fnv1a64_init();
            up_bytes = 0;

            // Ensure storage dir exists
            if (ensure_dir(STORE_DIR) != 0) {
                const char *msg = "storage-dir-error";
                send_frame(cfd, OP_UPLOAD_DONE, msg, (uint32_t)strlen(msg));
            } else {
                snprintf(up_tmp_path, sizeof(up_tmp_path), STORE_DIR "/.tmp.%ld.%d", (long)getpid(), cfd);
                up_fp = fopen(up_tmp_path, "wb");
                if (!up_fp) {
                    const char *msg = "temp-open-error";
                    send_frame(cfd, OP_UPLOAD_DONE, msg, (uint32_t)strlen(msg));
                    up_tmp_path[0] = '\0';
                }
            }

        } else if (op == OP_UPLOAD_CHUNK) {
            // TODO: process chunk (hash/store); here just drop
            if (!up_fp) {
            } else if (len > 0) {
                size_t w = fwrite(payload, 1, len, up_fp);
                if (w != len) {
                    // disk error; abort
                    fclose(up_fp); up_fp = NULL;
                    if (up_tmp_path[0]) { unlink(up_tmp_path); up_tmp_path[0] = '\0'; }
                    const char *msg = "write-error";
                    send_frame(cfd, OP_UPLOAD_DONE, msg, (uint32_t)strlen(msg));
                } else {
                    up_hash = fnv1a64_update(up_hash, payload, len);
                    up_bytes += len;
                }
            }
            
        } else if (op == OP_UPLOAD_FINISH) {
            // TODO: finalize DAG and compute real CID    
            if (!up_fp) {
                const char *msg = "no-active-upload";
                send_frame(cfd, OP_UPLOAD_DONE, msg, (uint32_t)strlen(msg));
            } else {
                fflush(up_fp);
                fsync(fileno(up_fp));
                fclose(up_fp); up_fp = NULL;

                char cid[64];
                snprintf(cid, sizeof(cid), "fnv64-%016llx", (unsigned long long)up_hash);

                char final_path[512];
                snprintf(final_path, sizeof(final_path), STORE_DIR "/%s.bin", cid);
                if (rename(up_tmp_path, final_path) != 0) {
                    if (errno == EEXIST) unlink(up_tmp_path);
                    else unlink(up_tmp_path);
                }
                up_tmp_path[0] = '\0';

                send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
            }
            
        } else if (op == OP_DOWNLOAD_START) {
            printf("[ENGINE] DOWNLOAD_START: cid=\"%.*s\"\n", (int)len, (char*)payload);
            fflush(stdout);
            // TODO: look up CID, stream verified chunks
            // Minimal placeholder: no chunks, just DONE
            char cid[128];
            size_t n = (len < sizeof(cid)-1) ? len : sizeof(cid)-1;
            memcpy(cid, payload, n);
            cid[n] = '\0';

            // Open the stored file
            char final_path[512];
            snprintf(final_path, sizeof(final_path), STORE_DIR "/%s.bin", cid);
            FILE *fp = fopen(final_path, "rb");
            if (!fp) {
                // Not found so just end the stream (gateway treats as empty body)
                send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
            } else {
                const size_t CHUNK = 256 * 1024;
                char *buf = (char*)malloc(CHUNK);
                if (!buf) {
                    fclose(fp);
                    send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
                } else {
                    for (;;) {
                        size_t r = fread(buf, 1, CHUNK, fp);
                        if (r > 0) {
                            if (send_frame(cfd, OP_DOWNLOAD_CHUNK, buf, (uint32_t)r) != 0) { break; }
                        }
                        if (r < CHUNK) { break; } // EOF or read error
                    }
                    free(buf);
                    fclose(fp);
                    send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
                }
            }
            
        } else {
        }

        free(payload);
    }
    close(cfd);
    // --- connection cleanup ---
    if (up_fp) { fclose(up_fp); up_fp = NULL; }
    if (up_tmp_path[0]) { unlink(up_tmp_path); up_tmp_path[0] = '\0'; }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /tmp/cengine.sock\n", argv[0]);
        return 2;
    }
    g_sock_path = argv[1];

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 2; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_sock_path, sizeof(addr.sun_path) - 1);
    unlink(g_sock_path);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 2; }
    if (listen(fd, 64) < 0) { perror("listen"); return 2; }

    printf("[ENGINE] listening on %s\n", g_sock_path);
    fflush(stdout);

    for (;;) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); break; }
        // Thread-per-connection keeps it readable for OS labs
        pthread_t th;
        pthread_create(&th, NULL, (void*(*)(void*))handle_connection, (void*)(intptr_t)cfd);
        pthread_detach(th);
    }

    close(fd);
    unlink(g_sock_path);
    return 0;
}

