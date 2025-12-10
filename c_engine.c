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
#include <fcntl.h>

#define BLOCKS_DIR "blocks"
#define MANIFESTS_DIR "manifests"

// Structure to hold chunk metadata
typedef struct {
    int index;
    int size;
    char hash[65];
} ChunkInfo;

// Structure to maintain upload state per connection
typedef struct {
    char filename[256];
    size_t total_size;
    ChunkInfo *chunks;
    int chunk_count;
    int capacity;
} UploadContext;

// Ensure directory exists
void ensure_dir(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        mkdir(path, 0700);
    }
}

// Hash Function
void compute_hash(const void *data, size_t len, char *output_hex) {
    unsigned long hash = 5381;
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + p[i]; 
    }
    sprintf(output_hex, "%08lx%08lx%08lx%08lx%08lx%08lx%08lx%08lx", hash, hash, hash+1, hash+2, hash, hash, hash+1, hash+2);
}

#define OP_UPLOAD_START  0x01
#define OP_UPLOAD_CHUNK  0x02
#define OP_UPLOAD_FINISH 0x03
#define OP_UPLOAD_DONE   0x81

#define OP_DOWNLOAD_START 0x11
#define OP_DOWNLOAD_CHUNK 0x91
#define OP_DOWNLOAD_DONE  0x92

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
    // Store Upload State
    UploadContext ctx;
    mem(&ctx, 0, sizeof(ctx));

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
            memset(&ctx, 0, sizeof(ctx)); // Reset context
            if (len < sizeof(ctx.filename)) {
                strncpy(ctx.filename, (char*)payload, len);
                ctx.filename[len] = '\0';
            } else {
                strcpy(ctx.filename, "unknown.bin");
            }
            ctx.capacity = 10; 
            ctx.chunks = (ChunkInfo*)malloc(ctx.capacity * sizeof(ChunkInfo));
            ctx.chunk_count = 0;
            ctx.total_size = 0;

        } else if (op == OP_UPLOAD_CHUNK) {
            // TODO: process chunk (hash/store); here just drop
            if (ctx.chunks) {
                // Compute Hash
                char hash[65];
                compute_hash(payload, len, hash);

                // Prepare paths
                char path_l1[256], path_l2[256], full_path[512];
                char sub1[3], sub2[3];
                strncpy(sub1, hash, 2); sub1[2] = 0;
                strncpy(sub2, hash + 2, 2); sub2[2] = 0;

                snprintf(path_l1, sizeof(path_l1), "%s/%s", BLOCKS_DIR, sub1);
                snprintf(path_l2, sizeof(path_l2), "%s/%s/%s", BLOCKS_DIR, sub1, sub2);
                
                ensure_dir(BLOCKS_DIR);
                ensure_dir(path_l1);
                ensure_dir(path_l2);
                
                snprintf(full_path, sizeof(full_path), "%s/%s", path_l2, hash);

                // Write to disk
                FILE *fp = fopen(full_path, "wb");
                if (fp) {
                    fwrite(payload, 1, len, fp);
                    fclose(fp);
                }

                // Update Context
                if (ctx.chunk_count >= ctx.capacity) {
                    ctx.capacity *= 2;
                    ctx.chunks = (ChunkInfo*)realloc(ctx.chunks, ctx.capacity * sizeof(ChunkInfo));
                }
                ctx.chunks[ctx.chunk_count].index = ctx.chunk_count;
                ctx.chunks[ctx.chunk_count].size = (int)len;
                strcpy(ctx.chunks[ctx.chunk_count].hash, hash);
                ctx.chunk_count++;
                ctx.total_size += len;
            }

        } else if (op == OP_UPLOAD_FINISH) {
            // TODO: finalize DAG and compute real CID
            // Build JSON Manually
            size_t json_size = 1024 + (ctx.chunk_count * 200);
            char *json_str = (char*)malloc(json_size);
            
            int offset = sprintf(json_str, 
                "{\n  \"version\": 1,\n  \"hash_algo\": \"simple\",\n  \"chunk_size\": 262144,\n  \"total_size\": %zu,\n  \"filename\": \"%s\",\n  \"chunks\": [\n",
                ctx.total_size, ctx.filename);

            for (int i = 0; i < ctx.chunk_count; i++) {
                offset += sprintf(json_str + offset,
                    "    {\"index\": %d, \"size\": %d, \"hash\": \"%s\"}%s\n",
                    ctx.chunks[i].index, ctx.chunks[i].size, ctx.chunks[i].hash,
                    (i < ctx.chunk_count - 1) ? "," : "");
            }
            sprintf(json_str + offset, "  ]\n}");

            // Compute CID (Hash of Manifest)
            static char real_cid[65]; 
            compute_hash(json_str, strlen(json_str), real_cid);

            // Save Manifest
            ensure_dir(MANIFESTS_DIR);
            char m_path[512];
            snprintf(m_path, sizeof(m_path), "%s/%s.json", MANIFESTS_DIR, real_cid);
            FILE *fp = fopen(m_path, "w");
            if (fp) {
                fputs(json_str, fp);
                fclose(fp);
            }

            // Cleanup
            free(json_str);
            if (ctx.chunks) { free(ctx.chunks); ctx.chunks = NULL; }

            const char* cid = real_cid;
            printf("[ENGINE] UPLOAD_FINISH -> returning CID %s\n", cid);
            fflush(stdout);
            send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));
        } else if (op == OP_DOWNLOAD_START) {
            printf("[ENGINE] DOWNLOAD_START: cid=\"%.*s\"\n", (int)len, (char*)payload);
            fflush(stdout);
            // TODO: look up CID, stream verified chunks
            // Minimal placeholder: no chunks, just DONE
            send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
        } else {
        }

        free(payload);
    }
    close(cfd);
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

