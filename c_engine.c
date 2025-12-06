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
#include <sys/stat.h>
#include <fcntl.h>

#define SOCKET_PATH "/tmp/cengine.sock"
#define BACKLOG 5
#define BLOCKS_DIR "blocks"
#define MANIFESTS_DIR "manifests"

// OPCodes
#define OP_UPLOAD_START  0x01
#define OP_UPLOAD_CHUNK  0x02
#define OP_UPLOAD_FINISH 0x03
#define OP_UPLOAD_DONE 0x81

typedef struct {
    int index;
    int size;
    char hash[65];
} ChunkInfo;

typedef struct {
    char filename[256];
    size_t total_size;
    ChunkInfo *chunks;
    int chunk_count;
    int capacity;
} UploadContext;


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

void simple_hash(const char *data, int len, char *output_hex) {
    unsigned long hash = 5381;
    for (int i = 0; i < len; i++) hash = ((hash << 5) + hash) + data[i];

    // Convert The Number To 64_Bit Hexadecimal String 
    sprintf(output_hex, "%08lx%08lx%08lx%08lx", hash, hash, hash, hash);
}

void ensure_dir(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) mkdir(path, 0700);
}

void send_response(int client_fd, unsigned char opcode, const char *payload) {
    uint32_t len = strlen(payload);
    uint32_t net_len = htonl(len); 
    
    write(client_fd, &opcode, 1);
    write(client_fd, &net_len, 4);
    if (len > 0) write(client_fd, payload, len);
}

void save_chunk_to_disk(const char *data, int len, char *out_hash) {
    simple_hash(data, len, out_hash); 

    char path_l1[256], path_l2[256], full_path[512];
    char sub1[3], sub2[3];
    
    strncpy(sub1, out_hash, 2); sub1[2] = 0;
    strncpy(sub2, out_hash + 2, 2); sub2[2] = 0;

    snprintf(path_l1, sizeof(path_l1), "%s/%s", BLOCKS_DIR, sub1);
    snprintf(path_l2, sizeof(path_l2), "%s/%s/%s", BLOCKS_DIR, sub1, sub2);

    ensure_dir(BLOCKS_DIR);
    ensure_dir(path_l1);
    ensure_dir(path_l2);

    snprintf(full_path, sizeof(full_path), "%s/%s", path_l2, out_hash);

    FILE *fp = fopen(full_path, "wb");
    if (fp) {
        fwrite(data, 1, len, fp);
        fclose(fp);
    } else {
        perror("File write error");
    }
}

void add_chunk_info(UploadContext *ctx, int size, const char *hash) {
    if (ctx->chunk_count >= ctx->capacity) {
        ctx->capacity *= 2;
        ctx->chunks = realloc(ctx->chunks, ctx->capacity * sizeof(ChunkInfo));
    }
    ctx->chunks[ctx->chunk_count].index = ctx->chunk_count;
    ctx->chunks[ctx->chunk_count].size = size;
    strcpy(ctx->chunks[ctx->chunk_count].hash, hash);
    ctx->chunk_count++;
    ctx->total_size += size;
}

void finalize_manifest(UploadContext *ctx, int client_fd) {
    // Estimating The Space Required For JSON
    size_t json_buf_size = 1024 + (ctx->chunk_count * 200);
    char *json_str = malloc(json_buf_size);
    
    int offset = snprintf(json_str, json_buf_size, 
        "{\n  \"version\": 1,\n  \"hash_algo\": \"simple\",\n  \"chunk_size\": 262144,\n  \"total_size\": %zu,\n  \"filename\": \"%s\",\n  \"chunks\": [\n",
        ctx->total_size, ctx->filename);

    for (int i = 0; i < ctx->chunk_count; i++) {
        offset += snprintf(json_str + offset, json_buf_size - offset,
            "    {\"index\": %d, \"size\": %d, \"hash\": \"%s\"}%s\n",
            ctx->chunks[i].index, ctx->chunks[i].size, ctx->chunks[i].hash,
            (i < ctx->chunk_count - 1) ? "," : "");
    }
    snprintf(json_str + offset, json_buf_size - offset, "  ]\n}");

    char cid[65];
    simple_hash(json_str, strlen(json_str), cid);

    ensure_dir(MANIFESTS_DIR);
    char manifest_path[512];
    snprintf(manifest_path, sizeof(manifest_path), "%s/%s.json", MANIFESTS_DIR, cid);
    
    FILE *fp = fopen(manifest_path, "w");
    if (fp) {
        fputs(json_str, fp);
        fclose(fp);
        printf("[Manifest] Created: %s\n", manifest_path);
        
        char response_payload[256];
        snprintf(response_payload, sizeof(response_payload), "{\"cid\": \"%s\"}", cid);
        send_response(client_fd, OP_UPLOAD_DONE, response_payload);
        
    } else {
        perror("Manifest save error");
    }

    free(json_str);
}

void handle_client(int client_fd) {
    unsigned char opcode;
    uint32_t payload_len_net; 
    uint32_t payload_len;

    // Begin New Context For Upload 
    UploadContext ctx;
    ctx.chunk_count = 0;
    ctx.total_size = 0;
    ctx.capacity = 10;
    ctx.chunks = malloc(ctx.capacity * sizeof(ChunkInfo));
    strcpy(ctx.filename, "unknown.bin");

    while (1) {
        // Reading OPCode & Length
        if (read_n_bytes(client_fd, &opcode, 1) <= 0) break;
        if (read_n_bytes(client_fd, &payload_len_net, 4) <= 0) break;
        payload_len = ntohl(payload_len_net); 

        // Reading Payload
        char *payload = NULL;
        if (payload_len > 0) {
            payload = malloc(payload_len + 1);
            if (read_n_bytes(client_fd, payload, payload_len) <= 0) { free(payload); break; }
            payload[payload_len] = 0;
        }

        switch (opcode) {
            case OP_UPLOAD_START: 
                printf("[CMD] START Upload\n");

                if (payload && strstr(payload, "filename")) {
                    char *start = strstr(payload, ": \"");
                    if (start) {
                        start += 3;
                        char *end = strchr(start, '"');
                        if (end) { *end = 0; strncpy(ctx.filename, start, 255); }
                    }
                }
                break;

            case OP_UPLOAD_CHUNK:
                if (payload) {
                    char chunk_hash[65];
                    save_chunk_to_disk(payload, payload_len, chunk_hash);
                    add_chunk_info(&ctx, payload_len, chunk_hash);
                    printf("[Chunk] Saved index %d (Size: %d)\n", ctx.chunk_count - 1, payload_len);
                }
                break;
                
            case OP_UPLOAD_FINISH:
                printf("[CMD] FINISH Upload. Finalizing...\n");
                finalize_manifest(&ctx, client_fd);
                break;

            default:
                printf("[Info] Unknown Opcode: 0x%02X\n", opcode);
        }

        if (payload) free(payload);
    }

    free(ctx.chunks);
    close(client_fd);
}

int main() {
    struct sockaddr_un server_addr;
    struct sigaction sa;

    ensure_dir(BLOCKS_DIR);
    ensure_dir(MANIFESTS_DIR);

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

    printf("[Info] Engine Ready (Phase 3 FINAL). Waiting for connections...\n");

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1) continue;
        handle_client(client_fd);
    }
    return 0;
}
