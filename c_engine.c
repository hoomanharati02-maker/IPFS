// c_engine.c
// Build: gcc -O2 -pthread -Wall -Wextra -o c_engine c_engine.c
// Run:   ./c_engine /tmp/cengine.sock

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// OPCODES-------------------------------------------------------------
enum {
    OP_UPLOAD_START   = 0x01,
    OP_UPLOAD_CHUNK   = 0x02,
    OP_UPLOAD_FINISH  = 0x03,
    OP_UPLOAD_DONE    = 0x81,

    OP_DOWNLOAD_START = 0x11,
    OP_DOWNLOAD_CHUNK = 0x91,
    OP_DOWNLOAD_DONE  = 0x92,

    OP_ERROR          = 0xFF
};

static const size_t DEFAULT_CHUNK_SIZE = 256u * 1024u; // 262144
static const int DEFAULT_WORKERS = 4;
static const int MAX_INFLIGHT = 32;

static char g_sock_path[PATH_MAX] = "/tmp/cengine.sock";
static char g_store_dir[PATH_MAX] = "./store";

static int safe_copy(char *dst, size_t dstsz, const char *src) {
    if (!dst || !src || dstsz == 0) return -1;
    size_t n = strlen(src);
    if (n >= dstsz) return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

static int buf_append(char *dst, size_t dstsz, size_t *pos, const char *src) {
    if (!dst || !pos || !src) return -1;
    size_t n = strlen(src);
    if (*pos + n >= dstsz) return -1;
    memcpy(dst + *pos, src, n);
    *pos += n;
    dst[*pos] = '\0';
    return 0;
}

static int build_blocks_dir(char out_path[PATH_MAX]) {
    size_t pos = 0;
    out_path[0] = '\0';
    if (buf_append(out_path, PATH_MAX, &pos, g_store_dir) < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, "/blocks") < 0) return -1;
    return 0;
}

static int build_manifests_dir(char out_path[PATH_MAX]) {
    size_t pos = 0;
    out_path[0] = '\0';
    if (buf_append(out_path, PATH_MAX, &pos, g_store_dir) < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, "/manifests") < 0) return -1;
    return 0;
}

static int build_manifest_path(const char *cid, char out_path[PATH_MAX]) {
    size_t pos = 0;
    out_path[0] = '\0';
    if (buf_append(out_path, PATH_MAX, &pos, g_store_dir) < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, "/manifests/") < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, cid) < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, ".json") < 0) return -1;
    return 0;
}

static ssize_t read_all(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char*)buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static int write_all(int fd, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

// Hash (FNV-1a 64-bit)-------------------------------------------------------------------
static uint64_t fnv1a64(const uint8_t *data, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint64_t)data[i];
        h *= 1099511628211ull;
    }
    return h;
}

static void to_hex64(uint64_t v, char out[17]) {
    static const char *hex = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        out[i] = hex[v & 0xFULL];
        v >>= 4;
    }
    out[16] = '\0';
}

// Filesystem helpers------------------------------------------------------------------------
static int mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) return -1;

    size_t len = strlen(tmp);
    if (len == 0) return 0;
    if (tmp[len-1] == '/') tmp[len-1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
    return 0;
}

static int fsync_dir_of(const char *path) {
    char dir[PATH_MAX];
    if (snprintf(dir, sizeof(dir), "%s", path) >= (int)sizeof(dir)) return -1;
    char *slash = strrchr(dir, '/');
    if (!slash) return 0;
    if (slash == dir) slash[1] = '\0';
    else *slash = '\0';

    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return -1;
    int rc = fsync(dfd);
    close(dfd);
    return rc;
}

static int atomic_write_file(const char *final_path, const uint8_t *data, size_t n) {
    char tmp_path[PATH_MAX];
    pid_t pid = getpid();
    unsigned long tid = (unsigned long)pthread_self();
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d.%lu", final_path, (int)pid, tid) >= (int)sizeof(tmp_path))
        return -1;

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    if (n && write_all(fd, data, n) < 0) { close(fd); unlink(tmp_path); return -1; }
    if (fsync(fd) < 0) { close(fd); unlink(tmp_path); return -1; }
    close(fd);

    if (rename(tmp_path, final_path) < 0) {
        // If final exists (race / dedup), discard temp.
        if (errno == EEXIST || errno == ENOTEMPTY) { unlink(tmp_path); return 0; }
        unlink(tmp_path);
        return -1;
    }
    (void)fsync_dir_of(final_path);
    return 0;
}

static int file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

static int read_entire_file(const char *path, uint8_t **out, size_t *out_len) {
    *out = NULL; *out_len = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    if (st.st_size < 0) { close(fd); return -1; }

    size_t n = (size_t)st.st_size;
    uint8_t *buf = (uint8_t*)malloc(n ? n : 1);
    if (!buf) { close(fd); return -1; }

    if (n) {
        ssize_t r = read_all(fd, buf, n);
        if (r < 0 || (size_t)r != n) { free(buf); close(fd); return -1; }
    }
    close(fd);
    *out = buf;
    *out_len = n;
    return 0;
}

// Framing-------------------------------------------------------------------------------------------- 
static int send_frame(int fd, uint8_t op, const uint8_t *payload, uint32_t len) {
    uint8_t hdr[5];
    hdr[0] = op;
    uint32_t be = htonl(len);
    memcpy(hdr + 1, &be, 4);
    if (write_all(fd, hdr, sizeof(hdr)) < 0) return -1;
    if (len && payload) {
        if (write_all(fd, payload, len) < 0) return -1;
    }
    return 0;
}

static int recv_frame(int fd, uint8_t *op, uint8_t **payload, uint32_t *len) {
    *payload = NULL;
    uint8_t hdr[5];
    ssize_t r = read_all(fd, hdr, sizeof(hdr));
    if (r == 0) return 1; // EOF
    if (r < 0 || r != (ssize_t)sizeof(hdr)) return -1;

    *op = hdr[0];
    uint32_t be;
    memcpy(&be, hdr + 1, 4);
    *len = ntohl(be);

    if (*len) {
        uint8_t *buf = (uint8_t*)malloc(*len);
        if (!buf) return -1;
        ssize_t rr = read_all(fd, buf, *len);
        if (rr < 0 || (uint32_t)rr != *len) { free(buf); return -1; }
        *payload = buf;
    }
    return 0;
}

typedef struct BlockEnt {
    char *hash;
    uint64_t refcount;
    struct BlockEnt *next;
} BlockEnt;

#define BLOCK_HT_SZ 4096
static BlockEnt *g_block_ht[BLOCK_HT_SZ];
static pthread_mutex_t g_block_mu = PTHREAD_MUTEX_INITIALIZER;

static uint32_t str_hash32(const char *s) {
    uint32_t h = 2166136261u;
    for (const unsigned char *p=(const unsigned char*)s; *p; p++) {
        h ^= (uint32_t)(*p);
        h *= 16777619u;
    }
    return h;
}

static void block_ref_inc(const char *hash) {
    uint32_t idx = str_hash32(hash) % BLOCK_HT_SZ;
    pthread_mutex_lock(&g_block_mu);
    for (BlockEnt *e = g_block_ht[idx]; e; e=e->next) {
        if (strcmp(e->hash, hash)==0) { e->refcount++; pthread_mutex_unlock(&g_block_mu); return; }
    }
    BlockEnt *e = (BlockEnt*)calloc(1, sizeof(BlockEnt));
    if (e) {
        e->hash = strdup(hash);
        e->refcount = 1;
        e->next = g_block_ht[idx];
        g_block_ht[idx] = e;
    }
    pthread_mutex_unlock(&g_block_mu);
}

// Thread pool----------------------------------------------------------------------
typedef void (*job_fn)(void*);

typedef struct Job {
    job_fn fn;
    void *arg;
    struct Job *next;
} Job;

typedef struct ThreadPool {
    pthread_t *threads;
    int nthreads;
    Job *head, *tail;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int stop;
} ThreadPool;

static ThreadPool g_pool;

static void* worker_main(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_pool.mu);
        while (!g_pool.stop && g_pool.head == NULL) {
            pthread_cond_wait(&g_pool.cv, &g_pool.mu);
        }
        if (g_pool.stop && g_pool.head == NULL) {
            pthread_mutex_unlock(&g_pool.mu);
            break;
        }
        Job *j = g_pool.head;
        g_pool.head = j->next;
        if (!g_pool.head) g_pool.tail = NULL;
        pthread_mutex_unlock(&g_pool.mu);

        j->fn(j->arg);
        free(j);
    }
    return NULL;
}

static int pool_init(int nthreads) {
    memset(&g_pool, 0, sizeof(g_pool));
    g_pool.nthreads = nthreads;
    g_pool.threads = (pthread_t*)calloc((size_t)nthreads, sizeof(pthread_t));
    if (!g_pool.threads) return -1;
    pthread_mutex_init(&g_pool.mu, NULL);
    pthread_cond_init(&g_pool.cv, NULL);
    for (int i=0;i<nthreads;i++) {
        if (pthread_create(&g_pool.threads[i], NULL, worker_main, NULL) != 0) return -1;
    }
    return 0;
}

static void pool_submit(job_fn fn, void *arg) {
    Job *j = (Job*)calloc(1, sizeof(Job));
    if (!j) { fprintf(stderr, "OOM: job\n"); return; }
    j->fn = fn;
    j->arg = arg;
    pthread_mutex_lock(&g_pool.mu);
    if (g_pool.tail) g_pool.tail->next = j;
    else g_pool.head = j;
    g_pool.tail = j;
    pthread_cond_signal(&g_pool.cv);
    pthread_mutex_unlock(&g_pool.mu);
}

static void pool_stop(void) {
    pthread_mutex_lock(&g_pool.mu);
    g_pool.stop = 1;
    pthread_cond_broadcast(&g_pool.cv);
    pthread_mutex_unlock(&g_pool.mu);
    for (int i=0;i<g_pool.nthreads;i++) pthread_join(g_pool.threads[i], NULL);
    free(g_pool.threads);
    pthread_mutex_destroy(&g_pool.mu);
    pthread_cond_destroy(&g_pool.cv);
}

// Perconnection inflight limiter----------------------------------------------------
typedef struct InflightLimiter {
    int outstanding;
    pthread_mutex_t mu;
    pthread_cond_t cv;
} InflightLimiter;

static void inflight_init(InflightLimiter *l) {
    l->outstanding = 0;
    pthread_mutex_init(&l->mu, NULL);
    pthread_cond_init(&l->cv, NULL);
}

static void inflight_destroy(InflightLimiter *l) {
    pthread_mutex_destroy(&l->mu);
    pthread_cond_destroy(&l->cv);
}

static void inflight_acquire(InflightLimiter *l) {
    pthread_mutex_lock(&l->mu);
    while (l->outstanding >= MAX_INFLIGHT) pthread_cond_wait(&l->cv, &l->mu);
    l->outstanding++;
    pthread_mutex_unlock(&l->mu);
}

static void inflight_release(InflightLimiter *l) {
    pthread_mutex_lock(&l->mu);
    if (l->outstanding > 0) l->outstanding--;
    pthread_cond_signal(&l->cv);
    pthread_mutex_unlock(&l->mu);
}

// Manifest lock---------------------------------------------------------------------------------------------
static pthread_rwlock_t g_manifest_rw = PTHREAD_RWLOCK_INITIALIZER;

// Chunk metadata--------------------------------------------------------------------------------------------
typedef struct ChunkMeta {
    int index;
    size_t size;
    char hash[32]; // "fnv64-"+16hex 
} ChunkMeta;

// Paths-------------------------------------------------------------------------------------------------------
static int block_path_from_hash(const char *hash, char out_path[PATH_MAX]) {
    if (!hash || !out_path) return -1;
    const char *hex = strchr(hash, '-');
    hex = hex ? (hex + 1) : hash;
    if (strlen(hex) < 4) return -1;

    char d1[3] = { hex[0], hex[1], '\0' };
    char d2[3] = { hex[2], hex[3], '\0' };

    size_t pos = 0;
    out_path[0] = '\0';

    if (buf_append(out_path, PATH_MAX, &pos, g_store_dir) < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, "/blocks/") < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, d1) < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, "/") < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, d2) < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, "/") < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, hash) < 0) return -1;
    if (buf_append(out_path, PATH_MAX, &pos, ".bin") < 0) return -1;

    return 0;
}


// Upload task-----------------------------------------------------------------------------------------------------
typedef struct UploadTask {
    int index;
    size_t size;
    uint8_t *data;

    char hash[32];
    int status; // 0 ok, <0 error
    int done;

    InflightLimiter *limiter;
    pthread_mutex_t mu;
    pthread_cond_t cv;
} UploadTask;

static void upload_task_fn(void *arg) {
    UploadTask *t = (UploadTask*)arg;
    t->status = 0;

    uint64_t h = fnv1a64(t->data, t->size);
    char hex[17];
    to_hex64(h, hex);
    snprintf(t->hash, sizeof(t->hash), "fnv64-%s", hex);

    char block_path[PATH_MAX];
    if (block_path_from_hash(t->hash, block_path) < 0) { t->status = -2; goto done; }

    char parent[PATH_MAX];
    snprintf(parent, sizeof(parent), "%s", block_path);
    char *slash = strrchr(parent, '/');
    if (slash) *slash = '\0';
    if (mkdir_p(parent, 0755) < 0) {
        t->status = -1;
        goto done;
    }

    if (!file_exists(block_path)) {
        if (atomic_write_file(block_path, t->data, t->size) < 0) {
            if (!file_exists(block_path)) {
                t->status = -1;
                goto done;
            }
        }
    }
    block_ref_inc(t->hash);

done:
    free(t->data);
    t->data = NULL;

    inflight_release(t->limiter);

    pthread_mutex_lock(&t->mu);
    t->done = 1;
    pthread_cond_broadcast(&t->cv);
    pthread_mutex_unlock(&t->mu);
}

// Download task--------------------------------------------------------------------------------------
typedef struct DownloadTask {
    int index;
    size_t expected_size;
    char expected_hash[32];

    uint8_t *data;
    size_t size;
    int status; // 0 ok, -2 not found, -3 hash mismatch, -1 other
    int done;

    InflightLimiter *limiter;
    pthread_mutex_t mu;
    pthread_cond_t cv;
} DownloadTask;

static void download_task_fn(void *arg) {
    DownloadTask *t = (DownloadTask*)arg;
    t->status = 0;

    char block_path[PATH_MAX];
    if (block_path_from_hash(t->expected_hash, block_path) < 0) { t->status = -2; goto done; }

    uint8_t *buf = NULL;
    size_t n = 0;
    if (read_entire_file(block_path, &buf, &n) < 0) {
        t->status = -2;
        goto done;
    }

    uint64_t h = fnv1a64(buf, n);
    char hex[17];
    to_hex64(h, hex);
    char got_hash[32];
    snprintf(got_hash, sizeof(got_hash), "fnv64-%s", hex);

    if (strcmp(got_hash, t->expected_hash) != 0) {
        free(buf);
        t->status = -3;
        goto done;
    }

    // size check is advisory (manifest is authoritative). we keep what we read
    (void)t->expected_size;

    t->data = buf;
    t->size = n;

done:
    inflight_release(t->limiter);
    pthread_mutex_lock(&t->mu);
    t->done = 1;
    pthread_cond_broadcast(&t->cv);
    pthread_mutex_unlock(&t->mu);
}

static int json_escape_append(char **buf, size_t *cap, const char *s) {
    size_t used = strlen(*buf);
    size_t need = used + 2;

    for (const unsigned char *p=(const unsigned char*)s; *p; p++) {
        if (*p < 0x20) need += 6;
        else if (*p=='"' || *p=='\\') need += 2;
        else need += 1;
    }
    need += 1;

    if (*cap < need) {
        size_t newcap = (*cap ? *cap : 256);
        while (newcap < need) newcap *= 2;
        char *nb = (char*)realloc(*buf, newcap);
        if (!nb) return -1;
        *buf = nb;
        *cap = newcap;
    }

    char *w = *buf;
    used = strlen(w);
    w[used++] = '"';
    for (const unsigned char *p=(const unsigned char*)s; *p; p++) {
        switch (*p) {
            case '"':  w[used++]='\\'; w[used++]='"'; break;
            case '\\': w[used++]='\\'; w[used++]='\\'; break;
            case '\b': w[used++]='\\'; w[used++]='b'; break;
            case '\f': w[used++]='\\'; w[used++]='f'; break;
            case '\n': w[used++]='\\'; w[used++]='n'; break;
            case '\r': w[used++]='\\'; w[used++]='r'; break;
            case '\t': w[used++]='\\'; w[used++]='t'; break;
            default:
                if (*p < 0x20) {
                    int n = snprintf(w+used, *cap-used, "\\u%04x", (unsigned)*p);
                    used += (size_t)n;
                } else {
                    w[used++] = (char)*p;
                }
        }
    }
    w[used++] = '"';
    w[used] = '\0';
    return 0;
}

static char* build_manifest_json(const char *hash_algo, size_t chunk_size, size_t total_size, const char *filename, const ChunkMeta *chunks, size_t nchunks) {
    size_t cap = 4096 + nchunks * 128;
    char *buf = (char*)calloc(1, cap);
    if (!buf) return NULL;
    snprintf(buf, cap, "{\"version\":1,\"hash_algo\":\"%s\",\"chunk_size\":%zu,\"total_size\":%zu,\"filename\":", hash_algo, chunk_size, total_size);
    if (json_escape_append(&buf, &cap, filename) < 0) { 
        free(buf); 
        return NULL; 
    }

    size_t used = strlen(buf);
    const char *prefix = ",\"chunks\":[";
    size_t pfx_len = strlen(prefix);
    if (used + pfx_len + 2 >= cap) {
        char *nb = (char*)realloc(buf, cap + pfx_len + 64);
        if (!nb) { free(buf); return NULL; }
        buf = nb; cap += pfx_len + 64;
    }
    memcpy(buf + used, prefix, pfx_len);
    used += pfx_len;
    buf[used] = '\0';

    for (size_t i=0;i<nchunks;i++) {
        char item[256];
        int n = snprintf(item, sizeof(item), "%s{\"index\":%d,\"size\":%zu,\"hash\":\"%s\"}", (i==0 ? "" : ","), chunks[i].index, chunks[i].size, chunks[i].hash);
        if (n <= 0) { 
            free(buf); 
            return NULL; 
        }
        size_t need = used + (size_t)n + 3;
        if (need >= cap) {
            size_t newcap = cap;
            while (newcap < need) newcap *= 2;
            char *nb = (char*)realloc(buf, newcap);
            if (!nb) { free(buf); return NULL; }
            buf = nb; cap = newcap;
        }
        memcpy(buf + used, item, (size_t)n);
        used += (size_t)n;
        buf[used] = '\0';
    }
    if (used + 3 >= cap) {
        char *nb = (char*)realloc(buf, cap + 16);
        if (!nb) { free(buf); return NULL; }
        buf = nb; cap += 16;
    }
    buf[used++] = ']';
    buf[used++] = '}';
    buf[used] = '\0';
    return buf;
}

static int parse_manifest_chunks(const char *json, ChunkMeta **out_chunks, size_t *out_n) {
    *out_chunks = NULL;
    *out_n = 0;

    const char *p = strstr(json, "\"chunks\"");
    if (!p) return -1;
    p = strchr(p, '[');
    if (!p) return -1;
    p++;

    size_t cnt = 0;
    for (const char *q = p; *q; q++) {
        if (*q == '{') cnt++;
        else if (*q == ']') break;
    }
    if (cnt == 0) return 0;

    ChunkMeta *arr = (ChunkMeta*)calloc(cnt, sizeof(ChunkMeta));
    if (!arr) return -1;

    size_t idx = 0;
    while (*p && *p != ']') {
        while (*p && *p != '{' && *p != ']') p++;
        if (*p == ']') break;
        const char *obj = p;
        const char *end = strchr(obj, '}');
        if (!end) { free(arr); return -1; }

        const char *pi = strstr(obj, "\"index\"");
        const char *ps = strstr(obj, "\"size\"");
        const char *ph = strstr(obj, "\"hash\"");
        if (!pi || !ps || !ph || pi > end || ps > end || ph > end) { free(arr); return -1; }

        pi = strchr(pi, ':'); ps = strchr(ps, ':'); ph = strchr(ph, ':');
        if (!pi || !ps || !ph) { free(arr); return -1; }
        pi++; ps++; ph++;

        arr[idx].index = (int)strtol(pi, NULL, 10);
        arr[idx].size  = (size_t)strtoull(ps, NULL, 10);

        while (*ph && *ph != '"') ph++;
        if (*ph != '"') { free(arr); return -1; }
        ph++;
        const char *hend = strchr(ph, '"');
        if (!hend || hend > end) { free(arr); return -1; }
        size_t hlen = (size_t)(hend - ph);
        if (hlen >= sizeof(arr[idx].hash)) hlen = sizeof(arr[idx].hash)-1;
        memcpy(arr[idx].hash, ph, hlen);
        arr[idx].hash[hlen] = '\0';

        idx++;
        p = end + 1;
    }

    *out_chunks = arr;
    *out_n = idx;
    return 0;
}

// Error helper--------------------------------------------------------------------------------------------------------------
static void send_error_and_done(int fd, const char *code, const char *message, uint8_t done_op) {
    char payload[512];
    snprintf(payload, sizeof(payload), "{\"code\":\"%s\",\"message\":\"%s\"}", code, message);
    (void)send_frame(fd, OP_ERROR, (const uint8_t*)payload, (uint32_t)strlen(payload));
    (void)send_frame(fd, done_op, NULL, 0);
}

// Upload handler-------------------------------------------------------------------------------------------------------------
static int handle_upload(int fd, const char *filename) {
    printf("[ENGINE] UPLOAD_START filename=\"%s\" (pid=%d)\n", filename, (int)getpid());
    fflush(stdout);

    InflightLimiter limiter;
    inflight_init(&limiter);

    size_t cap = 16, n = 0;
    UploadTask **tasks = (UploadTask**)calloc(cap, sizeof(UploadTask*));
    if (!tasks) { inflight_destroy(&limiter); return -1; }

    for (;;) {
        uint8_t op = 0;
        uint8_t *payload = NULL;
        uint32_t len = 0;
        int rc = recv_frame(fd, &op, &payload, &len);
        if (rc == 1) { free(payload); break; }
        if (rc < 0) { free(payload); goto fail; }

        if (op == OP_UPLOAD_CHUNK) {
            inflight_acquire(&limiter);

            UploadTask *t = (UploadTask*)calloc(1, sizeof(UploadTask));
            if (!t) { free(payload); inflight_release(&limiter); goto fail; }
            t->index = (int)n;
            t->size = (size_t)len;
            t->data = payload; // take ownership
            t->limiter = &limiter;
            pthread_mutex_init(&t->mu, NULL);
            pthread_cond_init(&t->cv, NULL);

            if (n >= cap) {
                cap *= 2;
                UploadTask **nt = (UploadTask**)realloc(tasks, cap * sizeof(UploadTask*));
                if (!nt) { goto fail; }
                tasks = nt;
            }
            tasks[n++] = t;
            pool_submit(upload_task_fn, t);
        } else if (op == OP_UPLOAD_FINISH) {
            free(payload);
            break;
        } else {
            free(payload);
            send_error_and_done(fd, "E_PROTO", "Unexpected opcode during upload", OP_UPLOAD_DONE);
            goto fail;
        }
    }

    ChunkMeta *chunks = (ChunkMeta*)calloc(n ? n : 1, sizeof(ChunkMeta));
    if (!chunks) goto fail;

    size_t total = 0;
    for (size_t i=0;i<n;i++) {
        UploadTask *t = tasks[i];
        pthread_mutex_lock(&t->mu);
        while (!t->done) pthread_cond_wait(&t->cv, &t->mu);
        pthread_mutex_unlock(&t->mu);
        if (t->status < 0) { free(chunks); send_error_and_done(fd, "E_BUSY", "Failed storing block", OP_UPLOAD_DONE); goto fail; }

        chunks[i].index = (int)i;
        chunks[i].size  = t->size;
        snprintf(chunks[i].hash, sizeof(chunks[i].hash), "%s", t->hash);
        total += t->size;
    }

    const char *algo_env = getenv("ALGO_HASH");
    const char *hash_algo = "fnv1a64";
    if (algo_env && algo_env[0]) {
        if (strcmp(algo_env, "fnv1a64") == 0 || strcmp(algo_env, "fnv64") == 0) {
            hash_algo = "fnv1a64";
        } else {
            fprintf(stderr,
                    "[ENGINE] warning: ALGO_HASH=%s not supported, using fnv1a64\n",
                    algo_env);
        }
    }
    size_t chunk_size = DEFAULT_CHUNK_SIZE;

    char *manifest = build_manifest_json(hash_algo, chunk_size, total, filename, chunks, n);
    free(chunks);
    if (!manifest) goto fail;

    uint64_t mh = fnv1a64((const uint8_t*)manifest, strlen(manifest));
    char hex[17]; to_hex64(mh, hex);
    char cid[64];
    snprintf(cid, sizeof(cid), "mfnv64-%s", hex);

    char manifests_dir[PATH_MAX];
    if (build_manifests_dir(manifests_dir) < 0) { free(manifest); goto fail; }
    if (mkdir_p(manifests_dir, 0755) < 0) { free(manifest); goto fail; }

    char manifest_path[PATH_MAX];
    if (build_manifest_path(cid, manifest_path) < 0) { free(manifest); goto fail; }

    pthread_rwlock_wrlock(&g_manifest_rw);
    int wrc = atomic_write_file(manifest_path, (const uint8_t*)manifest, strlen(manifest));
    pthread_rwlock_unlock(&g_manifest_rw);
    free(manifest);

    if (wrc < 0) { send_error_and_done(fd, "E_BUSY", "Failed writing manifest", OP_UPLOAD_DONE); goto fail; }

    if (send_frame(fd, OP_UPLOAD_DONE, (const uint8_t*)cid, (uint32_t)strlen(cid)) < 0) goto fail;

    for (size_t i=0;i<n;i++) {
        UploadTask *t = tasks[i];
        pthread_mutex_destroy(&t->mu);
        pthread_cond_destroy(&t->cv);
        free(t);
    }
    free(tasks);
    inflight_destroy(&limiter);
    return 0;

fail:
    if (tasks) {
        for (size_t i=0;i<n;i++) {
            UploadTask *t = tasks[i];
            if (!t) continue;
            pthread_mutex_lock(&t->mu);
            while (!t->done) pthread_cond_wait(&t->cv, &t->mu);
            pthread_mutex_unlock(&t->mu);
            pthread_mutex_destroy(&t->mu);
            pthread_cond_destroy(&t->cv);
            free(t);
        }
        free(tasks);
    }
    inflight_destroy(&limiter);
    return -1;
}

// Download handler---------------------------------------------------------------------------------------
static int handle_download(int fd, const char *cid) {
    printf("[ENGINE] DOWNLOAD_START cid=\"%s\" (pid=%d)\n", cid, (int)getpid());
    fflush(stdout);

    char manifest_path[PATH_MAX];
    if (build_manifest_path(cid, manifest_path) < 0) {
        send_error_and_done(fd, "E_PROTO", "Path too long", OP_DOWNLOAD_DONE);
        return -1;
    }

    pthread_rwlock_rdlock(&g_manifest_rw);
    uint8_t *mdata = NULL;
    size_t mlen = 0;
    int rrc = read_entire_file(manifest_path, &mdata, &mlen);
    pthread_rwlock_unlock(&g_manifest_rw);

    if (rrc < 0) {
        send_error_and_done(fd, "E_NOT_FOUND", "Manifest not found", OP_DOWNLOAD_DONE);
        return -1;
    }

    char *mjson = (char*)malloc(mlen + 1);
    if (!mjson) { free(mdata); send_error_and_done(fd, "E_BUSY", "OOM", OP_DOWNLOAD_DONE); return -1; }
    memcpy(mjson, mdata, mlen);
    mjson[mlen] = '\0';
    free(mdata);

    ChunkMeta *chunks = NULL;
    size_t nchunks = 0;
    if (parse_manifest_chunks(mjson, &chunks, &nchunks) < 0) {
        free(mjson);
        send_error_and_done(fd, "E_PROTO", "Bad manifest format", OP_DOWNLOAD_DONE);
        return -1;
    }
    free(mjson);

    InflightLimiter limiter;
    inflight_init(&limiter);

    DownloadTask **tasks = (DownloadTask**)calloc(nchunks ? nchunks : 1, sizeof(DownloadTask*));
    if (!tasks) {
        free(chunks);
        inflight_destroy(&limiter);
        send_error_and_done(fd, "E_BUSY", "OOM", OP_DOWNLOAD_DONE);
        return -1;
    }

    size_t scheduled = 0;
    // prime the pipeline
    while (scheduled < nchunks && scheduled < (size_t)MAX_INFLIGHT) {
        inflight_acquire(&limiter);
        DownloadTask *t = (DownloadTask*)calloc(1, sizeof(DownloadTask));
        if (!t) { inflight_release(&limiter); break; }
        t->index = chunks[scheduled].index;
        t->expected_size = chunks[scheduled].size;
        snprintf(t->expected_hash, sizeof(t->expected_hash), "%s", chunks[scheduled].hash);
        t->limiter = &limiter;
        pthread_mutex_init(&t->mu, NULL);
        pthread_cond_init(&t->cv, NULL);
        tasks[scheduled] = t;
        pool_submit(download_task_fn, t);
        scheduled++;
    }

    for (size_t i=0; i<nchunks; i++) {
        // keep pipeline full
        if (scheduled < nchunks) {
            inflight_acquire(&limiter);
            DownloadTask *t = (DownloadTask*)calloc(1, sizeof(DownloadTask));
            if (!t) { inflight_release(&limiter); send_error_and_done(fd, "E_BUSY", "OOM", OP_DOWNLOAD_DONE); goto fail; }
            t->index = chunks[scheduled].index;
            t->expected_size = chunks[scheduled].size;
            snprintf(t->expected_hash, sizeof(t->expected_hash), "%s", chunks[scheduled].hash);
            t->limiter = &limiter;
            pthread_mutex_init(&t->mu, NULL);
            pthread_cond_init(&t->cv, NULL);
            tasks[scheduled] = t;
            pool_submit(download_task_fn, t);
            scheduled++;
        }

        DownloadTask *t = tasks[i];
        if (!t) { send_error_and_done(fd, "E_BUSY", "Scheduling failure", OP_DOWNLOAD_DONE); goto fail; }

        pthread_mutex_lock(&t->mu);
        while (!t->done) pthread_cond_wait(&t->cv, &t->mu);
        pthread_mutex_unlock(&t->mu);

        if (t->status < 0) {
            if (t->status == -2) send_error_and_done(fd, "E_NOT_FOUND", "Block not found", OP_DOWNLOAD_DONE);
            else if (t->status == -3) send_error_and_done(fd, "E_HASH_MISMATCH", "Chunk hash mismatch", OP_DOWNLOAD_DONE);
            else send_error_and_done(fd, "E_BUSY", "Chunk read failed", OP_DOWNLOAD_DONE);
            goto fail;
        }

        if (send_frame(fd, OP_DOWNLOAD_CHUNK, t->data, (uint32_t)t->size) < 0) goto fail;

        free(t->data);
        t->data = NULL;
        pthread_mutex_destroy(&t->mu);
        pthread_cond_destroy(&t->cv);
        free(t);
        tasks[i] = NULL;
    }

    (void)send_frame(fd, OP_DOWNLOAD_DONE, NULL, 0);

    free(tasks);
    free(chunks);
    inflight_destroy(&limiter);
    return 0;

fail:
    for (size_t i=0;i<nchunks;i++) {
        DownloadTask *t = tasks[i];
        if (!t) continue;
        pthread_mutex_lock(&t->mu);
        while (!t->done) pthread_cond_wait(&t->cv, &t->mu);
        pthread_mutex_unlock(&t->mu);
        free(t->data);
        pthread_mutex_destroy(&t->mu);
        pthread_cond_destroy(&t->cv);
        free(t);
    }
    free(tasks);
    free(chunks);
    inflight_destroy(&limiter);
    return -1;
}

// Connection handler--------------------------------------------------------------------------------
static void* handle_connection(void *arg) {
    int cfd = (int)(intptr_t)arg;

    uint8_t op = 0;
    uint8_t *payload = NULL;
    uint32_t len = 0;
    int rc = recv_frame(cfd, &op, &payload, &len);
    if (rc != 0) { close(cfd); free(payload); return NULL; }

    if (op == OP_UPLOAD_START) {
        char *fname = (char*)malloc((size_t)len + 1);
        if (!fname) { send_error_and_done(cfd, "E_BUSY", "OOM", OP_UPLOAD_DONE); close(cfd); free(payload); return NULL; }
        memcpy(fname, payload, len);
        fname[len] = '\0';
        free(payload);

        (void)handle_upload(cfd, fname);
        free(fname);
    } else if (op == OP_DOWNLOAD_START) {
        char *cid = (char*)malloc((size_t)len + 1);
        if (!cid) { send_error_and_done(cfd, "E_BUSY", "OOM", OP_DOWNLOAD_DONE); close(cfd); free(payload); return NULL; }
        memcpy(cid, payload, len);
        cid[len] = '\0';
        free(payload);

        (void)handle_download(cfd, cid);
        free(cid);
    } else {
        free(payload);
        send_error_and_done(cfd, "E_PROTO", "Unknown opcode", OP_UPLOAD_DONE);
    }

    close(cfd);
    return NULL;
}

// Signal handling--------------------------------------------------------------------------------------------
static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

// Main-------------------------------------------------------------------------------------------------------
int main(int argc, char **argv) {
    if (argc >= 2) { if (safe_copy(g_sock_path, sizeof(g_sock_path), argv[1]) < 0) { fprintf(stderr, "Socket path too long\n"); return 1; } }

    const char *store_env = getenv("STORE_DIR");
    if (store_env && store_env[0]) { if (safe_copy(g_store_dir, sizeof(g_store_dir), store_env) < 0) { fprintf(stderr, "STORE_DIR too long\n"); return 1; } }

    int workers = DEFAULT_WORKERS;
    const char *wenv = getenv("WORKERS");
    if (wenv && wenv[0]) {
        int w = atoi(wenv);
        if (w > 0 && w < 256) workers = w;
    }

    // ensure store dirs exist
    char blocks_dir[PATH_MAX];
    char manifests_dir[PATH_MAX];
    if (build_blocks_dir(blocks_dir) < 0) { fprintf(stderr, "STORE_DIR too long\n"); return 1; }
    if (build_manifests_dir(manifests_dir) < 0) { fprintf(stderr, "STORE_DIR too long\n"); return 1; }
    if (mkdir_p(blocks_dir, 0755) < 0 || mkdir_p(manifests_dir, 0755) < 0) {
        perror("mkdir_p(store)");
        return 1;
    }

    if (pool_init(workers) < 0) {
        fprintf(stderr, "Failed to init thread pool\n");
        return 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); pool_stop(); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(g_sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "Socket path too long for AF_UNIX\n");
        close(sfd);
        pool_stop();
        return 1;
    }
    strcpy(addr.sun_path, g_sock_path);

    unlink(g_sock_path);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(sfd); pool_stop(); return 1; }
    if (listen(sfd, 64) < 0) { perror("listen"); close(sfd); unlink(g_sock_path); pool_stop(); return 1; }

    printf("[ENGINE] listening on unix://%s (workers=%d, store=%s)\n", g_sock_path, workers, g_store_dir);
    fflush(stdout);

    while (!g_stop) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        pthread_t th;
        if (pthread_create(&th, NULL, handle_connection, (void*)(intptr_t)cfd) == 0) pthread_detach(th);
        else close(cfd);
    }

    close(sfd);
    unlink(g_sock_path);
    pool_stop();
    printf("[ENGINE] shutdown\n");
    return 0;
}