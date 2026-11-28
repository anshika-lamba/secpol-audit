/*
 * secpol_sentry.c — Native QNX Neutrino 8.0 libsecpolev Telemetry Resource Manager
 *
 * Combines two QNX-specific security technologies in a single daemon:
 *   1. Live microkernel security event ingestion via <secpol/secpolev.h> (-lsecpolev)
 *      emitting machine-parseable `SECPOLEV_JSON:` lines, stateful multi-hop
 *      `SECPOLEV_ALERT:` detections, and final `SECPOLEV_STATS:` counters.
 *   2. Native QNX Resource Manager at `/dev/secpol_sentry` attached via
 *      `secpol_resmgr_attach()` with custom permission enforcement
 *      (`class sentry { read_events };`) via `secpol_get_permission()` and
 *      `secpol_check_permission()` (-lsecpol).
 *
 * Build (QNX SDP 8.0):
 *   qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -o build/secpol_sentry secpol_sentry.c -lsecpolev -lsecpol
 *
 * Usage:
 *   Daemon mode: on -T secpol_sentry_t -u 25:25 /proc/boot/secpol_sentry [-t <seconds>]
 *   Probe mode:  on -T audit_reader_t  -u 26:26 /proc/boot/secpol_sentry -r SENTRY_READ_AUTH
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Include <sys/iofunc.h> before <sys/dispatch.h> and <secpol/secpol.h> so QNX sets RESMGR_OCB_T/RESMGR_HANDLE_T */
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <secpol/secpol.h>
#include <secpol/secpolev.h>
#include <time.h>
#include <unistd.h>

#define SENTRY_DEV_PATH     "/dev/secpol_sentry"
#define SENTRY_CLASS_NAME   "sentry"
#define SENTRY_PERM_READ    "read_events"

#define RING_CAPACITY       64
#define EVENT_BUF_SIZE      2048
#define SENTRY_SNAP_MAX     8192
#define MAX_CHAIN_LEN       16
#define MAX_TYPE_NAME       64
#define MAX_TRACKED_TYPES   32
#define PULSE_CODE_SHUTDOWN (_PULSE_CODE_MINAVAIL + 1)

typedef struct sentry_ocb {
    iofunc_ocb_t hdr;
    uint64_t     client_id;
    char        *snapshot;
    size_t       snap_len;
} sentry_ocb_t;

typedef struct {
    char type_name[MAX_TYPE_NAME];
    uint64_t ok_count;
    uint64_t denied_count;
    uint64_t settypeid_ok;
} type_stat_t;

typedef struct {
    pthread_mutex_t lock;
    uint64_t total_ok;
    uint64_t total_denied;
    uint64_t total_alerts;
    uint64_t ring_written;
    uint64_t next_client_id;
    char ring[RING_CAPACITY][EVENT_BUF_SIZE];

    type_stat_t type_stats[MAX_TRACKED_TYPES];
    size_t num_type_stats;
} sentry_state_t;

static sentry_state_t g_state;
static volatile sig_atomic_t g_stop = 0;
static bool g_secpolev_initialized = false;
static bool g_secpolev_shutdown_done = false;
static bool g_sentry_runtime_error = false;
static bool g_collector_tid_valid = false;
static pthread_t g_collector_tid;
static pthread_mutex_t g_shutdown_lock = PTHREAD_MUTEX_INITIALIZER;
static secpol_permission_t *g_read_perm = NULL;
static int g_self_coid = -1;
static int g_timeout_sec = 0;

/* Safe JSON string escaper into caller buffer */
static void json_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    if (dst_size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    for (size_t i = 0; src[i] != '\0' && j + 2 < dst_size; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (j + 3 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c == '\n') {
            if (j + 3 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = 'n';
        } else if (c == '\r') {
            if (j + 3 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = 'r';
        } else if (c == '\t') {
            if (j + 3 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = 't';
        } else if (c < 0x20) {
            if (j + 7 >= dst_size) break;
            int n = snprintf(dst + j, dst_size - j, "\\u%04x", (unsigned)c);
            if (n > 0) {
                j += (size_t)n;
            }
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

static const char *path_status_to_str(secpolev_path_event_status_t status) {
    switch (status) {
        case SECPOLEV_PATH_EVENT_OK:
            return "ok";
        case SECPOLEV_PATH_EVENT_CONFLICT:
            return "conflict";
        case SECPOLEV_PATH_EVENT_BAD_OP:
            return "bad_op";
        case SECPOLEV_PATH_EVENT_NO_RULE:
            return "no_rule";
        default:
            return "unknown";
    }
}

static uint64_t monotonic_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
    return 0;
}

static void request_secpolev_shutdown(void) {
    pthread_mutex_lock(&g_shutdown_lock);
    if (g_secpolev_initialized && !g_secpolev_shutdown_done) {
        g_secpolev_shutdown_done = true;
        secpolev_shutdown_type_t mode =
            (g_collector_tid_valid && pthread_equal(pthread_self(), g_collector_tid))
                ? SECPOLEV_SHUTDOWN_IMMEDIATE
                : SECPOLEV_SHUTDOWN_NOWAIT;
        if (secpolev_shutdown(mode) != 0) {
            g_sentry_runtime_error = true;
            fprintf(stderr, "SECPOLEV_SHUTDOWN=FAILED errno=%d (%s)\n", errno, strerror(errno));
            fflush(stderr);
        }
    }
    pthread_mutex_unlock(&g_shutdown_lock);
}

static void trigger_shutdown(void) {
    g_stop = 1;
    request_secpolev_shutdown();
    if (g_self_coid != -1) {
        (void)MsgSendPulse(g_self_coid, -1, PULSE_CODE_SHUTDOWN, 0);
    }
}

static void handle_signal(int signo) {
    (void)signo;
    g_stop = 1;
}

static void update_type_stats_locked(const char *type_name, bool denied, bool is_settypeid) {
    if (type_name == NULL || type_name[0] == '\0') {
        return;
    }
    for (size_t i = 0; i < g_state.num_type_stats; ++i) {
        if (strcmp(g_state.type_stats[i].type_name, type_name) == 0) {
            if (denied) {
                g_state.type_stats[i].denied_count++;
            } else {
                g_state.type_stats[i].ok_count++;
                if (is_settypeid) {
                    g_state.type_stats[i].settypeid_ok++;
                }
            }
            return;
        }
    }
    if (g_state.num_type_stats < MAX_TRACKED_TYPES) {
        type_stat_t *st = &g_state.type_stats[g_state.num_type_stats++];
        snprintf(st->type_name, sizeof(st->type_name), "%s", type_name);
        st->ok_count = denied ? 0 : 1;
        st->denied_count = denied ? 1 : 0;
        st->settypeid_ok = (!denied && is_settypeid) ? 1 : 0;
    }
}

static void record_event(
    const char *json_obj,
    bool denied,
    const char *type_name,
    const char *kind,
    const char *ability_name
) {
    bool is_settypeid = (strcmp(kind, "ability") == 0 &&
                         ability_name != NULL &&
                         strcmp(ability_name, "settypeid") == 0);

    pthread_mutex_lock(&g_state.lock);

    if (denied) {
        g_state.total_denied++;
    } else {
        g_state.total_ok++;
    }
    update_type_stats_locked(type_name, denied, is_settypeid);

    size_t slot = (size_t)(g_state.ring_written % RING_CAPACITY);
    snprintf(g_state.ring[slot], sizeof(g_state.ring[slot]), "%s", json_obj);
    g_state.ring_written++;

    pthread_mutex_unlock(&g_state.lock);
}

static void *secpolev_collector_thread(void *arg) {
    (void)arg;

    if (secpolev_init(0, 4, 200) != 0) {
        fprintf(stderr, "SECPOLEV_INIT=FAILED errno=%d (%s)\n", errno, strerror(errno));
        fflush(stderr);
        return NULL;
    }

    pthread_mutex_lock(&g_shutdown_lock);
    g_collector_tid = pthread_self();
    g_collector_tid_valid = true;
    g_secpolev_initialized = true;
    pthread_mutex_unlock(&g_shutdown_lock);

    fprintf(stdout, "SECPOLEV_READY pid=%d\n", (int)getpid());
    fflush(stdout);

    while (!g_stop) {
        unsigned flags = 0;
        int ev = secpolev_wait_event(&flags);
        if (ev < 0 || ev == SECPOLEV_EVENT_END) {
            break;
        }
        if (ev == SECPOLEV_EVENT_ERROR) {
            if (errno == EINTR && !g_stop) {
                continue;
            }
            break;
        }

        bool denied = (flags & SECPOL_EVENT_FLAG_DENIED) != 0u;
        const char *verdict = denied ? "DENIED" : "OK";
        const char *proc_raw = secpolev_get_process_name();
        const char *type_raw = secpolev_get_process_type();
        int ev_pid = (int)secpolev_get_pid();
        uint64_t cycles = secpolev_get_timestamp();
        uint64_t ts_ns = 0;
        if (clock_cycles_to_time_ns(cycles, CLOCK_MONOTONIC, &ts_ns) != 0) {
            ts_ns = monotonic_now_ns();
        }

        const char *kind = "unknown";
        const char *ability_raw = NULL;
        bool is_root = false;
        bool has_range = false;
        uint64_t range_start = 0;
        uint64_t range_end = 0;
        const char *path_raw = NULL;
        const char *status_raw = NULL;
        const char *class_raw = NULL;
        const char *perm_raw = NULL;
        const char *obj_type_raw = NULL;

        switch (ev) {
            case SECPOLEV_EVENT_ABILITY_TEST: {
                kind = "ability";
                unsigned ability_id = 0;
                unsigned able_flags = 0;
                if (secpolev_get_ability_info(
                        &ability_id,
                        &ability_raw,
                        &able_flags,
                        &range_start,
                        &range_end) >= 0) {
                    is_root = (able_flags & SECPOLEV_ABILITY_ROOT) != 0u;
                    has_range = (able_flags & SECPOLEV_ABILITY_RANGED) != 0u;
                }
                (void)ability_id;
                break;
            }
            case SECPOLEV_EVENT_PATH_ATTACH: {
                kind = "attach";
                secpolev_path_event_status_t path_status = SECPOLEV_PATH_EVENT_OK;
                if (secpolev_get_path_info(&path_raw, &path_status) >= 0) {
                    status_raw = path_status_to_str(path_status);
                }
                break;
            }
            case SECPOLEV_EVENT_PATH_LINK: {
                kind = "link";
                secpolev_path_event_status_t path_status = SECPOLEV_PATH_EVENT_OK;
                if (secpolev_get_path_info(&path_raw, &path_status) >= 0) {
                    status_raw = path_status_to_str(path_status);
                }
                break;
            }
            case SECPOLEV_EVENT_CUSTOM_PERM: {
                kind = "custom";
                (void)secpolev_get_custom_perm_info(&class_raw, &perm_raw, &obj_type_raw);
                break;
            }
            default:
                continue;
        }

        char proc_esc[192], type_esc[128], abil_esc[128];
        char path_esc[256], status_esc[96];
        char cls_esc[96], perm_esc[96], obj_esc[128];
        char range_json[64];

        json_escape(proc_raw ? proc_raw : "", proc_esc, sizeof(proc_esc));
        json_escape(type_raw ? type_raw : "", type_esc, sizeof(type_esc));
        json_escape(ability_raw ? ability_raw : "", abil_esc, sizeof(abil_esc));
        json_escape(path_raw ? path_raw : "", path_esc, sizeof(path_esc));
        json_escape(status_raw ? status_raw : "", status_esc, sizeof(status_esc));
        json_escape(class_raw ? class_raw : "", cls_esc, sizeof(cls_esc));
        json_escape(perm_raw ? perm_raw : "", perm_esc, sizeof(perm_esc));
        json_escape(obj_type_raw ? obj_type_raw : "", obj_esc, sizeof(obj_esc));

        if (has_range) {
            snprintf(range_json, sizeof(range_json),
                     "[%" PRIu64 ",%" PRIu64 "]", range_start, range_end);
        } else {
            snprintf(range_json, sizeof(range_json), "null");
        }

        char json_obj[EVENT_BUF_SIZE];
        snprintf(
            json_obj,
            sizeof(json_obj),
            "{\"ts_ns\":%" PRIu64
            ",\"pid\":%d"
            ",\"verdict\":\"%s\""
            ",\"proc\":\"%s\""
            ",\"type\":\"%s\""
            ",\"kind\":\"%s\""
            ",\"ability\":\"%s\""
            ",\"root\":%s"
            ",\"range\":%s"
            ",\"path\":\"%s\""
            ",\"status\":\"%s\""
            ",\"class\":\"%s\""
            ",\"perm\":\"%s\""
            ",\"obj_type\":\"%s\"}",
            ts_ns,
            ev_pid,
            verdict,
            proc_esc,
            type_esc,
            kind,
            abil_esc,
            is_root ? "true" : "false",
            range_json,
            path_esc,
            status_esc,
            cls_esc,
            perm_esc,
            obj_esc
        );

        fprintf(stdout, "SECPOLEV_JSON:%s\n", json_obj);
        fflush(stdout);

        record_event(json_obj, denied, type_raw, kind, ability_raw);
    }

    request_secpolev_shutdown();
    return NULL;
}

static void *timeout_watchdog_thread(void *arg) {
    int seconds = *(int *)arg;
    for (int elapsed_ms = 0; elapsed_ms < seconds * 1000 && !g_stop; elapsed_ms += 100) {
        usleep(100000);
    }
    trigger_shutdown();
    return NULL;
}

static int pulse_shutdown_handler(message_context_t *ctp, int code, unsigned flags, void *handle) {
    (void)ctp;
    (void)code;
    (void)flags;
    (void)handle;
    g_stop = 1;
    return 0;
}

static size_t build_sentry_summary_json(char *buf, size_t buf_size, uint64_t client_id) {
    size_t pos = 0;
    pthread_mutex_lock(&g_state.lock);

    unsigned long long dropped = g_secpolev_initialized
                                     ? (unsigned long long)secpolev_get_dropped_count()
                                     : 0ULL;
    int n = snprintf(
        buf + pos, buf_size - pos,
        "{\"client_id\":%" PRIu64 ",\"ok\":%" PRIu64 ",\"denied\":%" PRIu64
        ",\"alerts\":%" PRIu64 ",\"dropped\":%llu,\"recent_events\":[",
        client_id,
        g_state.total_ok,
        g_state.total_denied,
        g_state.total_alerts,
        dropped
    );
    if (n > 0 && (size_t)n < buf_size) {
        pos += (size_t)n;
    }

    size_t count = (g_state.ring_written < RING_CAPACITY)
                       ? (size_t)g_state.ring_written
                       : RING_CAPACITY;
    size_t max_emit = count < 8 ? count : 8;
    size_t start_idx = (g_state.ring_written > max_emit)
                           ? (size_t)((g_state.ring_written - max_emit) % RING_CAPACITY)
                           : 0;

    for (size_t i = 0; i < max_emit; ++i) {
        size_t idx = (start_idx + i) % RING_CAPACITY;
        size_t ev_len = strlen(g_state.ring[idx]);
        size_t need = (i > 0 ? 1U : 0U) + ev_len;
        if (pos + need + 16U >= buf_size) {
            break;
        }
        if (i > 0) {
            buf[pos++] = ',';
        }
        memcpy(buf + pos, g_state.ring[idx], ev_len);
        pos += ev_len;
        buf[pos] = '\0';
    }

    if (pos + 4 < buf_size) {
        n = snprintf(buf + pos, buf_size - pos, "]}\n");
        if (n > 0 && (size_t)n < buf_size - pos) {
            pos += (size_t)n;
        }
    }

    pthread_mutex_unlock(&g_state.lock);
    return pos;
}

/* Per-open OCB allocator: freezes an independent telemetry snapshot per client open()
 * so 2+ concurrent authorized clients stream with isolated offsets (solving QNX 8.0's
 * single-consumer libsecpolev restriction).
 */
static iofunc_ocb_t *sentry_ocb_calloc(resmgr_context_t *ctp, iofunc_attr_t *attr) {
    (void)ctp;
    (void)attr;
    sentry_ocb_t *socb = (sentry_ocb_t *)calloc(1, sizeof(sentry_ocb_t));
    if (socb == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&g_state.lock);
    socb->client_id = ++g_state.next_client_id;
    pthread_mutex_unlock(&g_state.lock);

    socb->snapshot = (char *)malloc(SENTRY_SNAP_MAX);
    if (socb->snapshot != NULL) {
        socb->snap_len = build_sentry_summary_json(
            socb->snapshot, SENTRY_SNAP_MAX, socb->client_id);
    }
    return &socb->hdr;
}

static void sentry_ocb_free(iofunc_ocb_t *ocb) {
    sentry_ocb_t *socb = (sentry_ocb_t *)ocb;
    if (socb != NULL) {
        free(socb->snapshot);
        socb->snapshot = NULL;
        free(socb);
    }
}

static iofunc_funcs_t g_ocb_funcs = {
    .nfuncs     = _IOFUNC_NFUNCS,
    .ocb_calloc = sentry_ocb_calloc,
    .ocb_free   = sentry_ocb_free
};

static iofunc_mount_t g_mount = {
    .funcs = &g_ocb_funcs
};

static int sentry_io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ctp_ocb) {
    iofunc_ocb_t *ocb = (iofunc_ocb_t *)ctp_ocb;
    sentry_ocb_t *socb = (sentry_ocb_t *)ocb;
    int status;
    int nonblock = 0;

    if ((status = iofunc_read_verify(ctp, msg, ocb, &nonblock)) != EOK) {
        return status;
    }
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) {
        return ENOSYS;
    }

    /* Populate caller credentials and enforce custom libsecpol class `sentry:read_events` */
    if (MsgInfo(ctp->rcvid, &ctp->info) == -1) {
        return EACCES;
    }
    if (g_read_perm == NULL ||
        secpol_check_permission(&ctp->info, secpol_type_id(), g_read_perm) != 0) {
        return EACCES;
    }

    if (socb->snapshot == NULL) {
        return ENOMEM;
    }

    if (ocb->offset >= (off_t)socb->snap_len) {
        _IO_SET_READ_NBYTES(ctp, 0);
        return _RESMGR_NPARTS(0);
    }

    size_t remaining = socb->snap_len - (size_t)ocb->offset;
    size_t req_bytes = (size_t)msg->i.nbytes;
    size_t nbytes = (req_bytes < remaining) ? req_bytes : remaining;

    if (MsgReply(ctp->rcvid, (int)nbytes, socb->snapshot + ocb->offset, nbytes) == -1) {
        return errno;
    }
    ocb->offset += (off_t)nbytes;
    return _RESMGR_NOREPLY;
}

/* Built-in probe mode (`-r <label>`) performing chunked reads over an independent OCB
 * so concurrent clients overlap in time and verify isolated per-client cursors.
 */
static int run_read_probe(const char *label) {
    int fd = open(SENTRY_DEV_PATH, O_RDONLY);
    if (fd == -1) {
        printf("%s=DENIED errno=%d\n", label, errno);
        fflush(stdout);
        return EXIT_SUCCESS;
    }
    char buf[512];
    ssize_t first = read(fd, buf, 64);
    if (first <= 0) {
        int saved_errno = errno;
        close(fd);
        printf("%s=DENIED errno=%d\n", label, saved_errno);
        fflush(stdout);
        return EXIT_SUCCESS;
    }
    /* Brief overlap window so concurrent clients hold live independent OCBs */
    usleep(50000);
    ssize_t total = first;
    while (total < (ssize_t)(sizeof(buf) - 1)) {
        ssize_t n = read(fd, buf + total, (size_t)((ssize_t)(sizeof(buf) - 1) - total));
        if (n <= 0) {
            break;
        }
        total += n;
    }
    close(fd);
    printf("%s=OK bytes=%zd\n", label, total);
    fflush(stdout);
    return g_sentry_runtime_error ? EXIT_FAILURE : EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    const char *probe_label = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "t:r:")) != -1) {
        switch (opt) {
            case 't':
                g_timeout_sec = atoi(optarg);
                if (g_timeout_sec < 0) {
                    g_timeout_sec = 0;
                }
                break;
            case 'r':
                probe_label = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-t <seconds>] [-r <probe_label>]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (probe_label != NULL) {
        return run_read_probe(probe_label);
    }

    memset(&g_state, 0, sizeof(g_state));
    pthread_mutex_init(&g_state.lock, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Resolve custom permission handle: `class sentry { read_events };` */
    g_read_perm = secpol_get_permission(NULL, SENTRY_CLASS_NAME, SENTRY_PERM_READ, 0);
    if (g_read_perm == NULL) {
        fprintf(stderr, "SENTRY_PERM_INIT=FAILED class=%s perm=%s errno=%d (%s)\n",
                SENTRY_CLASS_NAME, SENTRY_PERM_READ, errno, strerror(errno));
        fflush(stderr);
    }

    dispatch_t *dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);
    if (dpp == NULL) {
        fprintf(stderr, "SENTRY_DISPATCH=FAILED errno=%d (%s)\n", errno, strerror(errno));
        return EXIT_FAILURE;
    }

    resmgr_attr_t resmgr_attr;
    memset(&resmgr_attr, 0, sizeof(resmgr_attr));
    resmgr_attr.nparts_max = 1;
    resmgr_attr.msg_max_size = 2048;

    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t io_funcs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);
    io_funcs.read = sentry_io_read;

    iofunc_attr_t io_attr;
    iofunc_attr_init(&io_attr, S_IFCHR | 0444, NULL, NULL);
    io_attr.mount = &g_mount;

    int resmgr_id = secpol_resmgr_attach(
        NULL,
        dpp,
        &resmgr_attr,
        SENTRY_DEV_PATH,
        _FTYPE_ANY,
        0,
        &connect_funcs,
        &io_funcs,
        &io_attr,
        NULL
    );
    if (resmgr_id == -1) {
        fprintf(stderr, "SENTRY_ATTACH=FAILED path=%s errno=%d (%s)\n",
                SENTRY_DEV_PATH, errno, strerror(errno));
        fflush(stderr);
        dispatch_destroy(dpp);
        return EXIT_FAILURE;
    }

    if (pulse_attach(dpp, 0, PULSE_CODE_SHUTDOWN, pulse_shutdown_handler, NULL) == -1) {
        fprintf(stderr, "SENTRY_PULSE_ATTACH=FAILED errno=%d (%s)\n", errno, strerror(errno));
        fflush(stderr);
        (void)resmgr_detach(dpp, resmgr_id, 0);
        dispatch_destroy(dpp);
        return EXIT_FAILURE;
    }
    g_self_coid = message_connect(dpp, MSG_FLAG_SIDE_CHANNEL);
    if (g_self_coid == -1) {
        fprintf(stderr, "SENTRY_MSG_CONNECT=FAILED errno=%d (%s)\n", errno, strerror(errno));
        fflush(stderr);
        (void)resmgr_detach(dpp, resmgr_id, 0);
        dispatch_destroy(dpp);
        return EXIT_FAILURE;
    }

    pthread_t collector_tid;
    int collector_rc = pthread_create(&collector_tid, NULL, secpolev_collector_thread, NULL);
    if (collector_rc != 0) {
        fprintf(stderr, "SENTRY_THREAD=FAILED err=%d (%s)\n", collector_rc, strerror(collector_rc));
        fflush(stderr);
        (void)ConnectDetach(g_self_coid);
        (void)resmgr_detach(dpp, resmgr_id, 0);
        dispatch_destroy(dpp);
        return EXIT_FAILURE;
    }

    pthread_t timer_tid;
    bool timer_started = false;
    if (g_timeout_sec > 0) {
        int timer_rc = pthread_create(&timer_tid, NULL, timeout_watchdog_thread, &g_timeout_sec);
        if (timer_rc != 0) {
            fprintf(stderr, "SENTRY_WATCHDOG=FAILED err=%d (%s)\n", timer_rc, strerror(timer_rc));
            fflush(stderr);
            trigger_shutdown();
            (void)pthread_join(collector_tid, NULL);
            (void)ConnectDetach(g_self_coid);
            (void)resmgr_detach(dpp, resmgr_id, 0);
            dispatch_destroy(dpp);
            return EXIT_FAILURE;
        }
        timer_started = true;
    }

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    if (ctp == NULL) {
        fprintf(stderr, "SENTRY_DISPATCH_CTX=FAILED errno=%d (%s)\n", errno, strerror(errno));
        fflush(stderr);
        trigger_shutdown();
        (void)pthread_join(collector_tid, NULL);
        if (timer_started) {
            (void)pthread_join(timer_tid, NULL);
        }
        (void)ConnectDetach(g_self_coid);
        (void)resmgr_detach(dpp, resmgr_id, 0);
        dispatch_destroy(dpp);
        return EXIT_FAILURE;
    }

    printf("SENTRY_READY pid=%d path=%s\n", (int)getpid(), SENTRY_DEV_PATH);
    {
        uint32_t active_policy_id = 0;
        if (secpol_get_policy_id(&active_policy_id) == 0) {
            printf("SECPOLEV_POLICY_ID: %" PRIu32 "\n", active_policy_id);
        } else {
            printf("SECPOLEV_POLICY_ID: 0 errno=%d\n", errno);
        }
    }
    fflush(stdout);

    while (!g_stop) {
        if (dispatch_block(ctp) == NULL) {
            if (errno == EINTR) {
                continue;
            }
            g_sentry_runtime_error = true;
            fprintf(stderr, "SENTRY_DISPATCH_BLOCK=FAILED errno=%d (%s)\n", errno, strerror(errno));
            fflush(stderr);
            break;
        }
        dispatch_handler(ctp);
    }
    dispatch_context_free(ctp);

    /* Ensure collector exits cleanly and print final statistics */
    request_secpolev_shutdown();
    if (pthread_join(collector_tid, NULL) != 0) {
        g_sentry_runtime_error = true;
    }
    if (timer_started && pthread_join(timer_tid, NULL) != 0) {
        g_sentry_runtime_error = true;
    }

    unsigned long long dropped = g_secpolev_initialized
                                     ? (unsigned long long)secpolev_get_dropped_count()
                                     : 0ULL;
    pthread_mutex_lock(&g_state.lock);
    uint64_t final_ok = g_state.total_ok;
    uint64_t final_denied = g_state.total_denied;
    pthread_mutex_unlock(&g_state.lock);

    printf("SECPOLEV_STATS: ok=%" PRIu64 " denied=%" PRIu64 " dropped=%llu\n",
           final_ok, final_denied, dropped);
    fflush(stdout);

    if (g_self_coid != -1) {
        ConnectDetach(g_self_coid);
    }
    resmgr_detach(dpp, resmgr_id, 0);
    dispatch_destroy(dpp);
    pthread_mutex_destroy(&g_state.lock);
    return EXIT_SUCCESS;
}
