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
 *   on -T secpol_sentry_t -u 25:25 /proc/boot/secpol_sentry [-t <seconds>]
 */

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <secpol/secpol.h>
#include <secpol/secpolev.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/neutrino.h>
#include <time.h>
#include <unistd.h>

#define SENTRY_DEV_PATH     "/dev/secpol_sentry"
#define SENTRY_CLASS_NAME   "sentry"
#define SENTRY_PERM_READ    "read_events"

#define RING_CAPACITY       64
#define EVENT_BUF_SIZE      1024
#define MAX_CHAIN_LEN       16
#define MAX_TYPE_NAME       64
#define MAX_TRACKED_TYPES   32
#define PULSE_CODE_SHUTDOWN (_PULSE_CODE_MINAVAIL + 1)

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
    char ring[RING_CAPACITY][EVENT_BUF_SIZE];

    type_stat_t type_stats[MAX_TRACKED_TYPES];
    size_t num_type_stats;

    /* Stateful multi-hop detector state */
    char hop_chain[MAX_CHAIN_LEN][MAX_TYPE_NAME];
    size_t hop_chain_len;
    size_t settypeid_hops;
    bool alert_emitted_for_len[MAX_CHAIN_LEN + 1];
} sentry_state_t;

static sentry_state_t g_state;
static volatile sig_atomic_t g_stop = 0;
static bool g_secpolev_initialized = false;
static bool g_secpolev_shutdown_done = false;
static pthread_mutex_t g_shutdown_lock = PTHREAD_MUTEX_INITIALIZER;
static secpol_perm_t g_read_perm = (secpol_perm_t)0;
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
        secpolev_shutdown(true);
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

static bool is_privileged_ability_name(const char *ability) {
    if (ability == NULL) {
        return false;
    }
    return strcmp(ability, "mem_phys") == 0 ||
           strcmp(ability, "io") == 0 ||
           strcmp(ability, "prot_exec") == 0 ||
           strcmp(ability, "mac_policy") == 0 ||
           strcmp(ability, "setuid") == 0 ||
           strcmp(ability, "channel_connect") == 0 ||
           strcmp(ability, "gain_priv") == 0;
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

static bool type_in_chain_locked(const char *type_name) {
    for (size_t i = 0; i < g_state.hop_chain_len; ++i) {
        if (strcmp(g_state.hop_chain[i], type_name) == 0) {
            return true;
        }
    }
    return false;
}

static void emit_multihop_alert_locked(uint64_t ts_ns) {
    if (g_state.hop_chain_len < 2 || g_state.hop_chain_len > MAX_CHAIN_LEN) {
        return;
    }
    if (g_state.alert_emitted_for_len[g_state.hop_chain_len]) {
        return;
    }
    g_state.alert_emitted_for_len[g_state.hop_chain_len] = true;
    g_state.total_alerts++;

    char alert_buf[EVENT_BUF_SIZE];
    size_t pos = 0;
    int n = snprintf(alert_buf, sizeof(alert_buf),
                     "SECPOLEV_ALERT:{\"kind\":\"multi_hop_chain\",\"chain\":[");
    if (n > 0) {
        pos = (size_t)n;
    }
    for (size_t i = 0; i < g_state.hop_chain_len && pos + 8 < sizeof(alert_buf); ++i) {
        char esc[MAX_TYPE_NAME * 2];
        json_escape(g_state.hop_chain[i], esc, sizeof(esc));
        n = snprintf(alert_buf + pos, sizeof(alert_buf) - pos,
                     "%s\"%s\"", (i > 0) ? "," : "", esc);
        if (n > 0) {
            pos += (size_t)n;
        }
    }
    (void)snprintf(alert_buf + pos, sizeof(alert_buf) - pos,
                   "],\"ts_ns\":%" PRIu64 "}", ts_ns);
    fprintf(stdout, "%s\n", alert_buf);
    fflush(stdout);
}

static void record_event_and_detect_chain(
    const char *json_obj,
    uint64_t ts_ns,
    bool denied,
    const char *type_name,
    const char *kind,
    const char *ability_name
) {
    bool is_settypeid = (strcmp(kind, "ability") == 0 &&
                         ability_name != NULL &&
                         strcmp(ability_name, "settypeid") == 0);
    bool is_priv_action = (strcmp(kind, "ability") == 0 &&
                           is_privileged_ability_name(ability_name));

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

    /* Stateful multi-hop detector:
     * Track sequential successful `settypeid` transitions across distinct types,
     * and correlate subsequent privileged ability/channel events in the same session.
     */
    if (!denied && type_name != NULL && type_name[0] != '\0') {
        if (is_settypeid) {
            if (!type_in_chain_locked(type_name) && g_state.hop_chain_len < MAX_CHAIN_LEN) {
                snprintf(g_state.hop_chain[g_state.hop_chain_len],
                         sizeof(g_state.hop_chain[0]), "%s", type_name);
                g_state.hop_chain_len++;
                g_state.settypeid_hops++;
                if (g_state.settypeid_hops >= 2) {
                    emit_multihop_alert_locked(ts_ns);
                }
            }
        } else if (is_priv_action && g_state.settypeid_hops >= 1) {
            if (!type_in_chain_locked(type_name) && g_state.hop_chain_len < MAX_CHAIN_LEN) {
                snprintf(g_state.hop_chain[g_state.hop_chain_len],
                         sizeof(g_state.hop_chain[0]), "%s", type_name);
                g_state.hop_chain_len++;
                if (g_state.hop_chain_len >= 2) {
                    emit_multihop_alert_locked(ts_ns);
                }
            }
        }
    }

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
    g_secpolev_initialized = true;
    pthread_mutex_unlock(&g_shutdown_lock);

    fprintf(stdout, "SECPOLEV_READY pid=%d\n", (int)getpid());
    fflush(stdout);

    while (!g_stop) {
        unsigned flags = 0;
        int ev = secpolev_wait_event(&flags);
        if (ev < 0) {
            if (errno == EINTR && !g_stop) {
                continue;
            }
            break;
        }
        if (ev == SECPOLEV_EVENT_NONE) {
            continue;
        }

        bool denied = (flags & SECPOL_EVENT_FLAG_DENIED) != 0;
        const char *verdict = denied ? "DENIED" : "OK";
        const char *proc_raw = secpolev_get_process_name();
        const char *type_raw = secpolev_get_process_type();
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
                int rc = secpolev_get_ability_info(&ability_raw, &is_root, &range_start, &range_end);
                if (rc > 0 || (rc == 0 && (range_start != 0 || (range_end != 0 && range_end != UINT64_MAX)))) {
                    has_range = true;
                }
                break;
            }
            case SECPOLEV_EVENT_PATH_ATTACH: {
                kind = "attach";
                (void)secpolev_get_path_info(&path_raw, &status_raw);
                break;
            }
            case SECPOLEV_EVENT_PATH_LINK: {
                kind = "link";
                (void)secpolev_get_path_info(&path_raw, &status_raw);
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

        record_event_and_detect_chain(json_obj, ts_ns, denied, type_raw, kind, ability_raw);
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

static size_t build_sentry_summary_json(char *buf, size_t buf_size) {
    size_t pos = 0;
    pthread_mutex_lock(&g_state.lock);

    unsigned long long dropped = (unsigned long long)secpolev_get_dropped_count();
    int n = snprintf(
        buf + pos, buf_size - pos,
        "{\"ok\":%" PRIu64 ",\"denied\":%" PRIu64 ",\"alerts\":%" PRIu64
        ",\"dropped\":%llu,\"recent_events\":[",
        g_state.total_ok,
        g_state.total_denied,
        g_state.total_alerts,
        dropped
    );
    if (n > 0) {
        pos += (size_t)n;
    }

    size_t count = (g_state.ring_written < RING_CAPACITY)
                       ? (size_t)g_state.ring_written
                       : RING_CAPACITY;
    size_t max_emit = count < 8 ? count : 8;
    size_t start_idx = (g_state.ring_written > max_emit)
                           ? (size_t)((g_state.ring_written - max_emit) % RING_CAPACITY)
                           : 0;

    for (size_t i = 0; i < max_emit && pos + 8 < buf_size; ++i) {
        size_t idx = (start_idx + i) % RING_CAPACITY;
        size_t ev_len = strlen(g_state.ring[idx]);
        if (pos + ev_len + 16 >= buf_size) {
            break;
        }
        n = snprintf(buf + pos, buf_size - pos, "%s%s", (i > 0) ? "," : "", g_state.ring[idx]);
        if (n > 0) {
            pos += (size_t)n;
        }
    }

    if (pos + 4 < buf_size) {
        n = snprintf(buf + pos, buf_size - pos, "]}\n");
        if (n > 0) {
            pos += (size_t)n;
        }
    }

    pthread_mutex_unlock(&g_state.lock);
    return pos;
}

static int sentry_io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb) {
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
    if (g_read_perm == (secpol_perm_t)0 ||
        !secpol_check_permission(&ctp->info, secpol_type_id(), g_read_perm)) {
        return EACCES;
    }

    char payload[8192];
    size_t total_len = build_sentry_summary_json(payload, sizeof(payload));

    if (ocb->offset >= (off_t)total_len) {
        _IO_SET_READ_NBYTES(ctp, 0);
        return _RESMGR_NPARTS(0);
    }

    size_t remaining = total_len - (size_t)ocb->offset;
    size_t nbytes = (msg->i.nbytes < remaining) ? (size_t)msg->i.nbytes : remaining;

    if (MsgReply(ctp->rcvid, (int)nbytes, payload + ocb->offset, nbytes) == -1) {
        return errno;
    }
    ocb->offset += (off_t)nbytes;
    return _RESMGR_NOREPLY;
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "t:")) != -1) {
        switch (opt) {
            case 't':
                g_timeout_sec = atoi(optarg);
                if (g_timeout_sec < 0) {
                    g_timeout_sec = 0;
                }
                break;
            default:
                fprintf(stderr, "Usage: %s [-t <seconds>]\n", argv[0]);
                return EXIT_FAILURE;
        }
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
    if (g_read_perm == (secpol_perm_t)0) {
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

    pulse_attach(dpp, 0, PULSE_CODE_SHUTDOWN, pulse_shutdown_handler, NULL);
    g_self_coid = message_connect(dpp, MSG_FLAG_SIDE_CHANNEL);

    printf("SENTRY_READY pid=%d path=%s\n", (int)getpid(), SENTRY_DEV_PATH);
    fflush(stdout);

    pthread_t collector_tid;
    bool collector_started = (pthread_create(&collector_tid, NULL, secpolev_collector_thread, NULL) == 0);
    if (!collector_started) {
        fprintf(stderr, "SENTRY_THREAD=FAILED errno=%d\n", errno);
        fflush(stderr);
    }

    pthread_t timer_tid;
    bool timer_started = false;
    if (g_timeout_sec > 0) {
        timer_started = (pthread_create(&timer_tid, NULL, timeout_watchdog_thread, &g_timeout_sec) == 0);
    }

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    if (ctp != NULL) {
        while (!g_stop) {
            if (dispatch_block(ctp) == NULL) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            dispatch_handler(ctp);
        }
        dispatch_context_free(ctp);
    }

    /* Ensure collector exits cleanly and print final statistics */
    request_secpolev_shutdown();
    if (collector_started) {
        pthread_join(collector_tid, NULL);
    }
    if (timer_started) {
        pthread_join(timer_tid, NULL);
    }

    unsigned long long dropped = (unsigned long long)secpolev_get_dropped_count();
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
