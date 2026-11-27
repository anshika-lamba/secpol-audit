/*
 * kprobe.c — On-Target QNX Neutrino 8.0 Syscall Prober for `secpol-audit blast`
 *
 * Independently exercises QNX 8.0 kernel enforcement under a caller's bound
 * security type (`on -T <origin>`) for three operations:
 *   - settypeid       : secpol_posix_spawnattr_settypeid() + posix_spawn("--noop")
 *   - channel_connect : name_open(target, 0) + name_close()
 *   - allow_attach    : name_attach(NULL, target, 0) + name_detach()
 *
 * Emits one machine-parseable JSONL line per probe:
 *   KPROBE_JSON:{"origin":"...","op":"settypeid"|"channel_connect"|"allow_attach",
 *                "target":"...","outcome":"ALLOW"|"DENY","errno":0}
 *
 * Build (QNX SDP 8.0):
 *   qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -o build/kprobe kprobe.c -lsecpol
 */

#include <errno.h>
#include <secpol/secpol.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define KPROBE_BIN_PATH "/proc/boot/kprobe"

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

static void emit_kprobe_json(
    const char *origin,
    const char *op,
    const char *target,
    int allowed,
    int err_num
) {
    char origin_esc[128];
    char op_esc[64];
    char target_esc[256];
    json_escape(origin ? origin : "unknown", origin_esc, sizeof(origin_esc));
    json_escape(op ? op : "unknown", op_esc, sizeof(op_esc));
    json_escape(target ? target : "", target_esc, sizeof(target_esc));

    printf(
        "KPROBE_JSON:{\"origin\":\"%s\",\"op\":\"%s\",\"target\":\"%s\","
        "\"outcome\":\"%s\",\"errno\":%d}\n",
        origin_esc,
        op_esc,
        target_esc,
        allowed ? "ALLOW" : "DENY",
        allowed ? 0 : err_num
    );
    fflush(stdout);
}

static void probe_settypeid(const char *origin, const char *target_type) {
    posix_spawnattr_t attr;
    if (posix_spawnattr_init(&attr) != 0) {
        emit_kprobe_json(origin, "settypeid", target_type, 0, errno);
        return;
    }

    errno = 0;
    if (secpol_posix_spawnattr_settypeid(NULL, &attr, target_type, SECPOL_TYPE_NAME) != 0) {
        int saved = errno ? errno : EINVAL;
        posix_spawnattr_destroy(&attr);
        emit_kprobe_json(origin, "settypeid", target_type, 0, saved);
        return;
    }

    char *spawn_argv[] = { (char *)"kprobe", (char *)"--noop", NULL };
    pid_t child_pid = -1;
    int rc = posix_spawn(&child_pid, KPROBE_BIN_PATH, NULL, &attr, spawn_argv, environ);
    posix_spawnattr_destroy(&attr);

    if (rc == 0) {
        int status = 0;
        (void)waitpid(child_pid, &status, 0);
        emit_kprobe_json(origin, "settypeid", target_type, 1, 0);
    } else {
        emit_kprobe_json(origin, "settypeid", target_type, 0, rc);
    }
}

static void probe_channel_connect(const char *origin, const char *name) {
    errno = 0;
    int coid = name_open(name, 0);
    if (coid >= 0) {
        (void)name_close(coid);
        emit_kprobe_json(origin, "channel_connect", name, 1, 0);
    } else {
        int saved = errno ? errno : EPERM;
        emit_kprobe_json(origin, "channel_connect", name, 0, saved);
    }
}

static void probe_allow_attach(const char *origin, const char *name) {
    errno = 0;
    name_attach_t *att = name_attach(NULL, name, 0);
    if (att != NULL) {
        (void)name_detach(att, 0);
        emit_kprobe_json(origin, "allow_attach", name, 1, 0);
    } else {
        int saved = errno ? errno : EPERM;
        emit_kprobe_json(origin, "allow_attach", name, 0, saved);
    }
}

static void run_csv_probes(
    const char *origin,
    const char *csv,
    void (*fn)(const char *, const char *)
) {
    if (csv == NULL || csv[0] == '\0') {
        return;
    }
    char *copy = strdup(csv);
    if (copy == NULL) {
        return;
    }
    char *saveptr = NULL;
    char *tok = strtok_r(copy, ",", &saveptr);
    while (tok != NULL) {
        if (tok[0] != '\0') {
            fn(origin, tok);
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
}

int main(int argc, char *argv[]) {
    const char *origin = "unknown";
    const char *settypeid_csv = NULL;
    const char *connect_csv = NULL;
    const char *attach_csv = NULL;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--noop") == 0) {
            return EXIT_SUCCESS;
        } else if (strcmp(argv[i], "--origin") == 0 && i + 1 < argc) {
            origin = argv[++i];
        } else if (strcmp(argv[i], "--settypeid") == 0 && i + 1 < argc) {
            settypeid_csv = argv[++i];
        } else if (strcmp(argv[i], "--connect") == 0 && i + 1 < argc) {
            connect_csv = argv[++i];
        } else if (strcmp(argv[i], "--attach") == 0 && i + 1 < argc) {
            attach_csv = argv[++i];
        } else {
            fprintf(
                stderr,
                "Usage: %s [--noop] | --origin <type> "
                "[--settypeid t1,t2] [--connect n1,n2] [--attach n1,n2]\n",
                argv[0]
            );
            return 2;
        }
    }

    run_csv_probes(origin, settypeid_csv, probe_settypeid);
    run_csv_probes(origin, connect_csv, probe_channel_connect);
    run_csv_probes(origin, attach_csv, probe_allow_attach);
    return EXIT_SUCCESS;
}
