/*
 * kprobe.c — On-Target QNX Neutrino 8.0 Syscall Prober for `secpol-audit blast`
 *
 * Independently exercises QNX 8.0 kernel enforcement under a caller's bound
 * security type (`on -T <origin>`) for three operations:
 *   - settypeid       : secpol_posix_spawnattr_settypeid() + posix_spawn("--noop")
 *   - channel_connect : name_open(target, 0) + name_close()
 *   - allow_attach    : dispatch_create() + secpol_resmgr_attach() + resmgr_detach()
 *                       against an isolated, previously unused pathname per test
 *
 * Emits one machine-parseable JSONL line per probe:
 *   KPROBE_JSON:{"origin":"...","op":"settypeid"|"channel_connect"|"allow_attach",
 *                "target":"...","path":"...","target_id":...,"pid":...,"ret":0,
 *                "outcome":"ALLOW"|"DENY","errno":0,"errno_name":"OK"}
 *
 * Build (QNX SDP 8.0):
 *   qcc -Vgcc_ntox86_64 -Wall -Wextra -Werror -O2 -o build/kprobe kprobe.c -lsecpol
 */

#include <errno.h>
#ifndef KPROBE_HOST_TEST
/* Include <sys/iofunc.h> before <sys/dispatch.h> and <secpol/secpol.h> so QNX sets RESMGR_OCB_T/RESMGR_HANDLE_T */
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <secpol/secpol.h>
#include <spawn.h>
#include <sys/wait.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

/*
 * Strictly parse `<channel_name>=<server_type>` for `--connect`.
 * Rejects NULL, missing '=', empty channel name, empty server_type, or
 * inputs that would truncate either destination buffer.
 * Returns 0 on success, -1 on malformed input.
 */
static int parse_channel_connect_spec(
    const char *name_spec,
    char *name_buf,
    size_t name_buf_size,
    char *type_buf,
    size_t type_buf_size
) {
    if (name_spec == NULL || name_buf == NULL || type_buf == NULL ||
        name_buf_size < 2 || type_buf_size < 2) {
        return -1;
    }
    const char *eq = strchr(name_spec, '=');
    if (eq == NULL) {
        return -1;
    }
    size_t nlen = (size_t)(eq - name_spec);
    const char *server_type = eq + 1;
    size_t tlen = strlen(server_type);
    if (nlen == 0 || tlen == 0 || nlen >= name_buf_size || tlen >= type_buf_size) {
        return -1;
    }
    memcpy(name_buf, name_spec, nlen);
    name_buf[nlen] = '\0';
    memcpy(type_buf, server_type, tlen);
    type_buf[tlen] = '\0';
    return 0;
}

#ifndef KPROBE_HOST_TEST

extern char **environ;

static const char *errno_to_name(int err_num) {
    switch (err_num) {
        case 0:      return "OK";
        case EPERM:  return "EPERM";
        case ENOENT: return "ENOENT";
        case EACCES: return "EACCES";
        case EEXIST: return "EEXIST";
        case EINVAL: return "EINVAL";
        case ENOMEM: return "ENOMEM";
        case EBUSY:  return "EBUSY";
        default:     return "ERRNO";
    }
}

static void emit_kprobe_json(
    const char *origin,
    const char *op,
    const char *target,
    const char *path,
    uint32_t target_id,
    int ret,
    int allowed,
    int err_num
) {
    char origin_esc[128];
    char op_esc[64];
    char target_esc[256];
    char path_esc[256];
    char err_name_esc[32];
    char target_id_json[32];
    int effective_errno = allowed ? 0 : err_num;

    json_escape(origin ? origin : "unknown", origin_esc, sizeof(origin_esc));
    json_escape(op ? op : "unknown", op_esc, sizeof(op_esc));
    json_escape(target ? target : "", target_esc, sizeof(target_esc));
    json_escape(path ? path : "", path_esc, sizeof(path_esc));
    json_escape(errno_to_name(effective_errno), err_name_esc, sizeof(err_name_esc));
    if (target_id != SECPOL_INVALID_TYPE) {
        snprintf(target_id_json, sizeof(target_id_json), "%u", (unsigned int)target_id);
    } else {
        snprintf(target_id_json, sizeof(target_id_json), "null");
    }

    printf(
        "KPROBE_JSON:{\"origin\":\"%s\",\"op\":\"%s\",\"target\":\"%s\","
        "\"path\":\"%s\",\"target_id\":%s,\"pid\":%d,\"ret\":%d,\"outcome\":\"%s\",\"errno\":%d,\"errno_name\":\"%s\"}\n",
        origin_esc,
        op_esc,
        target_esc,
        path_esc,
        target_id_json,
        (int)getpid(),
        ret,
        allowed ? "ALLOW" : "DENY",
        effective_errno,
        err_name_esc
    );
    fflush(stdout);
}

static int probe_settypeid(const char *origin, const char *target_type) {
    uint32_t target_id = secpol_get_type_id(NULL, target_type);

    posix_spawnattr_t attr;
    if (posix_spawnattr_init(&attr) != 0) {
        int saved = errno ? errno : EINVAL;
        emit_kprobe_json(origin, "settypeid", target_type, "", target_id, -1, 0, saved);
        return 0;
    }

    errno = 0;
    if (secpol_posix_spawnattr_settypeid(NULL, &attr, target_type, SECPOL_TYPE_NAME) != 0) {
        int saved = errno ? errno : EINVAL;
        posix_spawnattr_destroy(&attr);
        emit_kprobe_json(origin, "settypeid", target_type, "", target_id, -1, 0, saved);
        return 0;
    }

    char *spawn_argv[] = { (char *)"kprobe", (char *)"--noop", NULL };
    pid_t child_pid = -1;
    int rc = posix_spawn(&child_pid, KPROBE_BIN_PATH, NULL, &attr, spawn_argv, environ);
    posix_spawnattr_destroy(&attr);

    if (rc == 0) {
        int status = 0;
        (void)waitpid(child_pid, &status, 0);
        emit_kprobe_json(origin, "settypeid", target_type, "", target_id, 0, 1, 0);
    } else {
        emit_kprobe_json(origin, "settypeid", target_type, "", target_id, -1, 0, rc);
    }
    return 0;
}

static int probe_channel_connect(const char *origin, const char *name_spec) {
    char name_buf[256];
    char type_buf[128];

    if (parse_channel_connect_spec(
            name_spec,
            name_buf,
            sizeof(name_buf),
            type_buf,
            sizeof(type_buf)) != 0) {
        fprintf(
            stderr,
            "kprobe: malformed --connect spec '%s' (expected '<channel>=<server_type>')\n",
            name_spec ? name_spec : "(null)"
        );
        fflush(stderr);
        return -1;
    }

    uint32_t target_id = secpol_get_type_id(NULL, type_buf);

    errno = 0;
    int coid = name_open(name_buf, 0);
    if (coid >= 0) {
        (void)name_close(coid);
        emit_kprobe_json(origin, "channel_connect", name_buf, "", target_id, coid, 1, 0);
    } else {
        int saved = errno ? errno : EPERM;
        emit_kprobe_json(origin, "channel_connect", name_buf, "", target_id, -1, 0, saved);
    }
    return 0;
}

static int probe_allow_attach(const char *origin, const char *path) {
    errno = 0;
    dispatch_t *dpp = dispatch_create();
    if (dpp == NULL) {
        int saved = errno ? errno : ENOMEM;
        emit_kprobe_json(origin, "allow_attach", path, path, SECPOL_INVALID_TYPE, -1, 0, saved);
        return 0;
    }

    resmgr_attr_t resmgr_attr;
    memset(&resmgr_attr, 0, sizeof(resmgr_attr));
    resmgr_attr.nparts_max = 1;
    resmgr_attr.msg_max_size = 2048;

    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t io_funcs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);

    iofunc_attr_t io_attr;
    iofunc_attr_init(&io_attr, S_IFCHR | 0666, NULL, NULL);

    errno = 0;
    int resmgr_id = secpol_resmgr_attach(
        NULL,
        dpp,
        &resmgr_attr,
        path,
        _FTYPE_ANY,
        0,
        &connect_funcs,
        &io_funcs,
        &io_attr,
        NULL
    );
    if (resmgr_id >= 0) {
        (void)resmgr_detach(dpp, resmgr_id, 0);
        dispatch_destroy(dpp);
        emit_kprobe_json(origin, "allow_attach", path, path, SECPOL_INVALID_TYPE, resmgr_id, 1, 0);
    } else {
        int saved = errno ? errno : EPERM;
        dispatch_destroy(dpp);
        emit_kprobe_json(origin, "allow_attach", path, path, SECPOL_INVALID_TYPE, -1, 0, saved);
    }
    return 0;
}

static int run_csv_probes(
    const char *origin,
    const char *csv,
    int (*fn)(const char *, const char *)
) {
    if (csv == NULL || csv[0] == '\0') {
        return 0;
    }
    char *copy = strdup(csv);
    if (copy == NULL) {
        return -1;
    }
    int status = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(copy, ",", &saveptr);
    while (tok != NULL) {
        if (tok[0] != '\0') {
            if (fn(origin, tok) != 0) {
                status = -1;
            }
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    return status;
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
                "[--settypeid t1,t2] [--connect n1=t1,n2=t2] [--attach p1,p2]\n",
                argv[0]
            );
            return 2;
        }
    }

    int rc = 0;
    if (run_csv_probes(origin, settypeid_csv, probe_settypeid) != 0) rc = 1;
    if (run_csv_probes(origin, connect_csv, probe_channel_connect) != 0) rc = 1;
    if (run_csv_probes(origin, attach_csv, probe_allow_attach) != 0) rc = 1;
    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#endif /* KPROBE_HOST_TEST */
