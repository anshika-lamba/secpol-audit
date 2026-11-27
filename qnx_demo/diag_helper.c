
#include <errno.h>
#include <secpol/secpol.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--probe") == 0) {
        printf("HOP2_PROBE_START pid=%d\n", (int)getpid());
        fflush(stdout);
        int coid = name_open("can_ctrl", 0);
        if (coid == -1) {
            printf("HOP2_RESULT=DENIED errno=%d (%s)\n", errno, strerror(errno));
            return 1;
        }
        printf("HOP2_RESULT=GRANTED coid=%d\n", coid);
        name_close(coid);
        return 0;
    }

    pid_t parent_pid = getpid();
    const char *origin_type = "diag_helper_t";
    const char *target_type = "can_hal_t";

    printf("DIAG_HELPER_START pid=%d\n", (int)parent_pid);
    fflush(stdout);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if (secpol_posix_spawnattr_settypeid(NULL, &attr, target_type, SECPOL_TYPE_NAME) == -1) {
        int err = errno;
        printf("HOP2_SPAWN=DENIED errno=%d (%s)\n", err, strerror(err));
        printf("LINEAGE_HOP2:{\"parent_pid\":%d,\"child_pid\":-1,\"origin_type\":\"%s\",\"requested_target_type\":\"%s\",\"outcome\":\"DENIED\",\"errno\":%d}\n",
               (int)parent_pid, origin_type, target_type, err);
        fflush(stdout);
        posix_spawnattr_destroy(&attr);
        return 1;
    }

    char *child_argv[] = { "/proc/boot/diag_helper", "--probe", NULL };
    pid_t child = -1;
    int rc = posix_spawn(&child, "/proc/boot/diag_helper", NULL, &attr, child_argv, environ);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        printf("HOP2_SPAWN=DENIED errno=%d (%s)\n", rc, strerror(rc));
        printf("LINEAGE_HOP2:{\"parent_pid\":%d,\"child_pid\":-1,\"origin_type\":\"%s\",\"requested_target_type\":\"%s\",\"outcome\":\"DENIED\",\"errno\":%d}\n",
               (int)parent_pid, origin_type, target_type, rc);
        fflush(stdout);
        return 1;
    }
    printf("HOP2_SPAWN=OK child_pid=%d\n", (int)child);
    printf("LINEAGE_HOP2:{\"parent_pid\":%d,\"child_pid\":%d,\"origin_type\":\"%s\",\"requested_target_type\":\"%s\",\"outcome\":\"OK\",\"errno\":0}\n",
           (int)parent_pid, (int)child, origin_type, target_type);
    fflush(stdout);
    int status = 0;
    waitpid(child, &status, 0);
    return 0;
}
