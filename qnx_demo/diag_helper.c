
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

    printf("DIAG_HELPER_START pid=%d\n", (int)getpid());
    fflush(stdout);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if (secpol_posix_spawnattr_settypeid(NULL, &attr, "can_hal_t", SECPOL_TYPE_NAME) == -1) {
        printf("HOP2_SPAWN=DENIED errno=%d (%s)\n", errno, strerror(errno));
        posix_spawnattr_destroy(&attr);
        return 1;
    }

    char *child_argv[] = { "/proc/boot/diag_helper", "--probe", NULL };
    pid_t child = 0;
    int rc = posix_spawn(&child, "/proc/boot/diag_helper", NULL, &attr, child_argv, environ);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        printf("HOP2_SPAWN=DENIED errno=%d (%s)\n", rc, strerror(rc));
        return 1;
    }
    printf("HOP2_SPAWN=OK child_pid=%d\n", (int)child);
    fflush(stdout);
    int status = 0;
    waitpid(child, &status, 0);
    return 0;
}
