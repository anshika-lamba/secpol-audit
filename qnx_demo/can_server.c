/*
 * can_server.c — QNX Neutrino 8.0 Safety-Critical CAN HAL Server
 *
 * Launched via `on -T can_hal_t /proc/boot/can_server`.
 * Registers the local namespace channel `can_ctrl` via `name_attach(NULL, "can_ctrl", 0)`,
 * which attaches at `/dev/name/local/can_ctrl` (matching `allow_attach can_hal_t /dev/name/local/can_ctrl;`
 * plus `pathspace` and `public_channel` abilities in the .secpol policy).
 * Replies "CAN_CTRL_GRANTED" to any client permitted by the QNX 8.0 security policy.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <unistd.h>

#define CAN_ATTACH_NAME "can_ctrl"
#define CAN_REPLY_MSG   "CAN_CTRL_GRANTED"

typedef struct {
    struct _pulse hdr;
    char payload[64];
} can_msg_t;

int main(void) {
    name_attach_t *attach = name_attach(NULL, CAN_ATTACH_NAME, 0);
    if (attach == NULL) {
        fprintf(stderr, "CAN_SERVER_INIT=FAILED errno=%d (%s)\n", errno, strerror(errno));
        fflush(stderr);
        fflush(stdout); sleep(8); return EXIT_FAILURE;
    }

    printf("CAN_SERVER_READY pid=%d path=/dev/name/local/%s\n", (int)getpid(), CAN_ATTACH_NAME);
    fflush(stdout);

    for (;;) {
        can_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        int rcvid = MsgReceive(attach->chid, &msg, sizeof(msg), NULL);
        if (rcvid == -1) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "CAN_SERVER_RECV=ERROR errno=%d (%s)\n", errno, strerror(errno));
            fflush(stderr);
            break;
        }

        if (rcvid == 0) {
            /* Kernel pulse (e.g., _PULSE_CODE_DISCONNECT) */
            if (msg.hdr.code == _PULSE_CODE_DISCONNECT) {
                ConnectDetach(msg.hdr.scoid);
            }
            continue;
        }

        /* Standard QNX message: reply granting CAN control acknowledgement */
        if (MsgReply(rcvid, EOK, CAN_REPLY_MSG, strlen(CAN_REPLY_MSG) + 1) == -1) {
            fprintf(stderr, "CAN_SERVER_REPLY=ERROR errno=%d (%s)\n", errno, strerror(errno));
            fflush(stderr);
        }
    }

    name_detach(attach, 0);
    return EXIT_SUCCESS;
}
