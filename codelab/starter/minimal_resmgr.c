/*
 * minimal_resmgr.c — Minimal QNX Neutrino 8.0 Resource Manager for Codelab
 *
 * Demonstrates policy-aware attachment via `secpol_resmgr_attach()`.
 * Build (QNX SDP 8.0):
 *   qcc -Vgcc_ntox86_64 -Wall -Wextra -Werror -O2 -o minimal_resmgr minimal_resmgr.c -lsecpol
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __QNXNTO__
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <secpol/secpol.h>
#endif

int main(int argc, char *argv[]) {
    const char *dev_path = (argc > 1) ? argv[1] : "/dev/codelab_resmgr";

#ifdef __QNXNTO__
    dispatch_t *dpp = dispatch_create();
    if (dpp == NULL) {
        fprintf(stderr, "dispatch_create failed: errno=%d (%s)\n", errno, strerror(errno));
        return EXIT_FAILURE;
    }

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max = 1;
    rattr.msg_max_size = 2048;

    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t io_funcs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);

    iofunc_attr_t io_attr;
    iofunc_attr_init(&io_attr, S_IFCHR | 0666, NULL, NULL);

    errno = 0;
    int id = secpol_resmgr_attach(
        NULL, dpp, &rattr, dev_path, _FTYPE_ANY, 0,
        &connect_funcs, &io_funcs, &io_attr, NULL
    );
    if (id == -1) {
        int err = errno;
        printf("ATTACH=DENIED path=%s pid=%d errno=%d (%s)\n",
               dev_path, (int)getpid(), err, strerror(err));
        dispatch_destroy(dpp);
        return EXIT_FAILURE;
    }

    printf("ATTACH=ALLOW path=%s pid=%d id=%d\n", dev_path, (int)getpid(), id);
    resmgr_detach(dpp, id, 0);
    dispatch_destroy(dpp);
    return EXIT_SUCCESS;
#else
    printf("Host syntax-check build only (path=%s, pid=%d)\n", dev_path, (int)getpid());
    return EXIT_SUCCESS;
#endif
}
