/*
 * dump_file.c — Minimal QNX 8.0 file/resmgr streamer (no cat/toybox dependency)
 *
 * Streams all bytes from argv[1] via read() until EOF (0), required for dynamic
 * QNX resource managers like /dev/secpolgenerate/{policy,unused,errors} that
 * generate content on demand with no fixed st_size.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path>\n", argv[0]);
        return 2;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "dump_file: open(%s) failed: errno=%d (%s)\n",
                argv[1], errno, strerror(errno));
        return 1;
    }

    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) {
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "dump_file: read(%s) failed: errno=%d (%s)\n",
                    argv[1], errno, strerror(errno));
            close(fd);
            return 1;
        }
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(STDOUT_FILENO, buf + off, (size_t)(n - off));
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return 1;
            }
            off += w;
        }
    }

    close(fd);
    return 0;
}
