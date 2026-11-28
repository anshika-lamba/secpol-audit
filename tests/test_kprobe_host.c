/*
 * Host-compiled unit tests for pure-C helpers in qnx_demo/kprobe.c.
 * Compile:
 *   gcc -Wall -Wextra -Werror -DKPROBE_HOST_TEST -I qnx_demo -o /tmp/test_kprobe_host tests/test_kprobe_host.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "kprobe.c"

int main(void) {
    char name_buf[256];
    char type_buf[128];

    /* Valid spec */
    assert(parse_channel_connect_spec("can_ctrl=can_hal_t", name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == 0);
    assert(strcmp(name_buf, "can_ctrl") == 0);
    assert(strcmp(type_buf, "can_hal_t") == 0);

    /* Malformed specs must fail closed */
    assert(parse_channel_connect_spec(NULL, name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);
    assert(parse_channel_connect_spec("", name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);
    assert(parse_channel_connect_spec("can_ctrl", name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);
    assert(parse_channel_connect_spec("=can_hal_t", name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);
    assert(parse_channel_connect_spec("can_ctrl=", name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);
    assert(parse_channel_connect_spec("=", name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);
    assert(parse_channel_connect_spec("can_ctrl=can_hal_t=extra", name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);
    assert(parse_channel_connect_spec(" can_ctrl=can_hal_t", name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);
    assert(parse_channel_connect_spec("can_ctrl=can_hal_t ", name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);

    /* Oversized channel name or server type must be rejected, not silently truncated */
    char big_spec[400];
    memset(big_spec, 'a', 300);
    memcpy(big_spec + 300, "=can_hal_t", 11);
    assert(parse_channel_connect_spec(big_spec, name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);

    char big_type[250];
    memcpy(big_type, "can_ctrl=", 9);
    memset(big_type + 9, 'b', 200);
    big_type[209] = '\0';
    assert(parse_channel_connect_spec(big_type, name_buf, sizeof(name_buf), type_buf, sizeof(type_buf)) == -1);

    /* JSON escaper */
    char esc[64];
    json_escape("a\"b\\c\nd\re", esc, sizeof(esc));
    assert(strcmp(esc, "a\\\"b\\\\c\\nd\\re") == 0);

    printf("test_kprobe_host: ALL PASSED\n");
    return 0;
}
