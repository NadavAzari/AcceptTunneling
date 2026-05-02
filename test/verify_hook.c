#include <stdio.h>
#include <stdint.h>
#include "hook/accept_log.h"

int main(void)
{
    size_t sz = hook_accept_size();
    printf("hook_accept        @ %p\n", (void *)hook_accept);
    printf("hook_accept_end    @ %p\n", (void *)hook_accept_end);
    printf("hook_accept_size() = %zu bytes\n", sz);

    if (sz == 0 || sz > 4096) {
        fprintf(stderr, "ERROR: suspicious size\n");
        return 1;
    }

    uint8_t *code = (uint8_t *)hook_accept;
    int found_accept = 0, found_msg = 0;

    for (size_t i = 0; i + 8 <= sz; i++) {
        uint64_t val;
        __builtin_memcpy(&val, code + i, 8);
        if (val == HOOK_REAL_ACCEPT_MAGIC) {
            found_accept = 1;
            printf("  REAL_ACCEPT placeholder @ offset %zu\n", i);
        }
        if (val == HOOK_MSG_ADDR_MAGIC) {
            found_msg = 1;
            printf("  MSG_ADDR    placeholder @ offset %zu\n", i);
        }
    }

    if (!found_accept) fprintf(stderr, "ERROR: REAL_ACCEPT magic not found\n");
    if (!found_msg)    fprintf(stderr, "ERROR: MSG_ADDR magic not found\n");

    return (!found_accept || !found_msg);
}
