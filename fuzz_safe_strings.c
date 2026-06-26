#include "safe_c.h"
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define MAX_INPUT 4096

int main(void) {
    uint8_t buf[MAX_INPUT];

    __AFL_INIT();  // required for macOS

    while (__AFL_LOOP(10000)) {

        ssize_t n = read(0, buf, MAX_INPUT);
        if (n <= 0) continue;

        size_t size = (size_t)n;

        char stack_src[256];
        size_t copy_len = size < sizeof(stack_src)-1 ? size : sizeof(stack_src)-1;

        for (size_t i = 0; i < copy_len; i++)
            stack_src[i] = (char)buf[i];
        stack_src[copy_len] = '\0';

        char buf1[128] = {0};
        char buf2[64]  = {0};

        strscpy(buf1, stack_src, sizeof(buf1));
        strsncpy(buf2, sizeof(buf2), stack_src, copy_len);
        strscat(buf1, sizeof(buf1), buf2);

        size_t len1 = strsnlen(buf1, sizeof(buf1));
        (void)len1;

        char *dup = strsdup(stack_src);
        sfree(dup);
    }
    return 0;
}
