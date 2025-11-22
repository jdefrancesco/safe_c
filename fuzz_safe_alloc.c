#include "safe_c.h"
#include <stdint.h>
#include <unistd.h>

#define MAX_INPUT 4096

int main(void) {
    uint8_t buf[MAX_INPUT];

    __AFL_INIT();

    while (__AFL_LOOP(10000)) {
        ssize_t n = read(0, buf, MAX_INPUT);
        if (n < 2) continue;

        size_t a = buf[0] % 4096;
        size_t b = buf[1] % 4096;
        if (a == 0) a = 1;
        if (b == 0) b = 1;

        void *p1 = safe_malloc(a);
        void *p2 = safe_calloc(a, b);
        void *p3 = safe_realloc(p1, a, b);

        SAFE_FREE(p2);
        SAFE_FREE(p3);
    }
    return 0;
}