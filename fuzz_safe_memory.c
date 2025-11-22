#include "safe_c.h"
#include <stdint.h>
#include <unistd.h>

#define MAX_INPUT 4096

int main(void) {
    uint8_t buf[MAX_INPUT];

    __AFL_INIT();

    while (__AFL_LOOP(10000)) {
        ssize_t n = read(0, buf, MAX_INPUT);
        if (n <= 0) continue;

        uint8_t dst[128];
        size_t dstsz = sizeof(dst);

        size_t to_copy = (size_t)n < dstsz ? (size_t)n : dstsz;
        safe_memcpy(dst, dstsz, buf, to_copy);

        if (n > 0) {
            size_t m = buf[0] % (dstsz + 1);
            safe_memset(dst, dstsz, 0xAA, m);
        }
    }

    return 0;
}