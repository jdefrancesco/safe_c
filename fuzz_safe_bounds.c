#include "safe_c.h"
#include <stdint.h>
#include <unistd.h>

#define MAX_INPUT 4096

int main(void) {
    uint8_t buf[MAX_INPUT];

    __AFL_INIT();

    while (__AFL_LOOP(10000)) {
        ssize_t n = read(0, buf, MAX_INPUT);
        if (n < 3) continue;

        size_t buf_size = buf[0];
        size_t offset   = buf[1];
        size_t sz       = buf[2];

        safe_bounds_check(offset, sz, buf_size);
    }

    return 0;
}