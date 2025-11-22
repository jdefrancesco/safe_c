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

        char fmt[64];
        size_t flen = (size_t)n < sizeof(fmt)-1 ? (size_t)n : sizeof(fmt)-1;

        for (size_t i = 0; i < flen; i++) {
            char c = (char)buf[i];
            if (c == '%') c = 'X';
            fmt[i] = c;
        }
        fmt[flen] = '\0';

        char outbuf[128];
        safe_snprintf(outbuf, sizeof(outbuf), fmt, 123, 456, "test");
    }

    return 0;
}