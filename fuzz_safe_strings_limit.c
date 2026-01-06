#define SAFE_C_ENABLE_LOGGING 0
#define SAFE_C_MAX_STR 8

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
        size_t len = size >= SAFE_C_MAX_STR ? SAFE_C_MAX_STR : size;

        char src[SAFE_C_MAX_STR];
        if (len > 0) memcpy(src, buf, len);
        if (len < SAFE_C_MAX_STR) src[len] = '\0';

        char dst1[32] = {0};
        char dst2[32] = "X";
        char dst3[64] = "prefix";

        safe_strcpy(dst1, sizeof(dst1), src);
        safe_strcat(dst2, sizeof(dst2), src);
        safe_strncpy(dst3, sizeof(dst3), src, len);

        char *dup = safe_strdup(src);
        SAFE_FREE(dup);
    }
    return 0;
}
