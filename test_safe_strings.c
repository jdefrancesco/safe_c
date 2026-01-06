#define SAFE_C_ENABLE_LOGGING 0
#define SAFE_C_MAX_STR 8

#include "safe_c.h"
#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg)            \
    do {                            \
        if (!(cond)) {              \
            fprintf(stderr, "%s\n", msg); \
            return 1;               \
        }                           \
    } while (0)

static int test_safe_strcpy_truncates_at_max(void)
{
    char src[SAFE_C_MAX_STR] = {'A','B','C','D','E','F','G','H'};
    char dst[16];
    memset(dst, 'Z', sizeof dst);

    int rc = safe_strcpy(dst, sizeof dst, src);

    CHECK(rc == 1, "safe_strcpy should report truncation at SAFE_C_MAX_STR");
    CHECK(memcmp(dst, src, SAFE_C_MAX_STR) == 0,
          "safe_strcpy should copy validated bytes");
    CHECK(dst[SAFE_C_MAX_STR] == '\0', "safe_strcpy should NUL-terminate after copy");
    return 0;
}

static int test_safe_strcat_truncates_at_max(void)
{
    char src[SAFE_C_MAX_STR] = {'a','b','c','d','e','f','g','h'};
    char dst[32] = "hi";

    int rc = safe_strcat(dst, sizeof dst, src);

    CHECK(rc == 1, "safe_strcat should report truncation at SAFE_C_MAX_STR");
    CHECK(memcmp(dst, "hi", 2) == 0, "safe_strcat should keep existing prefix");
    CHECK(memcmp(dst + 2, src, SAFE_C_MAX_STR) == 0,
          "safe_strcat should append validated bytes");
    CHECK(dst[2 + SAFE_C_MAX_STR] == '\0', "safe_strcat should NUL-terminate after append");
    return 0;
}

static int test_safe_strdup_truncates_at_max(void)
{
    char src[SAFE_C_MAX_STR] = {'1','2','3','4','5','6','7','8'};
    char *dup = safe_strdup(src);

    CHECK(dup != NULL, "safe_strdup should allocate memory");
    CHECK(memcmp(dup, src, SAFE_C_MAX_STR) == 0, "safe_strdup should copy validated bytes");
    CHECK(dup[SAFE_C_MAX_STR] == '\0', "safe_strdup should NUL-terminate after copy");
    SAFE_FREE(dup);
    return 0;
}

int main(void)
{
    if (test_safe_strcpy_truncates_at_max()) return 1;
    if (test_safe_strcat_truncates_at_max()) return 1;
    if (test_safe_strdup_truncates_at_max()) return 1;
    return 0;
}
