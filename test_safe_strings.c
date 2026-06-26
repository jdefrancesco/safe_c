#define SAFE_C_ENABLE_LOGGING 0
#define SAFE_C_MAX_STR 8

#include "safe_c.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg)            \
    do {                            \
        if (!(cond)) {              \
            fprintf(stderr, "%s\n", msg); \
            return 1;               \
        }                           \
    } while (0)

static int test_strscpy_copies_string(void)
{
    char dst[8];
    memset(dst, 'Z', sizeof dst);

    errno = 0;
    ssize_t rc = strscpy(dst, "abc", sizeof dst);

    CHECK(rc == 3, "strscpy should return bytes copied on success");
    CHECK(strcmp(dst, "abc") == 0, "strscpy should copy source text");
    CHECK(dst[4] == 'Z', "strscpy should not clobber bytes after terminator");
    return 0;
}

static int test_strscpy_truncates_at_max(void)
{
    char src[SAFE_C_MAX_STR] = {'A','B','C','D','E','F','G','H'};
    char dst[16];
    memset(dst, 'Z', sizeof dst);

    errno = 0;
    ssize_t rc = strscpy(dst, src, sizeof dst);

    CHECK(rc == -E2BIG, "strscpy should report truncation at SAFE_C_MAX_STR");
    CHECK(errno == E2BIG, "strscpy should set errno on truncation");
    CHECK(memcmp(dst, src, SAFE_C_MAX_STR) == 0,
          "strscpy should copy validated bytes");
    CHECK(dst[SAFE_C_MAX_STR] == '\0', "strscpy should NUL-terminate after copy");
    CHECK(dst[SAFE_C_MAX_STR + 1] == 'Z', "strscpy should not clobber stale tail");
    return 0;
}

static int test_strscpy_truncates_to_destination(void)
{
    char dst[4];
    memset(dst, 'Z', sizeof dst);

    errno = 0;
    ssize_t rc = strscpy(dst, "abcdef", sizeof dst);

    CHECK(rc == -E2BIG, "strscpy should report destination truncation");
    CHECK(strcmp(dst, "abc") == 0, "strscpy should NUL-terminate truncated destination");
    CHECK(errno == E2BIG, "strscpy should set errno on destination truncation");
    return 0;
}

static int test_strscat_truncates_at_max(void)
{
    char src[SAFE_C_MAX_STR] = {'a','b','c','d','e','f','g','h'};
    char dst[32];
    memset(dst, 'Z', sizeof dst);
    dst[0] = 'h';
    dst[1] = 'i';
    dst[2] = '\0';

    int rc = strscat(dst, sizeof dst, src);

    CHECK(rc == 1, "strscat should report truncation at SAFE_C_MAX_STR");
    CHECK(memcmp(dst, "hi", 2) == 0, "strscat should keep existing prefix");
    CHECK(memcmp(dst + 2, src, SAFE_C_MAX_STR) == 0,
          "strscat should append validated bytes");
    CHECK(dst[2 + SAFE_C_MAX_STR] == '\0', "strscat should NUL-terminate after append");
    CHECK(dst[3 + SAFE_C_MAX_STR] == 'Z', "strscat should not rely on stale tail termination");
    return 0;
}

static int test_strsdup_truncates_at_max(void)
{
    char src[SAFE_C_MAX_STR] = {'1','2','3','4','5','6','7','8'};
    char *dup = strsdup(src);

    CHECK(dup != NULL, "strsdup should allocate memory");
    CHECK(memcmp(dup, src, SAFE_C_MAX_STR) == 0, "strsdup should copy validated bytes");
    CHECK(dup[SAFE_C_MAX_STR] == '\0', "strsdup should NUL-terminate after copy");
    sfree(dup);
    return 0;
}

static int test_smul_overflow_contract(void)
{
    size_t out = 12345;

    CHECK(smul_overflow(SIZE_MAX, 2, &out) == true,
          "smul_overflow should return true on overflow");
    CHECK(out == 12345, "smul_overflow should leave output unchanged on overflow");
    CHECK(smul_overflow(3, 4, &out) == false,
          "smul_overflow should return false on success");
    CHECK(out == 12, "smul_overflow should write output on success");
    return 0;
}

static int test_sfree_poison_is_idempotent(void)
{
    char *buf = smalloc(4);
    CHECK(buf != NULL, "smalloc should allocate test buffer");

    sfree_poison(buf);
    CHECK((void *)buf == SAFE_C_POISON_PTR, "sfree_poison should poison pointer");

    sfree_poison(buf);
    CHECK((void *)buf == SAFE_C_POISON_PTR,
          "sfree_poison should tolerate repeated cleanup");
    return 0;
}

static int test_safe_strcpy_wrapper_keeps_old_contract(void)
{
    char dst[4];

    CHECK(safe_strcpy(dst, sizeof dst, "hi") == 0,
          "safe_strcpy wrapper should return 0 on success");
    CHECK(strcmp(dst, "hi") == 0, "safe_strcpy wrapper should copy source text");

    CHECK(safe_strcpy(dst, sizeof dst, "abcdef") == 1,
          "safe_strcpy wrapper should return 1 on truncation");
    CHECK(strcmp(dst, "abc") == 0,
          "safe_strcpy wrapper should NUL-terminate truncated destination");

    CHECK(safe_strcpy(dst, 0, "x") == -1,
          "safe_strcpy wrapper should keep old invalid-argument return");
    return 0;
}

int main(void)
{
    if (test_strscpy_copies_string()) return 1;
    if (test_strscpy_truncates_at_max()) return 1;
    if (test_strscpy_truncates_to_destination()) return 1;
    if (test_strscat_truncates_at_max()) return 1;
    if (test_strsdup_truncates_at_max()) return 1;
    if (test_smul_overflow_contract()) return 1;
    if (test_sfree_poison_is_idempotent()) return 1;
    if (test_safe_strcpy_wrapper_keeps_old_contract()) return 1;
    return 0;
}
