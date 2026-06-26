# safe_c

Defensive C utility helpers for safer memory, strings, and integer arithmetic.

`safe_c.h` is a single-header library designed to reduce common C pitfalls
(buffer overflows, integer overflows, misuse of `malloc`/`free`, etc.) while
remaining easy to drop into existing projects.

The primary API uses compact `s` names such as `smalloc`, `scalloc`,
`strscpy`, and `strscat`. Legacy `safe_*` wrappers are kept for existing code.

Below are small, self-contained examples showing how to use each helper.
You can compile them with a normal C compiler, or with the AFL/ASan setup
from this repo.

```c
#include "safe_c.h"

int main(void) {
    char buf[32];
    ssnprintf(buf, sizeof(buf), "hello %s", "world");
    SLOG_INFO("buf = '%s'", buf);
    return 0;
}
```

---

## Configuration macros

These macros are defined in `safe_c.h` and can be overridden before including it:

- `SAFE_C_ENABLE_POISON` (default 1): enable poisoning freed pointers.
- `SAFE_C_POISON_PTR`: poison value used by `sfree_poison`.
- `SAFE_C_ABORT_ON_ERROR` (default 0): call `abort()` on serious errors.
- `SAFE_C_ENABLE_LOGGING` (default 1): enable `SLOG_*` macros.
- `SAFE_C_ENABLE_COLOR` (default 1): colorize log messages.
- `SAFE_C_MAX_STR` (default `1UL << 20`): maximum string length scanned.

Example: disable color but abort on error

```c
#define SAFE_C_ENABLE_COLOR 0
#define SAFE_C_ABORT_ON_ERROR 1
#include "safe_c.h"
```

---

## Logging helpers

### `slog_error`, `slog_warn`, `slog_info`, `slog_debug`

Thin wrappers around `fprintf(stderr, ...)` with a consistent prefix and
(optional) ANSI colors. Usually accessed via macros:

- `SLOG_ERROR(...)`
- `SLOG_WARN(...)`
- `SLOG_INFO(...)`
- `SLOG_DEBUG(...)`

Example:

```c
#include "safe_c.h"

int main(void) {
    SLOG_INFO("starting up (pid=%d)", (int)getpid());

    int x = 42;
    if (x != 0) {
        SLOG_DEBUG("x is %d", x);
    }

    SLOG_WARN("this is just a demo warning");
    SLOG_ERROR("and this is an error message");
    return 0;
}
```

---

## String utilities

### `strsnlen`

```c
size_t strsnlen(const char *s, size_t maxlen);
```

Like `strnlen`, but returns 0 for `NULL` or `maxlen == 0`.

Example:

```c
#include "safe_c.h"

int main(void) {
    const char *s = "hello";
    size_t n = strsnlen(s, 3);  // n == 3
    SLOG_INFO("first 3 chars length = %zu", n);

    n = strsnlen(s, 32);        // n == 5
    SLOG_INFO("full length = %zu", n);
    return 0;
}
```

### `strscpy`

```c
ssize_t strscpy(char *dst, const char *src, size_t dstsz);
```

- Guarantees `dst` is NUL-terminated when `dstsz > 0`.
- Copies like Linux `strscpy`, with `SAFE_C_MAX_STR` limiting source scans.
- Returns:
  - copied byte count on success,
  - `-E2BIG` if truncated,
  - `-EINVAL` on invalid arguments.

Example:

```c
#include "safe_c.h"

int main(void) {
    char dst[8];

    if (strscpy(dst, "hi", sizeof dst) >= 0) {
        SLOG_INFO("copied: '%s'", dst);
    }

    // Truncation example
    ssize_t rc = strscpy(dst, "this is too long", sizeof dst);
    if (rc == -E2BIG) {
        SLOG_WARN("truncated copy: '%s'", dst);
    }
    return 0;
}
```

### `strsncpy`

```c
int strsncpy(char *dst, size_t dstsz, const char *src, size_t n);
```

- Copies at most `n` bytes, always NUL-terminating when `dstsz > 0`.
- Returns 0 on success, 1 on truncation, -1 on invalid args.

Example:

```c
#include "safe_c.h"

int main(void) {
    char dst[6];

    // Copy at most 4 bytes from src
    int rc = strsncpy(dst, sizeof dst, "abcdef", 4);
    SLOG_INFO("rc=%d, dst='%s'", rc, dst);  // rc==1, truncated

    rc = strsncpy(dst, sizeof dst, "hi", 4);
    SLOG_INFO("rc=%d, dst='%s'", rc, dst);  // rc==0
    return 0;
}
```

### `strscat`

```c
int strscat(char *dst, size_t dstsz, const char *src);
```

- Appends `src` to `dst` if there is space.
- Always NUL-terminates `dst` when `dstsz > 0`.
- Returns 0 on success, 1 on truncation, -1 on invalid args or unterminated `dst`.

Example:

```c
#include "safe_c.h"

int main(void) {
    char buf[16] = "Hello";

    strscat(buf, sizeof buf, ", ");
    strscat(buf, sizeof buf, "world!");
    SLOG_INFO("buf='%s'", buf);
    return 0;
}
```

### `strsdup`

```c
char *strsdup(const char *src);
```

`strdup`-like helper using `strsnlen` and `smalloc`.

Example:

```c
#include "safe_c.h"

int main(void) {
    char *copy = strsdup("example");
    if (!copy) {
        SLOG_ERROR("allocation failed");
        return 1;
    }

    SLOG_INFO("copy='%s'", copy);
    sfree(copy);  // or sfree_poison(copy);
    return 0;
}
```

---

## Memory allocation helpers

### `sumul` / `smul_overflow`

```c
bool sumul(size_t a, size_t b, size_t *result);
bool smul_overflow(size_t a, size_t b, size_t *result);
```

Detect overflow when multiplying sizes.

Example:

```c
#include "safe_c.h"

int main(void) {
    size_t total;

    if (!sumul(1024, 1024, &total)) {
        SLOG_ERROR("overflow computing size");
        return 1;
    }
    SLOG_INFO("total bytes = %zu", total);
    return 0;
}
```

### `smalloc`

```c
void *smalloc(size_t n);
```

- Rejects zero-size allocations (sets `errno = EINVAL`, logs a warning).
- Logs on allocation failure.

Example:

```c
#include "safe_c.h"

int main(void) {
    int *arr = smalloc(10 * sizeof *arr);
    if (!arr) {
        SLOG_ERROR("smalloc failed");
        return 1;
    }

    for (int i = 0; i < 10; ++i) arr[i] = i;
    sfree(arr);
    return 0;
}
```

### `scalloc`

```c
void *scalloc(size_t count, size_t size);
```

- Checks `count * size` for overflow and zero.
- Calls `calloc` only when the product is valid.

Example:

```c
#include "safe_c.h"

int main(void) {
    double *v = scalloc(4, sizeof *v);
    if (!v) {
        SLOG_ERROR("scalloc failed");
        return 1;
    }

    for (int i = 0; i < 4; ++i) {
        SLOG_INFO("v[%d] = %f", i, v[i]);  // all zero
    }
    sfree(v);
    return 0;
}
```

### `srealloc`

```c
void *srealloc(void *ptr, size_t count, size_t size);
```

- Computes `count * size` with overflow checking.
- Behaves like `realloc` for valid, non-zero totals.

Example:

```c
#include "safe_c.h"

int main(void) {
    size_t n = 4;
    int *arr = scalloc(n, sizeof *arr);
    if (!arr) return 1;

    // grow
    n *= 2;
    int *tmp = srealloc(arr, n, sizeof *arr);
    if (!tmp) {
        SLOG_ERROR("srealloc failed");
        sfree(arr);
        return 1;
    }
    arr = tmp;

    sfree(arr);
    return 0;
}
```

### `sfree` and `sfree_poison`

```c
#define sfree(ptr)      ...
#define sfree_poison(ptr) ...
```

- `sfree(ptr)` frees and sets `ptr = NULL`.
- `sfree_poison(ptr)` frees and sets `ptr` to a poison pointer (or `NULL` if poisoning disabled).

Example:

```c
#include "safe_c.h"

int main(void) {
    char *buf = smalloc(32);
    if (!buf) return 1;

    sfree_poison(buf);
    // buf now points to a known poison value or NULL
    return 0;
}
```

---

## Memory utilities

### `smemset`

```c
int smemset(void *dst, size_t dstsz, int value, size_t n);
```

- Ensures `dst` is non-NULL and `n <= dstsz` before calling `memset`.

Example:

```c
#include "safe_c.h"

int main(void) {
    unsigned char buf[16];

    if (smemset(buf, sizeof buf, 0xAA, 8) == 0) {
        SLOG_INFO("first 8 bytes set to 0xAA");
    }
    return 0;
}
```

### `smemcpy`

```c
int smemcpy(void *dst, size_t dstsz, const void *src, size_t srcsz);
```

- Validates non-NULL pointers and that `dstsz >= srcsz`.
- Does **not** handle overlapping regions (same as `memcpy`).

Example:

```c
#include "safe_c.h"

int main(void) {
    unsigned char src[4] = {1,2,3,4};
    unsigned char dst[4];

    if (smemcpy(dst, sizeof dst, src, sizeof src) == 0) {
        SLOG_INFO("copied 4 bytes successfully");
    }
    return 0;
}
```

---

## Formatted output

### `ssnprintf`

```c
int ssnprintf(char *dst, size_t dstsz, const char *fmt, ...);
```

- Wraps `vsnprintf` with argument validation and truncation detection.
- Returns 0 on success, 1 on truncation, -1 on error.

Example:

```c
#include "safe_c.h"

int main(void) {
    char buf[16];

    int rc = ssnprintf(buf, sizeof buf, "value=%d", 123);
    SLOG_INFO("rc=%d, buf='%s'", rc, buf);

    rc = ssnprintf(buf, 8, "too-long-%d", 42);
    SLOG_WARN("rc=%d, truncated buf='%s'", rc, buf);
    return 0;
}
```

---

## Bounds checking

### `sbounds_check`

```c
int sbounds_check(size_t offset, size_t size, size_t buf_size);
```

- Ensures `offset` and `size` describe a range fully contained within a buffer.
- Returns 0 if in-bounds, -1 on error.

Example:

```c
#include "safe_c.h"

int main(void) {
    unsigned char buf[64];

    size_t offset = 16;
    size_t len = 32;

    if (sbounds_check(offset, len, sizeof buf) == 0) {
        // safe to access buf[offset .. offset+len-1]
        SLOG_INFO("range is in bounds");
    } else {
        SLOG_ERROR("out-of-bounds range");
    }
    return 0;
}
```

---

## Building the fuzzers in this repo

From the project root (this directory), run:

```sh
make
```

This uses `afl-clang-fast` plus ASan/UBSan to build several fuzzers
(`fuzz_safe_strings`, `fuzz_safe_memory`, `fuzz_safe_alloc`,
`fuzz_safe_snprintf`, `fuzz_safe_bounds`) that exercise the helpers
under randomized inputs.
