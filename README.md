# safe_c

Defensive C utility helpers for safer memory, strings, and integer arithmetic.

`safe_c.h` is a single-header library designed to reduce common C pitfalls
(buffer overflows, integer overflows, misuse of `malloc`/`free`, etc.) while
remaining easy to drop into existing projects.

Below are small, self-contained examples showing how to use each helper.
You can compile them with a normal C compiler, or with the AFL/ASan setup
from this repo.

```c
#include "safe_c.h"

int main(void) {
    char buf[32];
    safe_snprintf(buf, sizeof(buf), "hello %s", "world");
    SAFE_C_LOG_INFO("buf = '%s'", buf);
    return 0;
}
```

---

## Configuration macros

These macros are defined in `safe_c.h` and can be overridden before including it:

- `SAFE_C_ENABLE_POISON` (default 1): enable poisoning freed pointers.
- `SAFE_C_POISON_PTR`: poison value used by `SAFE_FREE_POISON`.
- `SAFE_C_ABORT_ON_ERROR` (default 0): call `abort()` on serious errors.
- `SAFE_C_ENABLE_LOGGING` (default 1): enable `SAFE_C_LOG_*` macros.
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

### `safe_c_log_error`, `safe_c_log_warn`, `safe_c_log_info`, `safe_c_log_debug`

Thin wrappers around `fprintf(stderr, ...)` with a consistent prefix and
(optional) ANSI colors. Usually accessed via macros:

- `SAFE_C_LOG_ERROR(...)`
- `SAFE_C_LOG_WARN(...)`
- `SAFE_C_LOG_INFO(...)`
- `SAFE_C_LOG_DEBUG(...)`

Example:

```c
#include "safe_c.h"

int main(void) {
    SAFE_C_LOG_INFO("starting up (pid=%d)", (int)getpid());

    int x = 42;
    if (x != 0) {
        SAFE_C_LOG_DEBUG("x is %d", x);
    }

    SAFE_C_LOG_WARN("this is just a demo warning");
    SAFE_C_LOG_ERROR("and this is an error message");
    return 0;
}
```

---

## String utilities

### `safe_strnlen`

```c
size_t safe_strnlen(const char *s, size_t maxlen);
```

Like `strnlen`, but returns 0 for `NULL` or `maxlen == 0`.

Example:

```c
#include "safe_c.h"

int main(void) {
    const char *s = "hello";
    size_t n = safe_strnlen(s, 3);  // n == 3
    SAFE_C_LOG_INFO("first 3 chars length = %zu", n);

    n = safe_strnlen(s, 32);        // n == 5
    SAFE_C_LOG_INFO("full length = %zu", n);
    return 0;
}
```

### `safe_strcpy`

```c
int safe_strcpy(char *dst, size_t dstsz, const char *src);
```

- Guarantees `dst` is NUL-terminated when `dstsz > 0`.
- Returns:
  - `0` on success (no truncation),
  - `1` if truncated,
  - `-1` on invalid arguments.

Example:

```c
#include "safe_c.h"

int main(void) {
    char dst[8];

    if (safe_strcpy(dst, sizeof dst, "hi") == 0) {
        SAFE_C_LOG_INFO("copied: '%s'", dst);
    }

    // Truncation example
    int rc = safe_strcpy(dst, sizeof dst, "this is too long");
    if (rc == 1) {
        SAFE_C_LOG_WARN("truncated copy: '%s'", dst);
    }
    return 0;
}
```

### `safe_strncpy`

```c
int safe_strncpy(char *dst, size_t dstsz, const char *src, size_t n);
```

- Copies at most `n` bytes, always NUL-terminating when `dstsz > 0`.
- Returns 0 on success, 1 on truncation, -1 on invalid args.

Example:

```c
#include "safe_c.h"

int main(void) {
    char dst[6];

    // Copy at most 4 bytes from src
    int rc = safe_strncpy(dst, sizeof dst, "abcdef", 4);
    SAFE_C_LOG_INFO("rc=%d, dst='%s'", rc, dst);  // rc==1, truncated

    rc = safe_strncpy(dst, sizeof dst, "hi", 4);
    SAFE_C_LOG_INFO("rc=%d, dst='%s'", rc, dst);  // rc==0
    return 0;
}
```

### `safe_strcat`

```c
int safe_strcat(char *dst, size_t dstsz, const char *src);
```

- Appends `src` to `dst` if there is space.
- Always NUL-terminates `dst` when `dstsz > 0`.
- Returns 0 on success, 1 on truncation, -1 on invalid args or unterminated `dst`.

Example:

```c
#include "safe_c.h"

int main(void) {
    char buf[16] = "Hello";

    safe_strcat(buf, sizeof buf, ", ");
    safe_strcat(buf, sizeof buf, "world!");
    SAFE_C_LOG_INFO("buf='%s'", buf);
    return 0;
}
```

### `safe_strdup`

```c
char *safe_strdup(const char *src);
```

`strdup`-like helper using `safe_strnlen` and `safe_malloc`.

Example:

```c
#include "safe_c.h"

int main(void) {
    char *copy = safe_strdup("example");
    if (!copy) {
        SAFE_C_LOG_ERROR("allocation failed");
        return 1;
    }

    SAFE_C_LOG_INFO("copy='%s'", copy);
    SAFE_FREE(copy);  // or SAFE_FREE_POISON(copy);
    return 0;
}
```

---

## Memory allocation helpers

### `safe_umul` / `safe_mul_overflow`

```c
bool safe_umul(size_t a, size_t b, size_t *result);
bool safe_mul_overflow(size_t a, size_t b, size_t *result);
```

Detect overflow when multiplying sizes.

Example:

```c
#include "safe_c.h"

int main(void) {
    size_t total;

    if (!safe_umul(1024, 1024, &total)) {
        SAFE_C_LOG_ERROR("overflow computing size");
        return 1;
    }
    SAFE_C_LOG_INFO("total bytes = %zu", total);
    return 0;
}
```

### `safe_malloc`

```c
void *safe_malloc(size_t n);
```

- Rejects zero-size allocations (sets `errno = EINVAL`, logs a warning).
- Logs on allocation failure.

Example:

```c
#include "safe_c.h"

int main(void) {
    int *arr = safe_malloc(10 * sizeof *arr);
    if (!arr) {
        SAFE_C_LOG_ERROR("safe_malloc failed");
        return 1;
    }

    for (int i = 0; i < 10; ++i) arr[i] = i;
    SAFE_FREE(arr);
    return 0;
}
```

### `safe_calloc`

```c
void *safe_calloc(size_t count, size_t size);
```

- Checks `count * size` for overflow and zero.
- Calls `calloc` only when the product is valid.

Example:

```c
#include "safe_c.h"

int main(void) {
    double *v = safe_calloc(4, sizeof *v);
    if (!v) {
        SAFE_C_LOG_ERROR("safe_calloc failed");
        return 1;
    }

    for (int i = 0; i < 4; ++i) {
        SAFE_C_LOG_INFO("v[%d] = %f", i, v[i]);  // all zero
    }
    SAFE_FREE(v);
    return 0;
}
```

### `safe_realloc`

```c
void *safe_realloc(void *ptr, size_t count, size_t size);
```

- Computes `count * size` with overflow checking.
- Behaves like `realloc` for valid, non-zero totals.

Example:

```c
#include "safe_c.h"

int main(void) {
    size_t n = 4;
    int *arr = safe_calloc(n, sizeof *arr);
    if (!arr) return 1;

    // grow
    n *= 2;
    int *tmp = safe_realloc(arr, n, sizeof *arr);
    if (!tmp) {
        SAFE_C_LOG_ERROR("safe_realloc failed");
        SAFE_FREE(arr);
        return 1;
    }
    arr = tmp;

    SAFE_FREE(arr);
    return 0;
}
```

### `SAFE_FREE` and `SAFE_FREE_POISON`

```c
#define SAFE_FREE(ptr)      ...
#define SAFE_FREE_POISON(ptr) ...
```

- `SAFE_FREE(ptr)` frees and sets `ptr = NULL`.
- `SAFE_FREE_POISON(ptr)` frees and sets `ptr` to a poison pointer (or `NULL` if poisoning disabled).

Example:

```c
#include "safe_c.h"

int main(void) {
    char *buf = safe_malloc(32);
    if (!buf) return 1;

    SAFE_FREE_POISON(buf);
    // buf now points to a known poison value or NULL
    return 0;
}
```

---

## Memory utilities

### `safe_memset`

```c
int safe_memset(void *dst, size_t dstsz, int value, size_t n);
```

- Ensures `dst` is non-NULL and `n <= dstsz` before calling `memset`.

Example:

```c
#include "safe_c.h"

int main(void) {
    unsigned char buf[16];

    if (safe_memset(buf, sizeof buf, 0xAA, 8) == 0) {
        SAFE_C_LOG_INFO("first 8 bytes set to 0xAA");
    }
    return 0;
}
```

### `safe_memcpy`

```c
int safe_memcpy(void *dst, size_t dstsz, const void *src, size_t srcsz);
```

- Validates non-NULL pointers and that `dstsz >= srcsz`.
- Does **not** handle overlapping regions (same as `memcpy`).

Example:

```c
#include "safe_c.h"

int main(void) {
    unsigned char src[4] = {1,2,3,4};
    unsigned char dst[4];

    if (safe_memcpy(dst, sizeof dst, src, sizeof src) == 0) {
        SAFE_C_LOG_INFO("copied 4 bytes successfully");
    }
    return 0;
}
```

---

## Formatted output

### `safe_snprintf`

```c
int safe_snprintf(char *dst, size_t dstsz, const char *fmt, ...);
```

- Wraps `vsnprintf` with argument validation and truncation detection.
- Returns 0 on success, 1 on truncation, -1 on error.

Example:

```c
#include "safe_c.h"

int main(void) {
    char buf[16];

    int rc = safe_snprintf(buf, sizeof buf, "value=%d", 123);
    SAFE_C_LOG_INFO("rc=%d, buf='%s'", rc, buf);

    rc = safe_snprintf(buf, 8, "too-long-%d", 42);
    SAFE_C_LOG_WARN("rc=%d, truncated buf='%s'", rc, buf);
    return 0;
}
```

---

## Bounds checking

### `safe_bounds_check`

```c
int safe_bounds_check(size_t offset, size_t size, size_t buf_size);
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

    if (safe_bounds_check(offset, len, sizeof buf) == 0) {
        // safe to access buf[offset .. offset+len-1]
        SAFE_C_LOG_INFO("range is in bounds");
    } else {
        SAFE_C_LOG_ERROR("out-of-bounds range");
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
