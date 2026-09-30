/**
 * @file safe_c.h
 * @brief Defensive C utility helpers aligned with CERT C guidelines.
 *
 *
 * @author J. DeFrancesco
 */

#ifndef SAFE_C_H
#define SAFE_C_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>

#ifndef SAFE_C_POISON_VALUE
    #define SAFE_C_POISON_VALUE 0xDEADBEEF
#endif

#ifndef SAFE_C_ENABLE_POISON
    #define SAFE_C_ENABLE_POISON 1
#endif

#ifndef SAFE_C_ABORT_ON_ERROR
    #define SAFE_C_ABORT_ON_ERROR 0
#endif

#ifndef SAFE_C_ENABLE_LOGGING
    #define SAFE_C_ENABLE_LOGGING 1
#endif

#ifndef SAFE_C_ENABLE_COLOR
    #define SAFE_C_ENABLE_COLOR 1
#endif

#ifndef SAFE_C_MAX_STR
    #define SAFE_C_MAX_STR (1UL << 20)
#endif

#if SAFE_C_ENABLE_POISON
    #define SAFE_C_POISON_PTR ((void *)(uintptr_t)(SAFE_C_POISON_VALUE))
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define SAFE_C_PRINTF_ATTR(fmt_idx, va_idx) __attribute__((format(printf, fmt_idx, va_idx)))
#else
    #define SAFE_C_PRINTF_ATTR(fmt_idx, va_idx)
#endif

#if SAFE_C_ENABLE_COLOR
    #define SAFE_C_COLOR_RED    "\033[31m"
    #define SAFE_C_COLOR_YELLOW "\033[33m"
    #define SAFE_C_COLOR_GREEN  "\033[32m"
    #define SAFE_C_COLOR_BLUE   "\033[34m"
    #define SAFE_C_COLOR_RESET  "\033[0m"
#else
    #define SAFE_C_COLOR_RED    ""
    #define SAFE_C_COLOR_YELLOW ""
    #define SAFE_C_COLOR_GREEN  ""
    #define SAFE_C_COLOR_BLUE   ""
    #define SAFE_C_COLOR_RESET  ""
#endif

/*
 * Forward-declared with the printf format attribute so both GCC and Clang
 * apply format-string/argument-type checking at every call site (GCC,
 * unlike Clang, rejects the attribute when it is attached directly to a
 * function definition, so it must appear on a separate prototype).
 */
static inline void slog_impl(const char *level, const char *color, const char *fmt, va_list ap) SAFE_C_PRINTF_ATTR(3, 0);
static inline void slog_error(const char *fmt, ...) SAFE_C_PRINTF_ATTR(1, 2);
static inline void slog_warn(const char *fmt, ...) SAFE_C_PRINTF_ATTR(1, 2);
static inline void slog_info(const char *fmt, ...) SAFE_C_PRINTF_ATTR(1, 2);
static inline void slog_debug(const char *fmt, ...) SAFE_C_PRINTF_ATTR(1, 2);
static inline void safe_c_log_impl(const char *level, const char *color, const char *fmt, va_list ap) SAFE_C_PRINTF_ATTR(3, 0);
static inline void safe_c_log_error(const char *fmt, ...) SAFE_C_PRINTF_ATTR(1, 2);
static inline void safe_c_log_warn(const char *fmt, ...) SAFE_C_PRINTF_ATTR(1, 2);
static inline void safe_c_log_info(const char *fmt, ...) SAFE_C_PRINTF_ATTR(1, 2);
static inline void safe_c_log_debug(const char *fmt, ...) SAFE_C_PRINTF_ATTR(1, 2);

static inline void
slog_impl(const char *level, const char *color, const char *fmt, va_list ap)
{
#if SAFE_C_ENABLE_LOGGING
    fprintf(stderr, "%s[safe_c][%s] ", color, level);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "%s\n", SAFE_C_COLOR_RESET);
#else
    (void)level; (void)color; (void)fmt; (void)ap;
#endif
}

static inline void
slog_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    slog_impl("ERROR", SAFE_C_COLOR_RED, fmt, ap);
    va_end(ap);
}

static inline void
slog_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    slog_impl("WARN", SAFE_C_COLOR_YELLOW, fmt, ap);
    va_end(ap);
}

static inline void
slog_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    slog_impl("INFO", SAFE_C_COLOR_GREEN, fmt, ap);
    va_end(ap);
}

static inline void
slog_debug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    slog_impl("DEBUG", SAFE_C_COLOR_BLUE, fmt, ap);
    va_end(ap);
}

static inline void
safe_c_log_impl(const char *level, const char *color, const char *fmt, va_list ap)
{
    slog_impl(level, color, fmt, ap);
}

static inline void
safe_c_log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    slog_impl("ERROR", SAFE_C_COLOR_RED, fmt, ap);
    va_end(ap);
}

static inline void
safe_c_log_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    slog_impl("WARN", SAFE_C_COLOR_YELLOW, fmt, ap);
    va_end(ap);
}

static inline void
safe_c_log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    slog_impl("INFO", SAFE_C_COLOR_GREEN, fmt, ap);
    va_end(ap);
}

static inline void
safe_c_log_debug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    slog_impl("DEBUG", SAFE_C_COLOR_BLUE, fmt, ap);
    va_end(ap);
}

#define SLOG_ERROR(...) slog_error(__VA_ARGS__)
#define SLOG_WARN(...)  slog_warn(__VA_ARGS__)
#define SLOG_INFO(...)  slog_info(__VA_ARGS__)
#define SLOG_DEBUG(...) slog_debug(__VA_ARGS__)

#define SAFE_C_LOG_ERROR(...) SLOG_ERROR(__VA_ARGS__)
#define SAFE_C_LOG_WARN(...)  SLOG_WARN(__VA_ARGS__)
#define SAFE_C_LOG_INFO(...)  SLOG_INFO(__VA_ARGS__)
#define SAFE_C_LOG_DEBUG(...) SLOG_DEBUG(__VA_ARGS__)

/**
 * @brief Computes the length of a string up to a maximum number of characters.
 *
 * @param s Pointer to the null-terminated string to measure.
 * @param maxlen Maximum number of characters to examine.
 * @return The number of characters before the null terminator or @p maxlen if no null terminator is found.
 */
static inline size_t
strsnlen(const char *s, size_t maxlen)
{
    if (!s || maxlen == 0) {
        return 0;
    }
    const char *end = memchr(s, '\0', maxlen);
    return end ? (size_t)(end - s) : maxlen;
}

static inline size_t
safe_strnlen(const char *s, size_t maxlen)
{
    return strsnlen(s, maxlen);
}

/**
 * Safely multiplies two size_t values, reporting overflow.
 *
 * Performs the multiplication of @p a and @p b, writing the product to @p result.
 * Returns true on success. If @p result is null, sets errno to EINVAL and logs an error.
 * If the multiplication would overflow, sets errno to EOVERFLOW, logs an error, and fails.
 *
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param result Pointer to store the product.
 * @return true if the multiplication succeeds without overflow; otherwise false.
 */
static inline bool
sumul(size_t a, size_t b, size_t *result)
{
    if (!result) {
        SLOG_ERROR("sumul: result pointer is NULL");
        errno = EINVAL;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return false;
    }
    if (a != 0 && b > SIZE_MAX / a) {
        SLOG_ERROR("sumul: overflow (%zu * %zu)", a, b);
        errno = EOVERFLOW;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return false;
    }
    *result = a * b;
    return true;
}

static inline bool
safe_umul(size_t a, size_t b, size_t *result)
{
    return sumul(a, b, result);
}

/**
 * @brief Checks whether the multiplication of two size_t values overflows.
 *
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param result Pointer that receives the product when no overflow occurs.
 *
 * @return true if the multiplication results in an overflow; otherwise false.
 */
static inline bool
smul_overflow(size_t a, size_t b, size_t *result)
{
    return !sumul(a, b, result);
}

static inline bool
safe_mul_overflow(size_t a, size_t b, size_t *result)
{
    return smul_overflow(a, b, result);
}

/*
 * ptr is only ever evaluated once, via &(ptr): this is what lets sfree()
 * be used safely with non-idempotent lvalues like arr[idx++]. Do not
 * "simplify" this back to repeating (ptr) in the macro body -- that
 * reintroduces multiple-evaluation of the argument (each occurrence can
 * observe a different index/side effect), which silently frees/nulls the
 * wrong slot instead of the one the caller intended.
 */
#define sfree(ptr) do {                          \
    __typeof__(&(ptr)) sfree_pp__ = &(ptr);      \
    if (*sfree_pp__ != NULL) {                   \
        free(*sfree_pp__);                       \
        *sfree_pp__ = NULL;                      \
    }                                            \
} while (0)

#if SAFE_C_ENABLE_POISON
#define sfree_poison(ptr) do {                                 \
    __typeof__(&(ptr)) sfree_pp__ = &(ptr);                     \
    if (*sfree_pp__ != NULL) {                                  \
        if ((void *)(*sfree_pp__) != SAFE_C_POISON_PTR) {       \
            free(*sfree_pp__);                                  \
        }                                                        \
        *sfree_pp__ = SAFE_C_POISON_PTR;                         \
    }                                                            \
} while (0)
#else
#define sfree_poison(ptr) do {                      \
    __typeof__(&(ptr)) sfree_pp__ = &(ptr);          \
    if (*sfree_pp__ != NULL) {                       \
        free(*sfree_pp__);                           \
        *sfree_pp__ = NULL;                          \
    }                                                \
} while (0)
#endif

#define SAFE_FREE(ptr) sfree(ptr)
#define SAFE_FREE_POISON(ptr) sfree_poison(ptr)

/**
 * @brief Allocates memory with additional safety checks and logging.
 *
 * Logs a warning and sets @c errno to @c EINVAL when zero bytes are requested,
 * optionally aborting the program if @c SAFE_C_ABORT_ON_ERROR is enabled,
 * and returns @c NULL in that case. Delegates to @c malloc(size_t) for non-zero
 * sizes, emitting an error log if allocation fails, and returns the allocated
 * memory pointer or @c NULL if the allocation could not be completed.
 *
 * @param n Number of bytes to allocate; must be greater than zero.
 * @return Pointer to the allocated memory on success, or @c NULL on failure.
 */
static inline void *
smalloc(size_t n)
{
    if (n == 0) {
        SLOG_WARN("smalloc: requested size 0");
        errno = EINVAL;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return NULL;
    }
    void *p = malloc(n);
    if (!p) {
        SLOG_ERROR("smalloc: malloc(%zu) failed", n);
    }
    return p;
}

static inline void *
safe_malloc(size_t n)
{
    return smalloc(n);
}

/**
 * @brief Allocates zero-initialized memory for an array with overflow checking.
 *
 * This helper verifies that multiplying @p count by @p size does not overflow
 * before calling `calloc`. A zero-size request (count == 0 or size == 0) is
 * not an error: it is treated like malloc(0)/calloc(0,0) commonly are and
 * yields a valid, unique, non-NULL pointer to a minimal allocation rather
 * than being conflated with an overflow failure.
 *
 * @param count Number of elements to allocate.
 * @param size  Size of each element in bytes.
 *
 * @return Pointer to the allocated zero-initialized memory on success; otherwise
 *         @c NULL is returned and @c errno is set to @c EOVERFLOW.
 *
 * @note When @c SAFE_C_ABORT_ON_ERROR is enabled, the process aborts on overflow.
 */
static inline void *
scalloc(size_t count, size_t size)
{
    size_t total;
    if (sumul(count, size, &total) == false) {
        SLOG_ERROR("scalloc: overflow (%zu * %zu)", count, size);
        errno = EOVERFLOW;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return NULL;
    }
    if (total == 0) {
        total = 1;
    }
    void *p = calloc(1, total);
    if (!p) {
        SLOG_ERROR("scalloc: calloc(%zu,%zu) failed", count, size);
    }
    return p;
}

static inline void *
safe_calloc(size_t count, size_t size)
{
    return scalloc(count, size);
}

/**
 * @brief Reallocate memory with overflow protection.
 *
 * Attempts to resize the allocation referenced by @p ptr to accommodate
 * @p count elements of @p size bytes each, validating that the product
 * does not overflow and is non-zero before invoking realloc.
 *
 * @param ptr    Pointer to the existing allocation, or NULL for a new allocation.
 * @param count  Number of elements requested.
 * @param size   Size in bytes of each element.
 *
 * @return Pointer to the resized allocation on success, or NULL if the
 *         count*size multiplication overflows or the underlying realloc
 *         fails. On failure, errno is set to EOVERFLOW and @p ptr is left
 *         untouched and still valid (standard realloc-failure semantics).
 *         A zero-size request (count == 0 or size == 0) is not treated as
 *         an error; it yields a minimal, valid, non-NULL allocation.
 */
static inline void *
srealloc(void *ptr, size_t count, size_t size)
{
    size_t total;
    if (sumul(count, size, &total) == false) {
        SLOG_ERROR("srealloc: overflow (%zu * %zu)", count, size);
        errno = EOVERFLOW;
#if SAFE_C_ABORT_ON_ERROR
        abort();
#endif
        return NULL;
    }
    if (total == 0) {
        total = 1;
    }
    void *p = realloc(ptr, total);
    if (!p) {
        SLOG_ERROR("srealloc: realloc(%p, %zu) failed", ptr, total);
    }
    return p;
}

static inline void *
safe_realloc(void *ptr, size_t count, size_t size)
{
    return srealloc(ptr, count, size);
}

/**
 * @brief Copies a string like Linux strscpy, with SAFE_C_MAX_STR scan limiting.
 *
 * Copies as much of @p src as fits in @p dst, always NUL-terminating when
 * @p dstsz is nonzero. On success, returns the number of copied characters,
 * excluding the terminator. If truncation occurs, returns -E2BIG. If the
 * arguments are invalid, returns -EINVAL.
 *
 * @param dst    Destination buffer to receive the copied string.
 * @param src    Null-terminated source string to copy.
 * @param dstsz  Size of the destination buffer in bytes.
 *
 * @return copied byte count on success, -E2BIG on truncation, or -EINVAL.
 */
static inline ssize_t
strscpy(char *dst, const char *src, size_t dstsz)
{
    if (!dst || !src) {
        SLOG_ERROR("strscpy: invalid args dst=%p src=%p dstsz=%zu",
                   (void *)dst, (const void *)src, dstsz);
        errno = EINVAL;
        return -EINVAL;
    }

    if (dstsz == 0) {
        SLOG_WARN("strscpy: destination size is 0");
        errno = E2BIG;
        return -E2BIG;
    }

    size_t i = 0;
    while (i < dstsz - 1 && i < SAFE_C_MAX_STR) {
        dst[i] = src[i];
        if (src[i] == '\0') {
            return (ssize_t)i;
        }
        i++;
    }

    if (i < SAFE_C_MAX_STR && src[i] == '\0') {
        dst[i] = '\0';
        return (ssize_t)i;
    }

    dst[i] = '\0';
    SLOG_WARN("strscpy: truncated (copied=%zu dstsz=%zu)", i, dstsz);
    errno = E2BIG;
    return -E2BIG;
}

static inline int
safe_strcpy(char *dst, size_t dstsz, const char *src)
{
    if (!dst || !src || dstsz == 0) {
        SLOG_ERROR("safe_strcpy: invalid args dst=%p src=%p dstsz=%zu",
                   (void *)dst, (const void *)src, dstsz);
        return -1;
    }

    ssize_t rc = strscpy(dst, src, dstsz);
    if (rc >= 0) {
        return 0;
    }
    if (rc == -E2BIG) {
        return 1;
    }
    return -1;
}

/**
 * @brief Safely copies up to @p n characters from a source string into a destination buffer.
 *
 * Copies from @p src into @p dst ensuring the destination is always NUL-terminated when
 * @p dstsz is nonzero. The routine checks for invalid arguments, computes the bounded length
 * of the source via strsnlen, and logs errors or warnings through SLOG macros.
 *
 * @param dst    Destination buffer that will receive the copied characters.
 * @param dstsz  Total size of the destination buffer in bytes.
 * @param src    Source string to copy from.
 * @param n      Maximum number of characters to examine from the source.
 *
 * @return 0 on success, 1 if truncation occurred, or -1 on invalid arguments.
 */
static inline int
strsncpy(char *dst, size_t dstsz, const char *src, size_t n)
{
    if (!dst || !src || dstsz == 0) {
        SLOG_ERROR("strsncpy: invalid args dst=%p src=%p dstsz=%zu",
                   (void*)dst, (const void*)src, dstsz);
        return -1;
    }

    size_t slen = strsnlen(src, n);
    int truncated = 0;

    if (slen == n) {
        truncated = 1;
    }

    size_t copy_len;
    if (slen < dstsz) {               // ensures slen <= dstsz - 1
        copy_len = slen;
    } else {
        truncated = 1;
        copy_len = dstsz ? dstsz - 1 : 0;
    }

    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';

    if (truncated) {
        SLOG_WARN("strsncpy: truncated (n=%zu slen=%zu dstsz=%zu)",
                  n, slen, dstsz);
        return 1;
    }

    return 0;
}

static inline int
safe_strncpy(char *dst, size_t dstsz, const char *src, size_t n)
{
    return strsncpy(dst, dstsz, src, n);
}

/**
 * Safely concatenates the NUL-terminated string `src` to the end of `dst`
 * without writing past the bounds of the destination buffer.
 *
 * @param dst   Destination buffer containing an existing NUL-terminated string.
 * @param dstsz Total size in bytes of the destination buffer.
 * @param src   Source NUL-terminated string to append to `dst`.
 *
 * @return 0 on success, 1 if truncation occurred, or -1 if invalid arguments
 *         are detected or the destination buffer is not properly terminated.
 */
static inline int
strscat(char *dst, size_t dstsz, const char *src)
{
    if (!dst || !src || dstsz == 0) {
        SLOG_ERROR("strscat: invalid args dst=%p src=%p dstsz=%zu",
                   (void*)dst, (const void*)src, dstsz);
        return -1;
    }

    size_t dlen = strsnlen(dst, dstsz);
    if (dlen >= dstsz) {
        SLOG_ERROR("strscat: dst not null terminated");
        return -1;
    }

    size_t avail = dstsz - dlen;      // >= 1 at this point
    size_t slen = strsnlen(src, SAFE_C_MAX_STR);
    int truncated = 0;
    if (slen == SAFE_C_MAX_STR) {
        truncated = 1;
        SLOG_WARN("strscat: src length >= SAFE_C_MAX_STR");
    }

    if (!truncated && slen + 1 <= avail) {          // or: if (slen < avail)
        memcpy(dst + dlen, src, slen + 1);
        return 0;
    }
    size_t copy_len = (slen < avail) ? slen : avail - 1;
    memcpy(dst + dlen, src, copy_len);
    dst[dlen + copy_len] = '\0';
    SLOG_WARN("strscat: truncated (dlen=%zu slen=%zu dstsz=%zu)",
              dlen, slen, dstsz);
    return 1;
}

static inline int
safe_strcat(char *dst, size_t dstsz, const char *src)
{
    return strscat(dst, dstsz, src);
}

/**
 * @brief Duplicates a C-string using safe memory utilities.
 *
 * Before copying, the source pointer is validated. If it is null, an error is
 * logged, errno is set to EINVAL, and NULL is returned. The function uses
 * strsnlen to cap the length at SAFE_C_MAX_STR, logging a warning when the
 * source length reaches that limit. Memory is allocated via smalloc, and
 * on success the null-terminated copy is returned; on allocation failure,
 * NULL is returned.
 *
 * @param src Pointer to the null-terminated string to duplicate.
 * @return Pointer to the duplicated string on success, or NULL on failure.
 */
static inline char *
strsdup(const char *src)
{
    if (!src) {
        SLOG_ERROR("strsdup: src is NULL");
        errno = EINVAL;
        return NULL;
    }
    size_t len = strsnlen(src, SAFE_C_MAX_STR);
    if (len == SAFE_C_MAX_STR) {
        SLOG_WARN("strsdup: src length >= SAFE_C_MAX_STR");
    }
    char *p = smalloc(len + 1);
    if (!p) return NULL;
    memcpy(p, src, len);
    p[len] = '\0';
    return p;
}

static inline char *
safe_strdup(const char *src)
{
    return strsdup(src);
}

/**
 * @brief Safely fills a destination buffer with a specified byte value.
 *
 * Ensures the destination pointer is valid and the requested number of bytes
 * does not exceed the buffer size before invoking memset.
 *
 * @param dst    Pointer to the destination buffer.
 * @param dstsz  Total size of the destination buffer in bytes.
 * @param value  The byte value to be written.
 * @param n      Number of bytes to set in the destination buffer.
 *
 * @return 0 on success, or -1 if the inputs are invalid.
 */
static inline int
smemset(void *dst, size_t dstsz, int value, size_t n)
{
    if (!dst || n > dstsz) {
        SLOG_ERROR("smemset: invalid args dst=%p dstsz=%zu n=%zu",
                   dst, dstsz, n);
        return -1;
    }
    unsigned char b = (unsigned char)value;
    memset(dst, b, n);
    return 0;
}

static inline int
safe_memset(void *dst, size_t dstsz, int value, size_t n)
{
    return smemset(dst, dstsz, value, n);
}

/**
 * @brief Safely copies a block of memory from one location to another.
 *
 * Validates that both source and destination pointers are non-null and that the destination buffer
 * is large enough to hold the source data before performing the copy.
 *
 * @param dst Pointer to the destination buffer where data will be copied.
 * @param dstsz Size of the destination buffer in bytes.
 * @param src Pointer to the source data to copy.
 * @param srcsz Number of bytes to copy from the source buffer.
 * @return 0 on success, or -1 if the arguments are invalid (null pointers or insufficient space).
 */
static inline int
smemcpy(void *dst, size_t dstsz, const void *src, size_t srcsz)
{
    if (!dst || !src || dstsz < srcsz) {
        SLOG_ERROR("smemcpy: invalid args dst=%p src=%p dstsz=%zu srcsz=%zu",
                   dst, src, dstsz, srcsz);
        return -1;
    }
    memcpy(dst, src, srcsz);
    return 0;
}

static inline int
safe_memcpy(void *dst, size_t dstsz, const void *src, size_t srcsz)
{
    return smemcpy(dst, dstsz, src, srcsz);
}

/**
 * @brief Safely prints formatted data into a destination buffer.
 *
 * Wraps vsnprintf to validate arguments, detect formatting errors, and log issues.
 *
 * @param dst    Destination buffer to receive the formatted string.
 * @param dstsz  Size of the destination buffer in bytes; must be greater than zero.
 * @param fmt    printf-style format string describing the output.
 * @param ...    Additional arguments matching the format specifiers in @p fmt.
 *
 * @return 0 on success, 1 if the output was truncated, or -1 on invalid arguments or formatting failure.
 */
static inline int ssnprintf(char *dst, size_t dstsz, const char *fmt, ...) SAFE_C_PRINTF_ATTR(3, 4);

static inline int
ssnprintf(char *dst, size_t dstsz, const char *fmt, ...)
{
    if (!dst || !fmt || dstsz == 0) {
        SLOG_ERROR("ssnprintf: invalid args dst=%p fmt=%p dstsz=%zu",
                   (void*)dst, (const void*)fmt, dstsz);
        return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(dst, dstsz, fmt, ap);
    va_end(ap);
    if (r < 0) {
        SLOG_ERROR("ssnprintf: vsnprintf error");
        return -1;
    }
    if ((size_t)r >= dstsz) {
        SLOG_WARN("ssnprintf: truncated (needed=%d dstsz=%zu)", r, dstsz);
        return 1;
    }
    return 0;
}

static inline int safe_snprintf(char *dst, size_t dstsz, const char *fmt, ...) SAFE_C_PRINTF_ATTR(3, 4);

static inline int
safe_snprintf(char *dst, size_t dstsz, const char *fmt, ...)
{
    if (!dst || !fmt || dstsz == 0) {
        SLOG_ERROR("safe_snprintf: invalid args dst=%p fmt=%p dstsz=%zu",
                   (void*)dst, (const void*)fmt, dstsz);
        return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(dst, dstsz, fmt, ap);
    va_end(ap);
    if (r < 0) {
        SLOG_ERROR("safe_snprintf: vsnprintf error");
        return -1;
    }
    if ((size_t)r >= dstsz) {
        SLOG_WARN("safe_snprintf: truncated (needed=%d dstsz=%zu)", r, dstsz);
        return 1;
    }
    return 0;
}

/**
 * @brief Validates that accessing a buffer with the given offset and size remains within bounds.
 *
 * @param offset The starting position within the buffer.
 * @param size The number of bytes to access from the starting offset.
 * @param buf_size The total size of the buffer in bytes.
 * @return 0 if the access is within bounds; -1 if the offset exceeds the buffer size or
 *         if the requested range would overflow the buffer.
 */
static inline int
sbounds_check(size_t offset, size_t size, size_t buf_size)
{
    if (offset > buf_size) {
        SLOG_ERROR("sbounds_check: offset > buf_size (%zu > %zu)",
                   offset, buf_size);
        return -1;
    }
    if (size > buf_size - offset) {
        SLOG_ERROR("sbounds_check: size too large (%zu offset=%zu buf_size=%zu)",
                   size, offset, buf_size);
        return -1;
    }
    return 0;
}

static inline int
safe_bounds_check(size_t offset, size_t size, size_t buf_size)
{
    return sbounds_check(offset, size, buf_size);
}

#endif /* SAFE_C_H */
