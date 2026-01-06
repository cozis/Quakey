#include "libc.h"

#define STB_SPRINTF_IMPLEMENTATION
#include "stb_sprintf.h"

#ifdef _WIN32
int WriteFile(void *handle,
    char *src,
    unsigned long len,
    unsigned long *num,
    void *ov);
void *GetStdHandle(unsigned long nStdHandle);
#endif

int printf(const char *restrict fmt, ...)
{
    long ret;
    char buf[1<<10];
    va_list args;
    va_start(args, fmt);
    ret = stbsp_vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

#ifdef _WIN32
    WriteFile(GetStdHandle((unsigned long) -11), buf, ret, NULL, NULL);
#else
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (1),
            "D" (1),
            "S" (args),
            "d" (ret)
        : "rcx", "r11", "memory"
    );
    (void) ret;
#endif

    return ret;
}

int puts(const char *s)
{
    long ret;
    size_t len = strlen(s);

#ifdef _WIN32
    WriteFile(GetStdHandle((unsigned long) -11), (char *)s, len, NULL, NULL);
    WriteFile(GetStdHandle((unsigned long) -11), "\n", 1, NULL, NULL);
#else
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (1),
            "D" (1),
            "S" (s),
            "d" (len)
        : "rcx", "r11", "memory"
    );
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (1),
            "D" (1),
            "S" ("\n"),
            "d" (1)
        : "rcx", "r11", "memory"
    );
#endif

    return (int)len + 1;
}

void *memcpy(void *restrict dest, const void *restrict src, size_t n)
{
    unsigned char *d = dest;
    const unsigned char *s = src;

    /* Word-at-a-time copy when aligned */
    if (((unsigned long)d | (unsigned long)s) % sizeof(unsigned long) == 0) {
        while (n >= sizeof(unsigned long)) {
            *(unsigned long *)d = *(const unsigned long *)s;
            d += sizeof(unsigned long);
            s += sizeof(unsigned long);
            n -= sizeof(unsigned long);
        }
    }

    /* Byte-by-byte for remainder or unaligned */
    while (n--)
        *d++ = *s++;

    return dest;
}

void *memmove(void *dest, const void *src, size_t n)
{
    unsigned char *d = dest;
    const unsigned char *s = src;

    if (d == s || n == 0)
        return dest;

    /* Non-overlapping or dest < src: forward copy */
    if (d < s || d >= s + n) {
        while (n--)
            *d++ = *s++;
    } else {
        /* Overlapping with dest > src: backward copy */
        d += n;
        s += n;
        while (n--)
            *--d = *--s;
    }

    return dest;
}

void *memset(void *s, int c, size_t n)
{
    unsigned char *p = s;
    unsigned char val = (unsigned char)c;

    /* Word-at-a-time when aligned */
    if ((unsigned long)p % sizeof(unsigned long) == 0 && n >= sizeof(unsigned long)) {
        unsigned long word = val;
        word |= word << 8;
        word |= word << 16;
        if (sizeof(unsigned long) > 4)
            word |= word << 32;
        while (n >= sizeof(unsigned long)) {
            *(unsigned long *)p = word;
            p += sizeof(unsigned long);
            n -= sizeof(unsigned long);
        }
    }

    /* Byte-by-byte for remainder or unaligned */
    while (n--)
        *p++ = val;

    return s;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;

    while (n--) {
        if (*p1 != *p2)
            return *p1 - *p2;
        p1++;
        p2++;
    }

    return 0;
}

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p)
        p++;
    return p - s;
}

size_t strnlen(const char *s, size_t maxlen)
{
    const char *p = s;
    while (maxlen-- && *p)
        p++;
    return p - s;
}

char *strcpy(char *restrict dest, const char *restrict src)
{
    char *ret = dest;
    while ((*dest++ = *src++))
        ;
    return ret;
}

char *strncpy(char *restrict dest, const char *restrict src, size_t n)
{
    char *ret = dest;

    while (n && (*dest++ = *src++))
        n--;

    /* Pad with zeros if src was shorter */
    while (n--)
        *dest++ = '\0';

    return ret;
}

int strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    if (n == 0)
        return 0;

    while (--n && *s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

char *strchr(const char *s, int c)
{
    while (*s) {
        if (*s == (char)c)
            return (char *)s;
        s++;
    }
    return (c == '\0') ? (char *)s : NULL;
}

char *strrchr(const char *s, int c)
{
    const char *last = NULL;

    while (*s) {
        if (*s == (char)c)
            last = s;
        s++;
    }
    return (c == '\0') ? (char *)s : (char *)last;
}

void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = s;
    unsigned char val = (unsigned char)c;

    while (n--) {
        if (*p == val)
            return (void *)p;
        p++;
    }
    return NULL;
}

char *strcat(char *restrict dest, const char *restrict src)
{
    char *ret = dest;

    while (*dest)
        dest++;

    while ((*dest++ = *src++))
        ;

    return ret;
}

char *strncat(char *restrict dest, const char *restrict src, size_t n)
{
    char *ret = dest;

    while (*dest)
        dest++;

    while (n-- && *src)
        *dest++ = *src++;

    *dest = '\0';
    return ret;
}

void __assert_fail(const char *assertion,
                   const char *file,
                   unsigned int line,
                   const char *function)
{
    (void) assertion;
    (void) file;
    (void) line;
    (void) function;
    __builtin_trap();
}

// TODO: test this
size_t strcspn(const char *s, const char *reject)
{
    size_t count = 0;
    while (*s) {
        for (const char *r = reject; *r; r++) {
            if (*s == *r)
                return count;
        }
        s++;
        count++;
    }
    return count;
}

// TODO: test this
size_t strspn(const char *s, const char *accept)
{
    size_t count = 0;
    while (*s) {
        const char *a = accept;
        while (*a && *a != *s)
            a++;
        if (!*a)
            return count;
        s++;
        count++;
    }
    return count;
}

// TODO: test this
// Compiler builtin for popcount - provide if needed
int __popcountdi2(long long a)
{
    int count = 0;
    unsigned long long u = (unsigned long long)a;
    while (u) {
        count += u & 1;
        u >>= 1;
    }
    return count;
}

// Syscall numbers for x86-64 Linux
#define SYS_mmap     9
#define SYS_munmap   11
#define SYS_madvise  28
#define SYS_prctl    157
#define SYS_sysconf  // Not a syscall - use sysinfo or hardcode

static long syscall1(long n, long a1)
{
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static long syscall2(long n, long a1, long a2)
{
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return ret;
}

static long syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    register long r10 __asm__("r10") = a3;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(r10) : "rcx", "r11", "memory");
    return ret;
}

static long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile("syscall" : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, long offset)
{
    return (void*) syscall6(SYS_mmap, (long)addr, len, prot, flags, fd, offset);
}

int munmap(void *addr, size_t len)
{
    return syscall2(SYS_munmap, (long) addr, len);
}

int madvise(void *addr, size_t len, int advice)
{
    return syscall3(SYS_madvise, (long) addr, len, advice);
}

int prctl(int option, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5)
{
    return syscall6(SYS_prctl, option, a2, a3, a4, a5, 0);
}

// Hardcode page size - avoids sysconf
long sysconf(int name)
{
    if (name == 30) // _SC_PAGESIZE
        return 4096;
    return -1;
}

// Stub errno
static int errno_val;
int *__errno_location(void)
{
    return &errno_val;
}

// Stub pthread functions (single-threaded)
static void *tls_value;
int pthread_key_create(unsigned *key, void (*destructor)(void *))
{
    (void) destructor;
    *key = 0;
    return 0;
}

int pthread_key_delete(unsigned key)
{
    (void) key;
    return 0;
}

int pthread_setspecific(unsigned key, const void *value)
{
    (void) key;
    tls_value = (void *)value;
    return 0;
}

void *pthread_getspecific(unsigned key)
{
    (void) key;
    return tls_value;
}

// Stub file functions - rpmalloc uses these to read /proc/meminfo
// Just make them fail gracefully
void *fopen(const char *path, const char *mode)
{
    (void) path;
    (void) mode;
    return NULL;
}

int fclose(void *stream)
{
    (void) stream;
    return 0;
}

char *fgets(char *s, int n, void *stream)
{
    (void) s;
    (void) n;
    (void) stream;
    return NULL;
}

// TODO: this should be implemented
char *strstr(const char *h, const char *n)
{
    (void) h;
    (void) n;
    return NULL;
}

long strtol(const char *s, char **end, int base)
{
    (void) s;
    (void) end;
    (void) base;
    return 0;
}