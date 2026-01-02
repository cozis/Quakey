#include "libc.h"

int memcmp(const void *p1, const void *p2, size_t n)
{
    return __builtin_memcmp(p1, p2, n);
}

void *memcpy(void *p1, const void *p2, size_t n)
{
    return __builtin_memcpy(p1, p2, n);
}

void *memmove(void *p1, const void *p2, size_t n)
{
    return __builtin_memmove(p1, p2, n);
}

void *memset(void *p, int ch, size_t n)
{
    return __builtin_memset(p, ch, n);
}

size_t strlen(const char *s)
{
    return __builtin_strlen(s);
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
char *strchr(const char *s, int c)
{
    while (*s) {
        if (*s == (char)c)
            return (char *)s;
        s++;
    }
    return (c == '\0') ? (char *)s : NULL;
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