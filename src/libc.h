#ifndef LIBC_INCLUDED
#define LIBC_INCLUDED

#include <stddef.h>

int   memcmp(const void *p1, const void *p2, size_t n);
void *memcpy(void *p1, const void *p2, size_t n);
void *memmove(void *p1, const void *p2, size_t n);
void *memset(void *p, int ch, size_t n);
size_t strlen(const char *s);

void __assert_fail(const char *assertion, const char *file,
    unsigned int line, const char *function);

size_t strcspn(const char *s, const char *reject);
size_t strspn(const char *s, const char *accept);
char *strchr(const char *s, int c);
int __popcountdi2(long long a);

void *mmap(void *addr, size_t len, int prot, int flags, int fd, long offset);
int munmap(void *addr, size_t len);
int madvise(void *addr, size_t len, int advice);
int prctl(int option, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5);
long sysconf(int name);

int *__errno_location(void);

int pthread_key_create(unsigned *key, void (*destructor)(void *));
int pthread_key_delete(unsigned key);
int pthread_setspecific(unsigned key, const void *value);
void *pthread_getspecific(unsigned key);

void *fopen(const char *path, const char *mode);
int fclose(void *stream);
char *fgets(char *s, int n, void *stream);
char *strstr(const char *h, const char *n);
long strtol(const char *s, char **end, int base);

#endif // LIBC_INCLUDED