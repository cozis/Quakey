#ifndef LIBC_INCLUDED
#define LIBC_INCLUDED

#include <stddef.h>

void *memcpy(void *restrict dest, const void *restrict src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
size_t strnlen(const char *s, size_t maxlen);
char *strcpy(char *restrict dest, const char *restrict src);
char *strncpy(char *restrict dest, const char *restrict src, size_t n);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
void *memchr(const void *s, int c, size_t n);
char *strcat(char *restrict dest, const char *restrict src);
char *strncat(char *restrict dest, const char *restrict src, size_t n);

void __assert_fail(const char *assertion, const char *file,
    unsigned int line, const char *function);

size_t strcspn(const char *s, const char *reject);
size_t strspn(const char *s, const char *accept);
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