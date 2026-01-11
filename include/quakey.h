#ifndef QUAKEY_INCLUDED
#define QUAKEY_INCLUDED

typedef struct {} Quakey;

struct pollfd {
	int fd;
	short events;
	short revents;
};

enum {
    POLLIN  = 1<<0,
    POLLOUT = 1<<1,
    POLLERR = 1<<2,
};

// Function pointers to a simulated program's code
typedef int (*QuakeyInitFunc)(void *state, int argc, char **argv, void **ctxs, struct pollfd *pdata, int pcap, int *pnum, int *timeout);
typedef int (*QuakeyTickFunc)(void *state, void **ctxs, struct pollfd *pdata, int pcap, int *pnum, int *timeout);
typedef int (*QuakeyFreeFunc)(void *state);

typedef enum {
    QUAKEY_LINUX,
    QUAKEY_WINDOWS,
} QuakeyPlatform;

typedef struct {

    // Size of the opaque state struct
    int state_size;

    // Pointers to program code
    QuakeyInitFunc init_func;
    QuakeyTickFunc tick_func;
    QuakeyFreeFunc free_func;

    // Network addresses enabled on the process
    char **addrs;
    int num_addrs;

    // Disk size for the process
    int disk_size;

    // Platform used by this program
    QuakeyPlatform platform;

} QuakeySpawn;

typedef unsigned long long QuakeyUInt64;

// Start a simulation
int quakey_init(Quakey **quakey, QuakeyUInt64 seed);

// Stop a simulation
void quakey_free(Quakey *quakey);

// Add a program to the simulation
void quakey_spawn(Quakey *quakey, QuakeySpawn config, char *arg);

// Schedule and executes one program until it would block, then returns
int quakey_schedule_one(Quakey *quakey);

// Generate a random u64
QuakeyUInt64 quakey_random(void);

////////////////////////////////////////////////////////

#define MAX_PATH 1024

enum {
    NO_ERROR = 0,
    EBADF,
    EINVAL,
    EISDIR,
    EIO,
    ENOTSOCK,
    ENOTCONN,
    EISCONN,
    ECONNRESET,
    EAGAIN,
    EWOULDBLOCK = EAGAIN,
    EPIPE,
    EMFILE,
    EAFNOSUPPORT,
    EADDRINUSE,
    EINPROGRESS,
    ENOENT,
    EADDRNOTAVAIL,
    ENOTEMPTY,
    EEXIST,
    ENOMEM,
    ERANGE,
    ETIMEDOUT,
};

#define INT_MAX (int) ((unsigned int) -1 >> 1)

typedef int            BOOL;
typedef char           CHAR;
typedef short          SHORT;
typedef int            s;
typedef long           LONG;
typedef unsigned char  UCHAR;
typedef unsigned short USHORT;
typedef unsigned int   UINT;
typedef unsigned long  ULONG;
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef float          FLOAT;
typedef unsigned long  DWORD;
typedef long long      LONGLONG;
typedef void *         PVOID;
typedef LONG *         PLONG;
typedef unsigned long  ULONG_PTR;

////////////////////////////////////////////////////////

int *mock_errno_ptr(void);

long mock_strtol(const char *ptr,
    char **restrict end, int base);

////////////////////////////////////////////////////////

enum {
    AF_INET,
    AF_INET6,
};

enum {
    SOCK_STREAM,
};

#define INVALID_SOCKET ((SOCKET) -1)

typedef int SOCKET;

int mock_socket(int domain, int type, int protocol);

int mock_closesocket(SOCKET fd);
int mock_ioctlsocket(SOCKET fd, long cmd, unsigned long *argp);

////////////////////////////////////////////////////////

typedef unsigned short sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

typedef unsigned short in_port_t;
typedef unsigned int   in_addr_t;
struct in_addr { in_addr_t s_addr; };

struct sockaddr_in {
	sa_family_t    sin_family;
	in_port_t      sin_port;
	struct in_addr sin_addr;
	unsigned char  sin_zero[8];
};

struct in6_addr {
	union {
		unsigned char  __s6_addr[16];
		unsigned short __s6_addr16[8];
		unsigned int   __s6_addr32[4];
	} __in6_union;
};
#define s6_addr __in6_union.__s6_addr
#define s6_addr16 __in6_union.__s6_addr16
#define s6_addr32 __in6_union.__s6_addr32

struct sockaddr_in6 {
	sa_family_t     sin6_family;
	in_port_t       sin6_port;
	unsigned int    sin6_flowinfo;
	struct in6_addr sin6_addr;
	unsigned int    sin6_scope_id;
};

#define INADDR_ANY 0

unsigned short htons(unsigned short hostshort);
unsigned short ntohs(unsigned short netshort);
int mock_inet_pton(int af, const char *restrict src, void *restrict dst);
int mock_bind(int fd, void *addr, unsigned long addr_len);

////////////////////////////////////////////////////////

typedef unsigned socklen_t;

enum {
    SO_ERROR,
};

enum {
    SOL_SOCKET,
};

int mock_connect(int fd, void *addr, unsigned long addr_len);
int mock_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);

////////////////////////////////////////////////////////

int mock_listen(int fd, int backlog);
int mock_accept(int fd, void *addr, socklen_t *addr_len);

////////////////////////////////////////////////////////

int mock_recv(int fd, char *dst, int len, int flags);
int mock_send(int fd, char *src, int len, int flags);

////////////////////////////////////////////////////////

enum {
    CLOCK_REALTIME,
    CLOCK_MONOTONIC,
};

typedef int clockid_t;

typedef long long time_t;

struct timespec {
    time_t tv_sec;   /* Seconds */
    long long tv_nsec;  /* Nanoseconds [0, 999'999'999] */
};

int mock_clock_gettime(clockid_t clockid, struct timespec *tp);

////////////////////////////////////////////////////////

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    };
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

BOOL mock_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
BOOL mock_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);

////////////////////////////////////////////////////////

// Linux open() flags
enum {
    O_RDONLY = 0,
    O_WRONLY = 1,
    O_RDWR   = 2,
    O_CREAT  = 0x0040,
    O_EXCL   = 0x0080,
    O_TRUNC  = 0x0200,
    O_APPEND = 0x0400,
    O_NONBLOCK = 0x0800,
};

enum {
    F_GETFL,
    F_SETFL,
};

int mock_open(char *path, int flags, int mode);
int mock_fcntl(int fd, int cmd, int flags);
int mock_close(int fd);

////////////////////////////////////////////////////////

typedef unsigned short WCHAR;
typedef void*          LPVOID;
typedef LPVOID         HANDLE;

// Special handle value for invalid handles
#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)

// CreateFileW dwDesiredAccess flags
#define GENERIC_READ    0x80000000
#define GENERIC_WRITE   0x40000000
#define GENERIC_EXECUTE 0x20000000
#define GENERIC_ALL     0x10000000

// CreateFileW dwShareMode flags
#define FILE_SHARE_READ   0x00000001
#define FILE_SHARE_WRITE  0x00000002
#define FILE_SHARE_DELETE 0x00000004

// CreateFileW dwCreationDisposition values
#define CREATE_NEW        1
#define CREATE_ALWAYS     2
#define OPEN_EXISTING     3
#define OPEN_ALWAYS       4
#define TRUNCATE_EXISTING 5

// CreateFileW dwFlagsAndAttributes flags (common ones)
#define FILE_ATTRIBUTE_NORMAL    0x00000080
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010

// SetFilePointer dwMoveMethod values
#define FILE_BEGIN   0
#define FILE_CURRENT 1
#define FILE_END     2

// SetFilePointer error return value
#define INVALID_SET_FILE_POINTER ((DWORD)-1)

// Windows error codes
#define ERROR_SUCCESS             0
#define ERROR_FILE_NOT_FOUND      2
#define ERROR_PATH_NOT_FOUND      3
#define ERROR_ACCESS_DENIED       5
#define ERROR_INVALID_HANDLE      6
#define ERROR_NOT_ENOUGH_MEMORY   8
#define ERROR_INVALID_PARAMETER   87
#define ERROR_ALREADY_EXISTS      183
#define ERROR_FILE_EXISTS         80
#define ERROR_NEGATIVE_SEEK       131
#define ERROR_NO_MORE_FILES       18

typedef struct _SECURITY_ATTRIBUTES {
    DWORD           nLength;
    LPVOID          lpSecurityDescriptor;
    BOOL            bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

HANDLE mock_CreateFileW(WCHAR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL   mock_CloseHandle(HANDLE handle);

////////////////////////////////////////////////////////

typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union {
        struct {
            DWORD Offset;
            DWORD OffsetHigh;
        };
        PVOID Pointer;
    };
    HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

BOOL mock_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov);
BOOL mock_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov);

int mock_read(int fd, char *dst, int len);
int mock_write(int fd, char *src, int len);

////////////////////////////////////////////////////////

typedef long long off_t;
typedef int mode_t;

// Simplified stat structure for mock
struct stat {
    mode_t   st_mode;     // File mode (type and permissions)
    off_t    st_size;     // Total size, in bytes
    time_t   st_atime;    // Time of last access
    time_t   st_mtime;    // Time of last modification
    time_t   st_ctime;    // Time of last status change
};

// File type mode bits
#define S_IFMT   0170000  // Mask for file type
#define S_IFREG  0100000  // Regular file
#define S_IFDIR  0040000  // Directory

#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)

int mock_fstat(int fd, struct stat *buf);

BOOL mock_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf);

////////////////////////////////////////////////////////

// lseek whence values
enum {
    SEEK_SET = 0,
    SEEK_CUR = 1,
    SEEK_END = 2,
};

off_t mock_lseek(int fd, off_t offset, int whence);

DWORD mock_SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

////////////////////////////////////////////////////////

int  mock_flock(int fd, int op);

BOOL mock_LockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh);
BOOL mock_UnlockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh);

////////////////////////////////////////////////////////

int  mock_fsync(int fd);
BOOL mock_FlushFileBuffers(HANDLE handle);

////////////////////////////////////////////////////////

int mock_mkstemp(char *path);

int mock_mkdir(char *path, mode_t mode);
int mock__mkdir(char *path);

int mock_remove(char *path);

int mock_rename(char *oldpath, char *newpath);

// MoveFileExW dwFlags flags
#define MOVEFILE_REPLACE_EXISTING      0x00000001
#define MOVEFILE_COPY_ALLOWED          0x00000002
#define MOVEFILE_DELAY_UNTIL_REBOOT    0x00000004
#define MOVEFILE_WRITE_THROUGH         0x00000008

BOOL mock_MoveFileExW(WCHAR *lpExistingFileName, WCHAR *lpNewFileName, DWORD dwFlags);

char *mock_realpath(char *path, char *dst);
char *mock__fullpath(char *path, char *dst, int cap);

////////////////////////////////////////////////////////

// File type values for d_type field
#define DT_UNKNOWN  0
#define DT_REG      8   // Regular file
#define DT_DIR      4   // Directory

struct dirent {
    unsigned char d_type;       // File type
    char          d_name[256];  // Filename
};

typedef struct {
    int           fd;           // Descriptor index
    struct dirent entry;        // Current entry (returned by readdir)
} DIR;

DIR *mock_opendir(char *name);

struct dirent* mock_readdir(DIR *dirp);

int mock_closedir(DIR *dirp);

////////////////////////////////////////////////////////

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef struct _WIN32_FIND_DATAA {
    DWORD    dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
    DWORD    dwReserved0;
    DWORD    dwReserved1;
    CHAR     cFileName[MAX_PATH];
    CHAR     cAlternateFileName[14];
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;

HANDLE mock_FindFirstFileA(char *lpFileName, WIN32_FIND_DATAA *lpFindFileData);
BOOL   mock_FindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA *lpFindFileData);
BOOL   mock_FindClose(HANDLE hFindFile);

#ifdef QUAKEY_ENABLE_MOCKS
#define errno (*mock_errno_ptr())
#define strtol           mock_strtol
#define socket           mock_socket
#define closesocket      mock_closesocket
#define ioctlsocket      mock_ioctlsocket
#define inet_pton        mock_inet_pton
#define bind             mock_bind
#define connect          mock_connect
#define getsockopt       mock_getsockopt
#define listen           mock_listen
#define accept           mock_accept
#define recv             mock_recv
#define send             mock_send
#define clock_gettime    mock_clock_gettime
#define QueryPerformanceCounter   mock_QueryPerformanceCounter
#define QueryPerformanceFrequency mock_QueryPerformanceFrequency
#define open             mock_open
#define fcntl            mock_fcntl
#define close            mock_close
#define CreateFileW      mock_CreateFileW
#define CloseHandle      mock_CloseHandle
#define ReadFile         mock_ReadFile
#define WriteFile        mock_WriteFile
#define read             mock_read
#define write            mock_write
#define fstat            mock_fstat
#define GetFileSizeEx    mock_GetFileSizeEx
#define lseek            mock_lseek
#define SetFilePointer   mock_SetFilePointer
#define flock            mock_flock
#define LockFile         mock_LockFile
#define UnlockFile       mock_UnlockFile
#define fsync            mock_fsync
#define FlushFileBuffers mock_FlushFileBuffers
#define mkstemp          mock_mkstemp
#define mkdir            mock_mkdir
#define _mkdir           mock__mkdir
#define remove           mock_remove
#define rename           mock_rename
#define MoveFileExW      mock_MoveFileExW
#define realpath         mock_realpath
#define _fullpath        mock__fullpath
#define opendir          mock_opendir
#define readdir          mock_readdir
#define closedir         mock_closedir
#define FindFirstFileA   mock_FindFirstFileA
#define FindNextFileA    mock_FindNextFileA
#define FindClose        mock_FindClose
#endif

#include <stddef.h>

typedef struct {} FILE;

#define stdin  ((void*) 0)
#define stdout ((void*) 1)
#define stderr ((void*) 2)

#define va_list          __builtin_va_list
#define va_start(v, l)   __builtin_va_start(v, l)
#define va_end(v)        __builtin_va_end(v)
#define va_arg(v, T)     __builtin_va_arg(v, T)
#define va_copy(d, s)    __builtin_va_copy(d, s)

int vfprintf(FILE *stream, const char *restrict fmt, va_list args);
int fprintf(FILE *stream, const char *restrict fmt, ...);
int printf(const char *restrict fmt, ...);
int puts(const char *s);

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
int fclose(FILE *stream);
char *fgets(char *s, int n, void *stream);
char *strstr(const char *h, const char *n);
long strtol(const char *s, char **end, int base);

// These are implemented by malloc.c, not libc.c
void *malloc(size_t size);
void* realloc(void* ptr, size_t size);
void free(void *p);

#endif // QUAKEY_INCLUDED