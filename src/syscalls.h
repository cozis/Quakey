#ifndef SYSCALLS_INCLUDED
#define SYSCALLS_INCLUDED

#include <stddef.h>
#include <stdint.h>

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
    EPIPE,
    EMFILE,
    EAFNOSUPPORT,
    EADDRINUSE,
    EINPROGRESS,
    ENOENT,
    EADDRNOTAVAIL,
    ENOTEMPTY,
    EEXIST,
};

typedef int            BOOL;
typedef char           CHAR;
typedef short          SHORT;
typedef int            INT;
typedef long           LONG;
typedef unsigned char  UCHAR;
typedef unsigned short USHORT;
typedef unsigned int   UINT;
typedef unsigned long  ULONG;
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef float          FLOAT;
typedef unsigned long  DWORD;
typedef int64_t        LONGLONG;
typedef void *         PVOID;
typedef LONG *         PLONG;
typedef unsigned long  ULONG_PTR;

////////////////////////////////////////////////////////

#define errno (*mock_errno_ptr())
int *mock_errno_ptr(void);

////////////////////////////////////////////////////////

enum {
    AF_INET,
    AF_INET6,
};

enum {
    SOCK_STREAM,
};

typedef int SOCKET;

int mock_linux_socket(int domain, int type, int protocol);

int mock_windows_closesocket(SOCKET fd);
int mock_windows_ioctlsocket(SOCKET fd, long cmd, unsigned long *argp);

////////////////////////////////////////////////////////

typedef unsigned short sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;
struct in_addr { in_addr_t s_addr; };

struct sockaddr_in {
	sa_family_t sin_family;
	in_port_t sin_port;
	struct in_addr sin_addr;
	uint8_t sin_zero[8];
};

struct in6_addr {
	union {
		uint8_t __s6_addr[16];
		uint16_t __s6_addr16[8];
		uint32_t __s6_addr32[4];
	} __in6_union;
};
#define s6_addr __in6_union.__s6_addr
#define s6_addr16 __in6_union.__s6_addr16
#define s6_addr32 __in6_union.__s6_addr32

struct sockaddr_in6 {
	sa_family_t     sin6_family;
	in_port_t       sin6_port;
	uint32_t        sin6_flowinfo;
	struct in6_addr sin6_addr;
	uint32_t        sin6_scope_id;
};

int mock_linux_bind(int fd, void *addr, size_t addr_len);

////////////////////////////////////////////////////////

typedef unsigned socklen_t;

int mock_linux_connect(int fd, void *addr, size_t addr_len);
int mock_linux_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);

////////////////////////////////////////////////////////

int mock_linux_listen(int fd, int backlog);
int mock_linux_accept(int fd, void *addr, socklen_t *addr_len);

////////////////////////////////////////////////////////

int mock_linux_recv(int fd, char *dst, int len, int flags);
int mock_linux_send(int fd, char *src, int len, int flags);

////////////////////////////////////////////////////////

enum {
    CLOCK_REALTIME,
    CLOCK_MONOTONIC,
};

typedef int clockid_t;

typedef int64_t time_t;

struct timespec {
    time_t  tv_sec;   /* Seconds */
    int64_t tv_nsec;  /* Nanoseconds [0, 999'999'999] */
};

int mock_linux_clock_gettime(clockid_t clockid, struct timespec *tp);

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

BOOL mock_windows_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
BOOL mock_windows_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);

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

int mock_linux_open(char *path, int flags, int mode);
int mock_linux_fcntl(int fd, int cmd, ...);
int mock_linux_close(int fd);

////////////////////////////////////////////////////////

typedef wchar_t WCHAR;
typedef void*   LPVOID;
typedef LPVOID  HANDLE;

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
#define FILE_ATTRIBUTE_NORMAL 0x00000080

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

typedef struct _SECURITY_ATTRIBUTES {
    DWORD           nLength;
    LPVOID          lpSecurityDescriptor;
    BOOL            bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

HANDLE mock_windows_CreateFileW(WCHAR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL   mock_windows_CloseHandle(HANDLE handle);

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

BOOL mock_windows_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov);
BOOL mock_windows_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov);

int mock_linux_read(int fd, char *dst, int len);
int mock_linux_write(int fd, char *src, int len);

////////////////////////////////////////////////////////

typedef int64_t off_t;
typedef int     mode_t;

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

int mock_linux_fstat(int fd, struct stat *buf);

BOOL mock_windows_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf);

////////////////////////////////////////////////////////

// lseek whence values
enum {
    SEEK_SET = 0,
    SEEK_CUR = 1,
    SEEK_END = 2,
};

off_t mock_linux_lseek(int fd, off_t offset, int whence);

DWORD mock_windows_SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

////////////////////////////////////////////////////////

int  mock_linux_flock(int fd, int op);

BOOL mock_windows_LockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh);
BOOL mock_windows_UnlockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh);

////////////////////////////////////////////////////////

int  mock_linux_fsync(int fd);
BOOL mock_windows_FlushFileBuffers(HANDLE handle);

////////////////////////////////////////////////////////

int mock_linux_mkstemp(char *path);

int mock_linux_mkdir(char *path, mode_t mode);
int mock_windows__mkdir(char *path);

int mock_linux_remove(char *path);

int  mock_linux_rename(char *oldpath, char *newpath);
BOOL mock_windows_MoveFileExW(WCHAR *lpExistingFileName, WCHAR *lpNewFileName, DWORD dwFlags);

char *mock_linux_realpath(char *path, char *dst);
char *mock_windows__fullpath(char *path, char *dst, int cap);

////////////////////////////////////////////////////////

typedef struct {} DIR;

struct dirent {
    // TODO
};

DIR *mock_linux_opendir(char *name);

struct dirent* mock_linux_readdir(DIR *dirp);

int mock_linux_closedir(DIR *dirp);

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

HANDLE mock_windows_FindFirstFileA(char *lpFileName, WIN32_FIND_DATAA *lpFindFileData);
BOOL   mock_windows_FindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA *lpFindFileData);
BOOL   mock_windows_FindClose(HANDLE hFindFile);

////////////////////////////////////////////////////////
#endif // SYSCALLS_INCLUDED
