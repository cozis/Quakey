#ifndef SYSCALLS_INCLUDED
#define SYSCALLS_INCLUDED

#include <errno.h>

#include "proc.h"

enum {
    AF_INET,
    AF_INET6,
};

enum {
    SOCK_STREAM,
};

enum {
    POLLIN  = 1<<0,
    POLLOUT = 1<<1,
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
typedef LONG *         PLONG;
typedef unsigned long  ULONG_PTR;
typedef void *LPVOID;
typedef LPVOID HANDLE;
typedef wchar_t WCHAR;

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

typedef struct _SECURITY_ATTRIBUTES {
    DWORD           nLength;
    LPVOID          lpSecurityDescriptor;
    BOOL            bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

typedef struct {} DIR;
typedef int SOCKET;

typedef unsigned socklen_t;

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

struct stat;

int    mock_linux_socket(int domain, int type, int protocol);
int    mock_linux_close(int fd);
int    mock_linux_bind(int fd, void *addr, size_t addr_len);
int    mock_linux_listen(int fd, int backlog);
int    mock_linux_connect(int fd, void *addr, size_t addr_len);
int    mock_linux_open(char *path, int flags, int mode);
int    mock_linux_read(int fd, char *dst, int len);
int    mock_linux_write(int fd, char *src, int len);
int    mock_linux_recv(int fd, char *dst, int len, int flags);
int    mock_linux_send(int fd, char *src, int len, int flags);
int    mock_linux_accept(int fd, void *addr, socklen_t *addr_len);
int    mock_linux_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
int    mock_linux_remove(char *path);
int    mock_linux_rename(char *oldpath, char *newpath);
int    mock_linux_clock_gettime(clockid_t clockid, struct timespec *tp);
int    mock_linux_flock(int fd, int op);
int    mock_linux_fsync(int fd);
off_t  mock_linux_lseek(int fd, off_t offset, int whence);
int    mock_linux_fstat(int fd, struct stat *buf);
int    mock_linux_mkstemp(char *path);
char*  mock_linux_realpath(char *path, char *dst);
int    mock_linux_mkdir(char *path, mode_t mode);
int    mock_linux_fcntl(int fd, int cmd, ...);
DIR*   mock_linux_opendir(char *name);
struct dirent* mock_linux_readdir(DIR *dirp);
int    mock_linux_closedir(DIR *dirp);

int    mock_windows_closesocket(SOCKET fd);
int    mock_windows_ioctlsocket(SOCKET fd, long cmd, u_long *argp);
HANDLE mock_windows_CreateFileW(WCHAR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL   mock_windows_CloseHandle(HANDLE handle);
BOOL   mock_windows_LockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh);
BOOL   mock_windows_UnlockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh);
BOOL   mock_windows_FlushFileBuffers(HANDLE handle);
BOOL   mock_windows_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov);
BOOL   mock_windows_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov);
DWORD  mock_windows_SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
BOOL   mock_windows_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf);
BOOL   mock_windows_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
BOOL   mock_windows_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
char*  mock_windows__fullpath(char *path, char *dst, int cap);
int    mock_windows__mkdir(char *path);
HANDLE mock_windows_FindFirstFileA(char *lpFileName, WIN32_FIND_DATAA *lpFindFileData);
BOOL   mock_windows_FindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA *lpFindFileData);
BOOL   mock_windows_FindClose(HANDLE hFindFile);
BOOL   mock_windows_MoveFileExW(WCHAR *lpExistingFileName, WCHAR *lpNewFileName, DWORD dwFlags);

#endif // SYSCALLS_INCLUDED
