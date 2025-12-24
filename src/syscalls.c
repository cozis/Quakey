#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>

#include "syscalls.h"

static void abortf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    abort();
}

static char *osname(OS os)
{
    switch (os) {
    case OS_LINUX:
        return "Linux";
    case OS_WINDOWS:
        return "Windows";
    default:
        break;
    }
    return "???";
}

static void ensure_os(Proc *proc, OS os, const char *func)
{
    assert(os != OS_UNSPECIFIED);

    if (proc->os == OS_UNSPECIFIED) {
        proc->os = os;
    } else {
        if (proc->os != os)
            abortf("Call to %s() not from a %s node\n", func, osname(os));
    }
}

int mock_linux_socket(int domain, int type, int protocol)
{
    if (domain != AF_INET && domain != AF_INET6)
        abortf("Quakey only supports socket() calls with doman=AF_INET or AF_INET6\n");

    if (type != SOCK_STREAM)
        abortf("Quakey only supports socket() calls with type=SOCK_STREAM\n");

    if (protocol != 0)
        abortf("Quakey only supports socket() calls with protocol=0\n");

    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    AddrFamily family;
    switch (domain) {
    case AF_INET:
        family = ADDR_FAMILY_IPV4;
        break;
    case AF_INET6:
        family = ADDR_FAMILY_IPV6;
        break;
    }

    int ret = proc_create_socket(proc, family);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_FULL:
            errno = xxx;
            return -1;
        default:
            break;
        }
        errno = xxx;
        return -1;
    }
    int desc_idx = ret;

    return desc_idx;
}

int mock_linux_close(int fd)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int desc_idx = fd;
    int ret = proc_close(proc, desc_idx, false);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            errno = EBADF;
            return -1;
        default:
            break;
        }
        errno = xxx;
        return -1;
    }

    return 0;
}

static int convert_addr(void *addr, size_t addr_len,
    Addr *converted_addr, uint16_t *converted_port)
{
    int family = ((struct sockaddr*) addr)->sa_family;
    switch (family) {
    case AF_INET:
        {
            if (addr_len != sizeof(struct sockaddr_in)) {
                errno = EINVAL;
                return -1;
            }
            struct sockaddr_in *p = addr;
            converted_addr->family = ADDR_FAMILY_IPV4;
            converted_addr->ipv4   = *(AddrIPv4*) &p->sin_addr;
            *converted_port        = p->sin_port;
        }
        break;
    case AF_INET6:
        {
            if (addr_len != sizeof(struct sockaddr_in6)) {
                errno = EINVAL;
                return -1;
            }
            struct sockaddr_in6 *p = addr;
            converted_addr->family = ADDR_FAMILY_IPV6;
            converted_addr->ipv6   = *(AddrIPv6*) &p->sin6_addr;
            *converted_port        = p->sin_port;
        }
        break;
    default:
        abortf("Quakey only supports the AF_INET and AF_INET6 address families");
    }
    return 0;
}

int mock_linux_bind(int fd, void *addr, size_t addr_len)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    Addr     converted_addr;
    uint16_t converted_port;
    int ret = convert_addr(addr, addr_len, &converted_addr, &converted_port);
    if (ret < 0)
        return ret;

    int desc_idx = fd;
    ret = proc_bind(proc, desc_idx, converted_addr, converted_port);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            errno = EBADF;
            return -1;
        case PROC_ERROR_NOTSOCK:
            errno = ENOTSOCK;
            return -1;
        case PROC_ERROR_CANTBIND:
            errno = EINVAL;
            return -1;
        case PROC_ERROR_BADFAM:
            errno = EAFNOSUPPORT;
            return -1;
        case PROC_ERROR_NOTAVAIL:
            errno = EADDRNOTAVAIL;
            return -1;
        case PROC_ERROR_ADDRUSED:
            errno = EADDRINUSE;
            return -1;
        default:
            break;
        }
        errno = xxx;
        return -1;
    }

    return 0;
}

int mock_linux_listen(int fd, int backlog)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int desc_idx = fd;
    int ret = proc_listen(proc, desc_idx, backlog);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            errno = EBADF;
            return -1;
        case PROC_ERROR_BADARG:
            errno = EINVAL;
            return -1;
        case PROC_ERROR_NOTSOCK:
            errno = ENOTSOCK;
            return -1;
        case PROC_ERROR_ADDRUSED:
            errno = EADDRINUSE;
            return -1;
        }
        errno = xxx;
        return -1;
    }

    return 0;
}

int mock_linux_connect(int fd, void *addr, size_t addr_len)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    Addr     converted_addr;
    uint16_t converted_port;
    int ret = convert_addr(addr, addr_len, &converted_addr, &converted_port);
    if (ret < 0)
        return ret;

    // TODO: connect() operations are only allowed on non-blocking
    //       sockets

    int desc_idx = fd;
    ret = proc_connect(proc, desc_idx, converted_addr, converted_port);
    if (ret < 0) {
        errno = xxx;
        return -1;
    }

    return 0;
}

int mock_linux_open(char *path, int flags, int mode)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int converted_flags = 0; // TODO: convert flags

    int ret = proc_open_file(proc, path, converted_flags);
    if (ret < 0) {
        errno = xxx;
        return -1;
    }
    int desc_idx = ret;

    return desc_idx;
}

int mock_linux_read(int fd, char *dst, int len)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int ret = proc_read(proc, fd, dst, len);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            errno = EBADF;
            return -1;
        case PROC_ERROR_BADARG:
            errno = EINVAL;
            return -1;
        case PROC_ERROR_ISDIR:
            errno = EISDIR;
            return -1;
        case PROC_ERROR_IO:
            errno = EIO;
            return -1;
        }
        errno = xxx;
        return -1;
    }

    return ret;
}

int mock_linux_write(int fd, char *src, int len)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int ret = proc_write(proc, fd, src, len);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            errno = EBADF;
            return -1;
        case PROC_ERROR_IO:
            errno = EIO;
            return -1;
        default:
            break;
        }
        errno = xxx;
        return -1;
    }

    return ret;
}

int mock_linux_recv(int fd, char *dst, int len, int flags)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    if (flags)
        abortf("Call to %s() with non-zero flags\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int ret = proc_recv(proc, fd, dst, len);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            errno = EBADF;
            return -1;
        case PROC_ERROR_NOTSOCK:
            errno = ENOTSOCK;
            return -1;
        case PROC_ERROR_NOTCONN:
            errno = ENOTCONN;
            return -1;
        case PROC_ERROR_RESET:
            errno = ECONNRESET;
            return -1;
        case PROC_ERROR_HANGUP:
            errno = 0;
            return 0;
        default:
            break;
        }
        errno = xxx;
        return -1;
    }

    assert(ret > 0);
    return ret;
}

int mock_linux_send(int fd, char *src, int len, int flags)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    if (flags)
        abortf("Call to %s() with non-zero flags\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int ret = proc_send(proc, fd, src, len);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            errno = EBADF;
            return -1;
        case PROC_ERROR_RESET:
            errno = ECONNRESET;
            return -1;
        case PROC_ERROR_HANGUP:
            errno = EPIPE;
            return -1;
        default:
            break;
        }
        errno = xxx;
        return -1;
    }

    return ret;
}

int mock_linux_accept(int fd, void *addr, socklen_t *addr_len)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_remove(char *path)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_rename(char *oldpath, char *newpath)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_clock_gettime(clockid_t clockid, struct timespec *tp)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_flock(int fd, int op)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_fsync(int fd)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

off_t mock_linux_lseek(int fd, off_t offset, int whence)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_fstat(int fd, struct stat *buf)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_mkstemp(char *path)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

char *mock_linux_realpath(char *path, char *dst)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_mkdir(char *path, mode_t mode)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_fcntl(int fd, int cmd, ...)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

DIR *mock_linux_opendir(char *name)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

struct dirent* mock_linux_readdir(DIR *dirp)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_closedir(DIR *dirp)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_windows_closesocket(SOCKET fd)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_windows_ioctlsocket(SOCKET fd, long cmd, u_long *argp)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

HANDLE mock_windows_CreateFileW(WCHAR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_CloseHandle(HANDLE handle)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_LockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_UnlockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_FlushFileBuffers(HANDLE handle)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

DWORD mock_windows_SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

char *mock_windows__fullpath(char *path, char *dst, int cap)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_windows__mkdir(char *path)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

HANDLE mock_windows_FindFirstFileA(char *lpFileName, WIN32_FIND_DATAA *lpFindFileData)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_FindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA *lpFindFileData)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_FindClose(HANDLE hFindFile)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

BOOL mock_windows_MoveFileExW(WCHAR *lpExistingFileName, WCHAR *lpNewFileName, DWORD dwFlags)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}