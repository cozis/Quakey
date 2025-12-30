#include "syscalls.h"
#include "proc.h"

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

static void abortf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    __builtin_trap();
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

int *mock_errno_ptr(void)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    return proc_errno_ptr(proc);
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
            *proc_errno_ptr(proc) = EMFILE;
            return -1;
        default:
            break;
        }
        *proc_errno_ptr(proc) = EIO;
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
            *proc_errno_ptr(proc) = EBADF;
            return -1;
        default:
            break;
        }
        *proc_errno_ptr(proc) = EIO;
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
            if (addr_len != sizeof(struct sockaddr_in))
                return -1;
            struct sockaddr_in *p = addr;
            converted_addr->family = ADDR_FAMILY_IPV4;
            converted_addr->ipv4   = *(AddrIPv4*) &p->sin_addr;
            *converted_port        = p->sin_port;
        }
        break;
    case AF_INET6:
        {
            if (addr_len != sizeof(struct sockaddr_in6))
                return -1;
            struct sockaddr_in6 *p = addr;
            converted_addr->family = ADDR_FAMILY_IPV6;
            converted_addr->ipv6   = *(AddrIPv6*) &p->sin6_addr;
            *converted_port        = p->sin6_port;
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
    if (ret < 0) {
        *proc_errno_ptr(proc) = EINVAL;
        return ret;
    }

    int desc_idx = fd;
    ret = proc_bind(proc, desc_idx, converted_addr, converted_port);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            *proc_errno_ptr(proc) = EBADF;
            return -1;
        case PROC_ERROR_NOTSOCK:
            *proc_errno_ptr(proc) = ENOTSOCK;
            return -1;
        case PROC_ERROR_CANTBIND:
            *proc_errno_ptr(proc) = EINVAL;
            return -1;
        case PROC_ERROR_BADFAM:
            *proc_errno_ptr(proc) = EAFNOSUPPORT;
            return -1;
        case PROC_ERROR_NOTAVAIL:
            *proc_errno_ptr(proc) = EADDRNOTAVAIL;
            return -1;
        case PROC_ERROR_ADDRUSED:
            *proc_errno_ptr(proc) = EADDRINUSE;
            return -1;
        default:
            break;
        }
        *proc_errno_ptr(proc) = EIO;
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
            *proc_errno_ptr(proc) = EBADF;
            return -1;
        case PROC_ERROR_BADARG:
            *proc_errno_ptr(proc) = EINVAL;
            return -1;
        case PROC_ERROR_NOTSOCK:
            *proc_errno_ptr(proc) = ENOTSOCK;
            return -1;
        case PROC_ERROR_ADDRUSED:
            *proc_errno_ptr(proc) = EADDRINUSE;
            return -1;
        }
        *proc_errno_ptr(proc) = EIO;
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
    if (ret < 0) {
        *proc_errno_ptr(proc) = EINVAL;
        return -1;
    }

    // TODO: connect() operations are only allowed on non-blocking
    //       sockets

    int desc_idx = fd;
    ret = proc_connect(proc, desc_idx, converted_addr, converted_port);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            *proc_errno_ptr(proc) = EBADF;
            return -1;
        case PROC_ERROR_NOTSOCK:
            *proc_errno_ptr(proc) = ENOTSOCK;
            return -1;
        case PROC_ERROR_BADARG:
            *proc_errno_ptr(proc) = EISCONN;
            return -1;
        case PROC_ERROR_ADDRUSED:
            *proc_errno_ptr(proc) = EADDRINUSE;
            return -1;
        default:
            break;
        }
        *proc_errno_ptr(proc) = EINPROGRESS;
        return -1;
    }

    *proc_errno_ptr(proc) = EINPROGRESS;
    return -1;
}

static int convert_linux_open_flags_to_lfs(int flags)
{
    int lfs_flags = 0;

    // Convert access mode (lowest 2 bits)
    // Linux: O_RDONLY=0, O_WRONLY=1, O_RDWR=2
    // LFS:   LFS_O_RDONLY=1, LFS_O_WRONLY=2, LFS_O_RDWR=3
    int access_mode = flags & 3;
    lfs_flags = access_mode + 1;

    // Convert other flags
    if (flags & O_CREAT)
        lfs_flags |= LFS_O_CREAT;
    if (flags & O_EXCL)
        lfs_flags |= LFS_O_EXCL;
    if (flags & O_TRUNC)
        lfs_flags |= LFS_O_TRUNC;
    if (flags & O_APPEND)
        lfs_flags |= LFS_O_APPEND;

    return lfs_flags;
}

int mock_linux_open(char *path, int flags, int mode)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int converted_flags = convert_linux_open_flags_to_lfs(flags);

    int ret = proc_open_file(proc, path, converted_flags);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_FULL:
            *proc_errno_ptr(proc) = EMFILE;
            return -1;
        case PROC_ERROR_IO:
            *proc_errno_ptr(proc) = EIO;
            return -1;
        default:
            break;
        }
        *proc_errno_ptr(proc) = ENOENT;
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
            *proc_errno_ptr(proc) = EBADF;
            return -1;
        case PROC_ERROR_BADARG:
            *proc_errno_ptr(proc) = EINVAL;
            return -1;
        case PROC_ERROR_ISDIR:
            *proc_errno_ptr(proc) = EISDIR;
            return -1;
        case PROC_ERROR_IO:
            *proc_errno_ptr(proc) = EIO;
            return -1;
        }
        *proc_errno_ptr(proc) = EIO;
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
            *proc_errno_ptr(proc) = EBADF;
            return -1;
        case PROC_ERROR_IO:
            *proc_errno_ptr(proc) = EIO;
            return -1;
        default:
            break;
        }
        *proc_errno_ptr(proc) = EIO;
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
            *proc_errno_ptr(proc) = EBADF;
            return -1;
        case PROC_ERROR_NOTSOCK:
            *proc_errno_ptr(proc) = ENOTSOCK;
            return -1;
        case PROC_ERROR_NOTCONN:
            *proc_errno_ptr(proc) = ENOTCONN;
            return -1;
        case PROC_ERROR_RESET:
            *proc_errno_ptr(proc) = ECONNRESET;
            return -1;
        case PROC_ERROR_HANGUP:
            *proc_errno_ptr(proc) = 0;
            return 0;
        case PROC_ERROR_WOULDBLOCK:
            *proc_errno_ptr(proc) = EAGAIN;
            return -1;
        default:
            break;
        }
        *proc_errno_ptr(proc) = EIO;
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
            *proc_errno_ptr(proc) = EBADF;
            return -1;
        case PROC_ERROR_RESET:
            *proc_errno_ptr(proc) = ECONNRESET;
            return -1;
        case PROC_ERROR_HANGUP:
            *proc_errno_ptr(proc) = EPIPE;
            return -1;
        case PROC_ERROR_WOULDBLOCK:
            *proc_errno_ptr(proc) = EAGAIN;
            return -1;
        default:
            break;
        }
        *proc_errno_ptr(proc) = EIO;
        return -1;
    }

    return ret;
}

int mock_linux_accept(int fd, void *addr, socklen_t *addr_len)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    Addr     peer_addr;
    uint16_t peer_port;
    int ret = proc_accept(proc, fd, &peer_addr, &peer_port);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
            *proc_errno_ptr(proc) = EBADF;
            return -1;
        case PROC_ERROR_NOTSOCK:
            *proc_errno_ptr(proc) = ENOTSOCK;
            return -1;
        case PROC_ERROR_BADARG:
            *proc_errno_ptr(proc) = EINVAL;
            return -1;
        case PROC_ERROR_FULL:
            *proc_errno_ptr(proc) = EMFILE;
            return -1;
        case PROC_ERROR_WOULDBLOCK:
            *proc_errno_ptr(proc) = EAGAIN;
            return -1;
        default:
            break;
        }
        *proc_errno_ptr(proc) = EIO;
        return -1;
    }
    int new_fd = ret;

    // Fill in the address if provided
    if (addr != NULL && addr_len != NULL) {
        if (peer_addr.family == ADDR_FAMILY_IPV4) {
            struct sockaddr_in *sin = addr;
            if (*addr_len >= sizeof(struct sockaddr_in)) {
                sin->sin_family = AF_INET;
                sin->sin_port = peer_port;
                memcpy(&sin->sin_addr, &peer_addr.ipv4, sizeof(peer_addr.ipv4));
                *addr_len = sizeof(struct sockaddr_in);
            }
        } else {
            struct sockaddr_in6 *sin6 = addr;
            if (*addr_len >= sizeof(struct sockaddr_in6)) {
                sin6->sin6_family = AF_INET6;
                sin6->sin6_port = peer_port;
                memcpy(&sin6->sin6_addr, &peer_addr.ipv6, sizeof(peer_addr.ipv6));
                *addr_len = sizeof(struct sockaddr_in6);
            }
        }
    }

    return new_fd;
}

int mock_linux_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_remove(char *path)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int ret = proc_remove(proc, path);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_NOENT:
            *proc_errno_ptr(proc) = ENOENT;
            break;
        case PROC_ERROR_NOTEMPTY:
            *proc_errno_ptr(proc) = ENOTEMPTY;
            break;
        default:
            *proc_errno_ptr(proc) = EIO;
            break;
        }
        return -1;
    }

    return 0;
}

int mock_linux_rename(char *oldpath, char *newpath)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int ret = proc_rename(proc, oldpath, newpath);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_NOENT:
            *proc_errno_ptr(proc) = ENOENT;
            break;
        case PROC_ERROR_EXIST:
            *proc_errno_ptr(proc) = EEXIST;
            break;
        case PROC_ERROR_NOTEMPTY:
            *proc_errno_ptr(proc) = ENOTEMPTY;
            break;
        case PROC_ERROR_ISDIR:
            *proc_errno_ptr(proc) = EISDIR;
            break;
        default:
            *proc_errno_ptr(proc) = EIO;
            break;
        }
        return -1;
    }

    return 0;
}

int mock_linux_clock_gettime(clockid_t clockid, struct timespec *tp)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    if (tp == NULL) {
        *proc_errno_ptr(proc) = EINVAL;
        return -1;
    }

    // Both CLOCK_REALTIME and CLOCK_MONOTONIC use the same
    // simulated time. In simulation, they're equivalent since
    // we don't model wall-clock vs monotonic differences.
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC) {
        *proc_errno_ptr(proc) = EINVAL;
        return -1;
    }

    // Get current time and advance it slightly (simulates syscall cost)
    Nanos now = proc_time(proc);

    // Convert nanoseconds to timespec
    // 1 second = 1,000,000,000 nanoseconds
    tp->tv_sec  = (time_t)  (now / 1000000000ULL);
    tp->tv_nsec = (int64_t) (now % 1000000000ULL);

    return 0;
}

int mock_linux_flock(int fd, int op)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

int mock_linux_fsync(int fd)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    int ret = proc_fsync(proc, fd);
    if (ret < 0) {
        if (ret == PROC_ERROR_BADIDX)
            *proc_errno_ptr(proc) = EBADF;
        else
            *proc_errno_ptr(proc) = EINVAL;
        return -1;
    }

    return 0;
}

off_t mock_linux_lseek(int fd, off_t offset, int whence)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    // Convert POSIX whence to PROC whence
    int proc_whence;
    switch (whence) {
    case SEEK_SET:
        proc_whence = PROC_SEEK_SET;
        break;
    case SEEK_CUR:
        proc_whence = PROC_SEEK_CUR;
        break;
    case SEEK_END:
        proc_whence = PROC_SEEK_END;
        break;
    default:
        *proc_errno_ptr(proc) = EINVAL;
        return (off_t)-1;
    }

    int ret = proc_lseek(proc, fd, offset, proc_whence);
    if (ret < 0) {
        if (ret == PROC_ERROR_BADIDX)
            *proc_errno_ptr(proc) = EBADF;
        else
            *proc_errno_ptr(proc) = EINVAL;
        return (off_t)-1;
    }

    return (off_t)ret;
}

int mock_linux_fstat(int fd, struct stat *buf)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    if (buf == NULL) {
        *proc_errno_ptr(proc) = EINVAL;
        return -1;
    }

    FileInfo info;
    int ret = proc_fileinfo(proc, fd, &info);
    if (ret < 0) {
        if (ret == PROC_ERROR_BADIDX) {
            *proc_errno_ptr(proc) = EBADF;
        } else {
            *proc_errno_ptr(proc) = EIO;
        }
        return -1;
    }

    memset(buf, 0, sizeof(*buf));

    if (info.is_dir) {
        buf->st_mode = S_IFDIR | 0755;  // Directory with rwxr-xr-x permissions
        buf->st_size = 0;
    } else {
        buf->st_mode = S_IFREG | 0644;  // Regular file with rw-r--r-- permissions
        buf->st_size = (off_t) info.size;
    }

    return 0;
}

int mock_linux_mkstemp(char *path)
{
    abortf("mock %s() not implemented yet\n", __func__); // TODO
}

char *mock_linux_realpath(char *path, char *dst)
{
    abortf("Not implemented yet\n");
}

int mock_linux_mkdir(char *path, mode_t mode)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_LINUX, __func__);

    // LittleFS doesn't use mode, but we accept it for API compatibility
    (void) mode;

    int ret = proc_mkdir(proc, path);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_EXIST:
            *proc_errno_ptr(proc) = EEXIST;
            return -1;
        case PROC_ERROR_NOENT:
            // Parent directory doesn't exist
            *proc_errno_ptr(proc) = ENOENT;
            return -1;
        default:
            *proc_errno_ptr(proc) = EIO;
            return -1;
        }
    }

    return 0;
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

int mock_windows_GetLastError(void)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_WINDOWS, __func__);

    // Note that technically on windows errno and GetLastError
    // are different things. Here we use errno_ to store the
    // GetLastError value and assume the user will not access
    // errno.
    return *proc_errno_ptr(proc);
}

int mock_windows_WSAGetLastError(void)
{
    return mock_windows_GetLastError();
}

void mock_windows_SetLastError(int err)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_WINDOWS, __func__);

    *proc_errno_ptr(proc) = err;
}

void mock_windows_WSASetLastError(int err)
{
    return mock_windows_SetLastError(err);
}

int mock_windows_closesocket(SOCKET fd)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_WINDOWS, __func__);

    int desc_idx = fd;
    int ret = proc_close(proc, desc_idx, true);  // expect_socket = true
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_BADIDX:
        case PROC_ERROR_NOTSOCK:
            // Windows uses WSAGetLastError(), but for simplicity we just return error
            return -1;
        default:
            break;
        }
        return -1;
    }

    return 0;
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
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_WINDOWS, __func__);

    if (lpPerformanceCount == NULL)
        return 0;  // FALSE

    // Get current time in nanoseconds and convert to performance counter units
    // We use nanoseconds directly as the counter value (frequency = 1,000,000,000)
    Nanos now = proc_time(proc);
    lpPerformanceCount->QuadPart = (LONGLONG)now;

    return 1;  // TRUE
}

BOOL mock_windows_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_WINDOWS, __func__);

    if (lpFrequency == NULL)
        return 0;  // FALSE

    // Frequency is 1 billion (nanoseconds per second)
    // This matches our counter which counts in nanoseconds
    lpFrequency->QuadPart = 1000000000LL;

    return 1;  // TRUE
}

char *mock_windows__fullpath(char *path, char *dst, int cap)
{
    abortf("Not implemented yet\n");
}

int mock_windows__mkdir(char *path)
{
    Proc *proc = proc_current();
    if (proc == NULL)
        abortf("Call to %s() with no node scheduled\n", __func__);

    ensure_os(proc, OS_WINDOWS, __func__);

    int ret = proc_mkdir(proc, path);
    if (ret < 0) {
        switch (ret) {
        case PROC_ERROR_EXIST:
            *proc_errno_ptr(proc) = EEXIST;
            return -1;
        case PROC_ERROR_NOENT:
            // Parent directory doesn't exist
            *proc_errno_ptr(proc) = ENOENT;
            return -1;
        default:
            *proc_errno_ptr(proc) = EIO;
            return -1;
        }
    }

    return 0;
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