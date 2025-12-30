#ifndef PROC_INCLUDED
#define PROC_INCLUDED

#include <quakey.h>

#include "poll.h"
#include "3p/lfs.h"

#include <stdint.h>
#include <stdbool.h>

#define PROC_IPADDR_LIMIT 4

// On Linux the descriptor limit is usually 1K
#define PROC_DESC_LIMIT 1024

#define PROC_ARGC_LIMIT 32

// Backlog size used by listen() when the provided
// backlog argument is non-positive
#define DEFAULT_BACKLOG 128

#define FIRST_EPHEMERAL_PORT 10000
#define LAST_EPHEMERAL_PORT  50000

typedef struct Proc Proc;
typedef struct Desc Desc;

typedef enum {
    OS_UNSPECIFIED,
    OS_LINUX,
    OS_WINDOWS,
} OS;

enum {
    PROC_ERROR_OTHER   = -1,
    PROC_ERROR_FULL    = -2,
    PROC_ERROR_BADIDX  = -3,
    PROC_ERROR_NOTSOCK = -4,
    PROC_ERROR_CANTBIND = -5,
    PROC_ERROR_NOTAVAIL = -6,
    PROC_ERROR_ADDRUSED = -7,
    PROC_ERROR_BADARG   = -8,
    PROC_ERROR_BADFAM   = -9,
    PROC_ERROR_RESET    = -10,
    PROC_ERROR_HANGUP   = -11,
    PROC_ERROR_NOTCONN  = -12,
    PROC_ERROR_IO       = -13,
    PROC_ERROR_ISDIR    = -14,
    PROC_ERROR_WOULDBLOCK = -15,
    PROC_ERROR_NOMEM    = -16,
    PROC_ERROR_NOENT    = -17,
    PROC_ERROR_NOTEMPTY = -18,
    PROC_ERROR_EXIST    = -19,
    PROC_ERROR_EXISTS   = -19,  // Alias for PROC_ERROR_EXIST
};

// lseek whence values for proc_lseek
enum {
    PROC_SEEK_SET = 0,
    PROC_SEEK_CUR = 1,
    PROC_SEEK_END = 2,
};

// Number of nanoseconds
typedef uint64_t Nanos;

typedef enum {
    ADDR_FAMILY_IPV4,
    ADDR_FAMILY_IPV6,
} AddrFamily;

typedef struct {
    uint32_t data;
} AddrIPv4;

typedef struct {
    uint16_t data[8];
} AddrIPv6;

typedef struct {
    AddrFamily family;
    union {
        AddrIPv4 ipv4;
        AddrIPv6 ipv6;
    };
} Addr;

typedef enum {

    // The Desc structure is unused
    DESC_EMPTY,

    // The Desc represents a socket created
    // with the socket() system call. The
    // specific type of socket depends on
    // how it's configured
    DESC_SOCKET,

    // The Desc represents a listening socket,
    // one created with socket() on which listen()
    // is used.
    DESC_SOCKET_L,

    // The Desc represents a connection socket,
    // one created using accept() or with socket()
    // and then configured using listen()
    DESC_SOCKET_C,

    // The Desc represents an opened file
    DESC_FILE,

    // The Desc represent an open directory
    DESC_DIRECTORY,

} DescType;

typedef struct {
    int head;
    int count;
    int capacity;
    Desc **entries;
} AcceptQueue;

typedef struct {

    // Enqeued bytes
    char *data;

    // Index of the first byte
    int head;

    // Number of bytes in the queue
    int used;

    // Capacity of the queue
    int size;

} SocketQueue;

struct Desc {

    // Parent process object. This is set once at startup
    Proc *proc;

    /////////////////////////////////////////
    // General descriptor fields

    DescType type;
    bool     non_blocking;

    /////////////////////////////////////////
    // General socket fields

    // True if bind() has been called on this socket
    bool is_explicitly_bound;

    // Address and port bound to this socket (either
    // implicitly or explicitly).
    //
    // An implicit bind occurs when listen() or connect()
    // are called on a socket that was never bound to an
    // interface using bind().
    //
    // The address starts out with family equal to the
    // first argument of socket() and address of 0. The
    // port starts from 0.
    Addr     bound_addr;
    uint16_t bound_port;

    /////////////////////////////////////////
    // Listen socket fields

    AcceptQueue accept_queue;

    /////////////////////////////////////////
    // Connection socket fields

    // These are used when the socket is still connecting
    Addr     connect_addr;
    uint16_t connect_port;

    // Time when the call to connect() or accept() first
    // occurred
    Nanos connect_time;

    // Number of nanoseconds the connect() operation will
    // delay before resolving
    Nanos connect_delay;

    // Number of bytes transferred since connect_time
    uint64_t num_transf;

    // Transfer rate of the connection
    uint64_t bytes_per_sec;

    // When connected this refers to the peer socket, else it's NULL.
    //
    // The peer is either a listen socket if the connection wasn't
    // accepted yet, or a connection socket if it was. Note that this
    // means the references to this descriptor must be removed from
    // the peer's accept queue if it's freed abruptly.
    Desc *peer;

    // If peer is NULL and this is set, the connecton was reset by
    // peer
    bool rst;

    // If peer is NULL and this is set, the connection was closed
    // gracefully by peer
    bool hup;

    // Bytes received from/about to get sent to the peer
    SocketQueue input;
    SocketQueue output;

    /////////////////////////////////////////
    // File fields

    lfs_file_t file;

    /////////////////////////////////////////
    // Directory fields

    lfs_dir_t dir;

    /////////////////////////////////////////
};

struct Proc {

    // Parent simulation
    Quakey *sim;

    // Command-line arguments as a single dynamic string
    char *arg;

    // TODO: comment
    int   argc;
    char *argv[PROC_ARGC_LIMIT];

    // Pointers to program code
    QuakeyInitFunc init_func;
    QuakeyTickFunc tick_func;
    QuakeyFreeFunc free_func;

    // Program-specific state
    void *state;
    int   state_size;

    // Operating system used by the process.
    // It starts as UNSPECIFIED and is set to
    // LINUX or WINDOWS based on the first
    // mock system call it uses. After that,
    // all calls must be to system calls of
    // that same platform
    OS os;

    uint16_t next_ephemeral_port;

    // IP addresses associated to this process
    int  num_addrs;
    Addr addrs[PROC_IPADDR_LIMIT];

    // Current time in nanoseconds (since an unspecified
    // point in time).
    Nanos current_time;

    // Sparse array of descriptors. Unused slots have
    // type DESC_EMPTY and "num_used" is the number of
    // non-empty slots.
    int num_desc;
    Desc desc[PROC_DESC_LIMIT];

    // Raw disk bytes
    int   disk_size;
    char *disk_data;

    // LittleFS instance managing the disk bytes
    lfs_t lfs;
    struct lfs_config lfs_cfg;

    struct pollfd poll_array[PROC_DESC_LIMIT];
    int           poll_count;
    int           poll_timeout;

    // Last time poll() was called
    Nanos poll_call_time;

    // Current error number
    int errno_;
};

// Returns a pointer to the currently scheduled process, or NULL
// if no process is currently being executed.
Proc *proc_current(void);

// Initializes a process with the given simulation context, callbacks,
// network addresses, and disk configuration. The init_func is called
// immediately to set up the initial process state.
// Returns 0 on success, -1 on failure (memory allocation or init failed).
int proc_init(Proc *proc,
    Quakey *sim,
    int state_size,
    QuakeyInitFunc init_func,
    QuakeyTickFunc tick_func,
    QuakeyFreeFunc free_func,
    Addr *addrs,
    int   num_addrs,
    int   disk_size,
    char *arg);

// Frees all resources associated with a process, including its state,
// open descriptors, and filesystem. Calls the process's free_func callback.
void proc_free(Proc *proc);

// Restarts a process by freeing its current state, closing all descriptors,
// and reinitializing the filesystem. If wipe_disk is true, the disk contents
// are zeroed before remounting. Returns 0 on success, -1 on failure.
int proc_restart(Proc *proc, bool wipe_disk);

// Advances the network simulation for the process. Transfers data between
// connected sockets based on elapsed time and transfer rates.
void proc_advance_network(Proc *proc);

// Executes one tick of the process by calling its tick_func callback.
// Updates poll revents before calling. Returns 0 on success, -1 on failure.
int proc_tick(Proc *proc);

// Returns true if the process has pending events to handle, i.e., if any
// polled descriptors have ready events or if the poll timeout is zero.
bool proc_ready(Proc *proc);

// Returns the current error number
int *proc_errno_ptr(Proc *proc);

// Returns true if the given address is one of the addresses assigned
// to this process.
bool proc_has_addr(Proc *proc, Addr addr);

// TODO: comment
Desc *proc_find_desc_bound_to(Proc *proc, Addr addr, uint16_t port);

// Returns the current simulated time in nanoseconds and advances it
// by a small duration.
Nanos proc_time(Proc *proc);

// Creates a new socket descriptor with the specified address family.
// Advances the process's current_time.
// Returns the descriptor index on success, or an error code on failure:
//   - PROC_ERROR_FULL descriptor limit reached
int proc_create_socket(Proc *proc, AddrFamily family);

// Closes a descriptor and frees associated resources.
// Advances the process's current_time.
// Returns 0 on success, or a negative code on error:
//   - PROC_ERROR_BADIDX index doesn't refer to an open descriptor
//   - PROC_ERROR_NOTSOCK the expect_socket flag is set and the
//     descriptor doesn't refer to a socket
int proc_close(Proc *proc, int desc_idx,
    bool expect_socket);

// Binds a socket to a local address and port.
// Advances the process's current_time.
// Returns 0 on success or a negative code on failure:
//   - PROC_ERROR_BADIDX the descriptor index does not refer
//     to a valid descriptor
//   - PROC_ERROR_NOTSOCK the descriptor is not a socket
//   - PROC_ERROR_CANTBIND either the socket was already bound
//     or listen()/connect() were already called on it.
//   - PROC_ERROR_BADFAM the address family is incompatile with the
//     one specified when socket() was called
//   - PROC_ERROR_NOTAVAIL either the address doesn't exist,
//     is not local, or port 0 was passed and all ports
//     are in use
//   - PROC_ERROR_ADDRUSED address is already in use
int proc_bind(Proc *proc, int desc_idx,
    Addr addr, uint16_t port);

// Marks a socket as listening for incoming connections.
// Advances the process's current_time.
// Returns 0 on success and a negative code on error:
//   - PROC_ERROR_BADIDX index does not refer to a valid descriptor
//   - PROC_ERROR_BADARG descriptor is a socket but of the wrong kind
//   - PROC_ERROR_NOTSOCK descriptor is not a socket
//   - PROC_ERROR_ADDRUSED the socket wasn't bound to an interface
//     and no ephemeral ports are available
int proc_listen(Proc *proc, int desc_idx,
    int backlog);

// Accepts a pending connection from a listening socket.
// Advances the process's current_time.
// Returns a new descriptor index on success, or a negative error code:
//   - PROC_ERROR_BADIDX index does not refer to a valid descriptor
//   - PROC_ERROR_NOTSOCK descriptor is not a socket
//   - PROC_ERROR_BADARG descriptor is a socket but not a listening socket
//   - PROC_ERROR_FULL descriptor limit reached
//   - PROC_ERROR_WOULDBLOCK no pending connections
int proc_accept(Proc *proc, int desc_idx,
    Addr *addr, uint16_t *port);

// Initiates a connection to the specified address and port.
// Advances the process's current_time.
// Returns 0 on success, or a negative error code:
//   - PROC_ERROR_BADIDX index does not refer to a valid descriptor
//   - PROC_ERROR_NOTSOCK descriptor is not a socket
//   - PROC_ERROR_BADARG descriptor is already connected or listening
//   - PROC_ERROR_ADDRUSED no ephemeral ports available for implicit bind
int proc_connect(Proc *proc, int desc_idx,
    Addr addr, uint16_t port);

// Opens a file at the given path with the specified flags.
// Advances the process's current_time.
// Returns a descriptor index on success, or a negative error code:
//   - PROC_ERROR_FULL descriptor limit reached
//   - PROC_ERROR_IO filesystem error
int proc_open_file(Proc *proc, char *file, int flags);

// Opens a directory at the given path.
// Advances the process's current_time.
// Returns a descriptor index on success, or a negative error code:
//   - PROC_ERROR_FULL descriptor limit reached
//   - PROC_ERROR_IO filesystem error
int proc_open_dir(Proc *proc, char *file);

// Reads up to len bytes from a descriptor into dst.
// Works for both files and connection sockets.
// Advances the process's current_time.
// Returns the number of bytes read on success, or a negative error code:
//   - PROC_ERROR_BADIDX invalid descriptor index
//   - PROC_ERROR_BADARG descriptor type doesn't support reading
//   - PROC_ERROR_ISDIR descriptor refers to a directory
//   - PROC_ERROR_IO filesystem error
//   - PROC_ERROR_WOULDBLOCK no data available (sockets)
//   - PROC_ERROR_RESET connection reset by peer
//   - PROC_ERROR_HANGUP connection closed by peer
//   - PROC_ERROR_NOTCONN socket not connected
int proc_read(Proc *proc, int desc_idx, char *dst, int len);

// Writes up to len bytes from src to a descriptor.
// Works for both files and connection sockets.
// Advances the process's current_time.
// Returns the number of bytes written on success, or a negative error code:
//   - PROC_ERROR_BADIDX invalid descriptor index
//   - PROC_ERROR_IO filesystem error
//   - PROC_ERROR_WOULDBLOCK output buffer full (sockets)
//   - PROC_ERROR_RESET connection reset by peer
//   - PROC_ERROR_HANGUP connection closed by peer
//   - PROC_ERROR_NOTCONN socket not connected
int proc_write(Proc *proc, int desc_idx, char *src, int len);

// Receives up to len bytes from a socket into dst.
// Advances the process's current_time.
// Returns the number of bytes received on success, or a negative error code:
//   - PROC_ERROR_BADIDX invalid descriptor index
//   - PROC_ERROR_NOTSOCK descriptor is not a socket
//   - PROC_ERROR_WOULDBLOCK no data available
//   - PROC_ERROR_RESET connection reset by peer
//   - PROC_ERROR_HANGUP connection closed by peer
//   - PROC_ERROR_NOTCONN socket not connected
int proc_recv(Proc *proc, int desc_idx, char *dst, int len);

// Sends up to len bytes from src to a socket.
// Advances the process's current_time.
// Returns the number of bytes sent on success, or a negative error code:
//   - PROC_ERROR_BADIDX invalid descriptor index
//   - PROC_ERROR_WOULDBLOCK output buffer full
//   - PROC_ERROR_RESET connection reset by peer
//   - PROC_ERROR_HANGUP connection closed by peer
//   - PROC_ERROR_NOTCONN socket not connected
int proc_send(Proc *proc, int desc_idx, char *src, int len);

// TODO: comment
int proc_mkdir(Proc *proc, char *path);

// TODO: comment
int proc_remove(Proc *proc, char *path);

// TODO: comment
int proc_rename(Proc *proc, char *oldpath, char *newpath);

typedef struct {
    int64_t size;
    bool    is_dir;
} FileInfo;

// TODO: comment
int proc_fileinfo(Proc *proc, int desc_idx, FileInfo *info);

// TODO: comment
int proc_lseek(Proc *proc, int desc_idx, int64_t offset, int whence);

// TODO: comment
int proc_fsync(Proc *proc, int desc_idx);

enum {
    PROC_FLAG_NONBLOCK = 1,
};

// TODO: comment
int proc_setdescflags(Proc *proc, int fd, int flags);

// TODO: comment
int proc_getdescflags(Proc *proc, int fd);

#endif // PROC_INCLUDED