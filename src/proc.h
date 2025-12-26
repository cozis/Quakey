#ifndef PROC_INCLUDED
#define PROC_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#include <quakey.h>

#include "3p/lfs.h"

#define PROC_IPADDR_LIMIT 4

// On Linux the descriptor limit is usually 1K
#define PROC_DESC_LIMIT 1024

// Backlog size used by listen() when the provided
// backlog argument is non-positive
#define DEFAULT_BACKLOG 128

#define FIRST_EPHIMERAL_PORT 10000
#define LAST_EPHIMERAL_PORT  50000

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

struct pollfd {
	int fd;
	short events;
	short revents;
};

enum {
    POLLIN  = 1<<0,
    POLLOUT = 1<<1,
};

struct Proc {

    // Parent simulation
    QuakeySim *sim;

    // Pointers to program code
    QuakeyInitFunc init_func;
    QuakeyTickFunc tick_func;
    QuakeyFreeFunc free_func;

    // Program-specific state
    void *state;

    // Operating system used by the process.
    // It starts as UNSPECIFIED and is set to
    // LINUX or WINDOWS based on the first
    // mock system call it uses. After that,
    // all calls must be to system calls of
    // that same platform
    OS os;

    uint16_t next_ephimeral_port;

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
};

// TODO: comment
Proc *proc_current(void);

// TODO: comment
int proc_init(Proc *proc,
    QuakeySim *sim,
    int state_size,
    QuakeyInitFunc init_func,
    QuakeyTickFunc tick_func,
    QuakeyFreeFunc free_func,
    Addr *addrs,
    int   num_addrs,
    int   disk_size,
    int    argc,
    char **argv);

// TODO: comment
void proc_free(Proc *proc);

// TODO: comment
int proc_restart(Proc *proc, bool whipe_disk);

// TODO: comment
void proc_advance_network(Proc *proc);

// TODO: comment
int proc_tick(Proc *proc);

// TODO: comment
bool proc_ready(Proc *proc);

// TODO: comment
bool proc_has_addr(Proc *proc, Addr addr);

// TODO: comment
Nanos proc_time(Proc *proc);

// Returns the descriptor index on success,
// an error code on failure:
//   PROC_ERROR_FULL: Descriptor limit reached
int proc_create_socket(Proc *proc, AddrFamily family);

// Returns 0 on success, or a negative code on error:
//   - PROC_ERROR_BADIDX index doesn't refer to an
//     open descriptor
//   - PROC_ERROR_NOTSOCK the expect_socket flag is
//     set and the descriptor doesn't refer to a socket
int proc_close(Proc *proc, int desc_idx,
    bool expect_socket);

// Returns 0 on success or a negative code on failure:
//   - PROC_ERROR_BADIDX the descriptor index does not refer
//     to a valid descriptor
//   - PROC_ERROR_NOTSOCK the descriptor is not a socket
//   - PROC_ERROR_CANTBIND either the socket was already bound
//     or listen()/connect() were already called on it.
//   - PROC_ERROR_BADFAM the address family is incompatile with the
//     one specified when socket() was called
//   - PROC_ERROR_NOTAVAIL either the address doesn't exist,
//     is not local, or port 0 was passed and all ephimeral ports
//     are in use
//   - PROC_ERROR_ADDRUSED address is already in use
int proc_bind(Proc *proc, int desc_idx,
    Addr addr, uint16_t port);

// Returns 0 on success and a negative code on error:
//   - PROC_ERROR_BADIDX index does not refer to a valid
//     descriptor
//   - PROC_ERROR_BADARG descriptor is a socket but of the
//     wrong kind
//   - PROC_ERROR_NOTSOCK descriptor is not a socket
//   - PROC_ERROR_ADDRUSED the socket wasn't bound to an
//     interface and no ephimeral ports are available
int proc_listen(Proc *proc, int desc_idx,
    int backlog);

// Returns a new descriptor index on success, or a negative error code:
//   - PROC_ERROR_BADIDX index does not refer to a valid descriptor
//   - PROC_ERROR_NOTSOCK descriptor is not a socket
//   - PROC_ERROR_BADARG descriptor is a socket but not a listening socket
//   - PROC_ERROR_FULL descriptor limit reached
//   - PROC_ERROR_WOULDBLOCK no pending connections
int proc_accept(Proc *proc, int desc_idx,
    Addr *addr, uint16_t *port);

// TODO: comment
int proc_connect(Proc *proc, int desc_idx,
    Addr addr, uint16_t port);

// TODO: comment
int proc_open_file(Proc *proc, char *file, int flags);

// TODO: comment
int proc_open_dir(Proc *proc, char *file);

// TODO: comment
int proc_read(Proc *proc, int desc_idx, char *dst, int len);

// TODO: comment
int proc_write(Proc *proc, int desc_idx, char *src, int len);

// TODO: comment
int proc_recv(Proc *proc, int desc_idx, char *dst, int len);

// TODO: comment
int proc_send(Proc *proc, int desc_idx, char *src, int len);

#endif // PROC_INCLUDED