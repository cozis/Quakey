#ifndef DESC_INCLUDED
#define DESC_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#include "disk.h"

// On Linux the descriptor limit is usually 1K
#define DESC_TABLE_CAPACITY 1024

// Backlog size used by listen() when the provided
// backlog argument is non-positive
#define DEFAULT_BACKLOG 128

struct Proc;

enum {
    DESC_TABLE_ERROR_OTHER   = -1,
    DESC_TABLE_ERROR_FULL    = -2,
    DESC_TABLE_ERROR_BADIDX  = -3,
    DESC_TABLE_ERROR_NOTSOCK = -4,
    DESC_TABLE_ERROR_CANTBIND = -5,
    DESC_TABLE_ERROR_NOTAVAIL = -6,
    DESC_TABLE_ERROR_ADDRUSED = -7,
    DESC_TABLE_ERROR_BADARG   = -8,
    DESC_TABLE_ERROR_BADFAM   = -9,
};

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
    // TODO
} AcceptQueue;

typedef struct {

    /////////////////////////////////////////
    // General descriptor fields

    DescType type;

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

    /////////////////////////////////////////
    // File fields

    DiskOpenFile file;

    /////////////////////////////////////////
    // Directory fields

    DiskOpenDir dir;

    /////////////////////////////////////////
} Desc;

typedef struct {

    struct Proc *proc;

    // Sparse array of descriptors. Unused slots have
    // type DESC_EMPTY and "num_used" is the number of
    // non-empty slots.
    int num_used;
    Desc pool[DESC_TABLE_CAPACITY];
} DescTable;

void desc_table_init(DescTable *desc_table, struct Proc *proc);
void desc_table_free(DescTable *desc_table);

// Returns the descriptor index on success,
// an error code on failure:
//   DESC_TABLE_ERROR_FULL: Descriptor limit reached
int desc_table_create_socket(DescTable *desc_table, AddrFamily family);

// Returns 0 on success, or a negative code on error:
//   - DESC_TABLE_ERROR_BADIDX index doesn't refer to an
//     open descriptor
//   - DESC_TABLE_ERROR_NOTSOCK the expect_socket flag is
//     set and the descriptor doesn't refer to a socket
int desc_table_close(DescTable *desc_table, int desc_idx,
    bool expect_socket);

// Returns 0 on success or a negative code on failure:
//   - DESC_TABLE_ERROR_BADIDX the descriptor index does not refer
//     to a valid descriptor
//   - DESC_TABLE_ERROR_NOTSOCK the descriptor is not a socket
//   - DESC_TABLE_ERROR_CANTBIND either the socket was already bound
//     or listen()/connect() were already called on it.
//   - DESC_TABLE_ERROR_BADFAM the address family is incompatile with the
//     one specified when socket() was called
//   - DESC_TABLE_ERROR_NOTAVAIL either the address doesn't exist,
//     is not local, or port 0 was passed and all ephimeral ports
//     are in use
//   - DESC_TABLE_ERROR_ADDRUSED address is already in use
int desc_table_bind(DescTable *desc_table, int desc_idx,
    Addr addr, uint16_t port);

// Returns 0 on success and a negative code on error:
//   - DESC_TABLE_ERROR_BADIDX index does not refer to a valid
//     descriptor
//   - DESC_TABLE_ERROR_BADARG descriptor is a socket but of the
//     wrong kind
//   - DESC_TABLE_ERROR_NOTSOCK descriptor is not a socket
//   - DESC_TABLE_ERROR_ADDRUSED the socket wasn't bound to an
//     interface and no ephimeral ports are available
int desc_table_listen(DescTable *desc_table, int desc_idx,
    int backlog);

// TODO: comment
int desc_table_connect(DescTable *desc_table, int desc_idx,
    Addr addr, uint16_t port);

// TODO: comment
int desc_table_open_file(DescTable *desc_table, DiskFileHandle file);

// TODO: comment
int desc_table_open_dir(DescTable *desc_table, DiskDirHandle dir);

#endif // DESC_INCLUDED
