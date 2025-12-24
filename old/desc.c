#include <string.h>
#include <assert.h>

#include "proc.h"
#include "desc.h"

void accept_queue_init(AcceptQueue *queue)
{
    // TODO
}

void accept_queue_free(AcceptQueue *queue)
{
    // TODO
}

static void desc_init_socket(Desc *desc, AddrFamily family)
{
    desc->type = DESC_SOCKET;
    desc->is_explicitly_bound = false;
    desc->bound_addr = (Addr) { .family=family };
    desc->bound_port = 0;
}

static void desc_free(Desc *desc)
{
    switch (desc->type) {
    case DESC_EMPTY:
        break;
    case DESC_SOCKET:
        break;
    case DESC_SOCKET_L:
        accept_queue_free(&desc->accept_queue);
        break;
    case DESC_SOCKET_C:
        break;
    case DESC_FILE:
        disk_close_file(disk, desc->file);
        break;
    case DESC_DIRECTORY:
        disk_close_dir(disk, desc->dir);
        break;
    default:
        break;
    }
}

void desc_table_init(DescTable *desc_table, Proc *proc)
{
    desc_table->proc = proc;
    desc_table->num_used = 0;
    for (int i = 0; i < DESC_TABLE_CAPACITY; i++)
        desc_table->pool[i].type = DESC_EMPTY;
}

void desc_table_free(DescTable *desc_table)
{
    for (int i = 0; i < DESC_TABLE_CAPACITY; i++)
        if (desc_table->pool[i].type != DESC_EMPTY)
            desc_free(&desc_table->pool[i]);
}

static int find_empty_desc_struct(DescTable *desc_table)
{
    if (desc_table->num_used == DESC_TABLE_CAPACITY)
        return -1;

    int i = 0;
    while (desc_table->pool[i].type != DESC_EMPTY)
        i++;

    return i;
}

int desc_table_create_socket(DescTable *desc_table, AddrFamily family)
{
    int desc_idx = find_empty_desc_struct(desc_table);
    if (desc_idx < 0)
        return DESC_TABLE_ERROR_FULL;

    desc_init_socket(&desc_table->pool[desc_idx], family);
    return desc_idx;
}

static bool is_socket(Desc *desc)
{
    return desc->type != DESC_SOCKET
        || desc->type != DESC_SOCKET_L
        || desc->type != DESC_SOCKET_C;
}

static bool is_idx_valid(DescTable *desc_table, int desc_idx)
{
    // Out of bounds
    if (desc_idx < 0 || desc_idx >= DESC_TABLE_CAPACITY)
        return false;

    // Not in use
    if (desc_table->pool[desc_idx].type == DESC_EMPTY)
        return false;

    return true;
}

int desc_table_close(DescTable *desc_table, int desc_idx,
    bool expect_socket)
{
    if (!is_idx_valid(desc_table, desc_idx))
        return DESC_TABLE_ERROR_BADIDX;

    if (expect_socket) {
        if (!is_socket(&desc_table->pool[desc_idx]))
            return DESC_TABLE_ERROR_NOTSOCK;
    }

    desc_free(&desc_table->pool[desc_idx]);
    return 0;
}

// Returns 0 on error
static uint16_t choose_ephimeral_port(DescTable *desc_table)
{
    // TODO
}

static bool interf_exists_locally(DescTable *desc_table, Addr addr)
{
    Proc *proc = desc_table->proc;
    for (int i = 0; i < proc->num_addrs; i++)
        if (!memcmp(&proc->addrs[i], &addr, sizeof(Addr)))
            return true;
    return false;
}

// Returns true if the descriptor is a socket bound
// (implicitly or explicitly) to an address
static bool is_bound(Desc *desc)
{
    if (desc->type == DESC_SOCKET)
        return desc->is_explicitly_bound;

    if (desc->type == DESC_SOCKET_C ||
        desc->type == DESC_SOCKET_L)
        return true;

    return false;
}

// Note that this is assumed to work on empty
// descriptors too
static bool is_bound_to(Desc *desc, Addr addr, uint16_t port)
{
    if (is_bound(desc)) {
        if (!memcmp(&addr, &desc->bound_addr, sizeof(Addr)) && port == desc->bound_port)
            return true;
    }
    return false;
}

static bool addr_in_use(DescTable *desc_table, Addr addr, uint16_t port)
{
    assert(port != 0);

    for (int i = 0; i < DESC_TABLE_CAPACITY; i++) {
        Desc *desc = &desc_table->pool[i];
        if (is_bound_to(desc, addr, port))
            return true;
    }

    return false;
}

int desc_table_bind(DescTable *desc_table, int desc_idx, Addr addr, uint16_t port)
{
    /////////////////////////////////////////////////////////
    // Check index

    if (!is_idx_valid(desc_table, desc_idx))
        return DESC_TABLE_ERROR_BADIDX;
    Desc *desc = &desc_table->pool[desc_idx];

    /////////////////////////////////////////////////////////
    // Check descriptor

    if (!is_socket(desc))
        return DESC_TABLE_ERROR_NOTSOCK;

    if (desc_table->pool[desc_idx].type != DESC_SOCKET)
        return DESC_TABLE_ERROR_CANTBIND;

    if (desc->is_explicitly_bound)
        return DESC_TABLE_ERROR_CANTBIND;

    /////////////////////////////////////////////////////////
    // Check address

    if (addr.family != desc->bound_addr.family)
        return DESC_TABLE_ERROR_BADFAM;

    if (!interf_exists_locally(desc_table, addr))
        return DESC_TABLE_ERROR_NOTAVAIL;

    /////////////////////////////////////////////////////////
    // Check port

    if (port == 0) {
        port = choose_ephimeral_port(desc_table);
        if (port == 0)
            return DESC_TABLE_ERROR_NOTAVAIL;
    } else {
        if (addr_in_use(desc_table, addr, port))
            return DESC_TABLE_ERROR_ADDRUSED;
    }

    /////////////////////////////////////////////////////////
    // Perform the binding

    desc->is_explicitly_bound = true;
    desc->bound_addr = addr;
    desc->bound_port = port;

    /////////////////////////////////////////////////////////
    return 0;
}

int desc_table_listen(DescTable *desc_table, int desc_idx, int backlog)
{
    if (backlog <= 0)
        backlog = DEFAULT_BACKLOG;

    if (!is_idx_valid(desc_table, desc_idx))
        return DESC_TABLE_ERROR_BADIDX;
    Desc *desc = &desc_table->pool[desc_idx];

    if (desc->type != DESC_SOCKET) {
        if (is_socket(desc))
            return DESC_TABLE_ERROR_BADARG;
        return DESC_TABLE_ERROR_NOTSOCK;
    }

    if (!desc->is_explicitly_bound) {
        // We need to bind implicitly
        //
        // The bound_addr field already contains the right
        // family and a zero address. The port is 0, which
        // is not a valid value.
        desc->bound_port = choose_ephimeral_port();
        if (desc->bound_port == 0)
            return DESC_TABLE_ERROR_ADDRUSED;
    }

    if (accept_queue_init(&desc->accept_queue) < 0) {
        ZZZ // TODO
    }

    desc->type = DESC_SOCKET_L;
    return 0;
}

// TODO: check error codes returned by this function
int desc_table_connect(DescTable *desc_table, int desc_idx,
    Addr addr, uint16_t port)
{
    if (!is_idx_valid(desc_table, desc_idx))
        return DESC_TABLE_ERROR_BADIDX;
    Desc *desc = &desc_table->pool[desc_idx];

    if (desc->type != DESC_SOCKET) {
        if (is_socket(desc))
            return DESC_TABLE_ERROR_BADARG;
        return DESC_TABLE_ERROR_NOTSOCK;
    }

    if (!desc->is_explicitly_bound) {
        // We need to bind implicitly
        //
        // The bound_addr field already contains the right
        // family and a zero address. The port is 0, which
        // is not a valid value.
        desc->bound_port = choose_ephimeral_port();
        if (desc->bound_port == 0)
            return DESC_TABLE_ERROR_ADDRUSED;
    }

    desc->connect_addr = addr;
    desc->connect_port = port;

    desc->type = DESC_SOCKET_C;
    return 0;
}

int desc_table_open_file(DescTable *desc_table, DiskFileHandle file)
{
    int desc_idx = find_empty_desc_struct(desc_table);
    if (desc_idx < 0)
        return DESC_TABLE_ERROR_FULL;

    desc_init_file(&desc_table->pool[desc_idx], file);
    return desc_idx;
}

int desc_table_open_dir(DescTable *desc_table, DiskDirHandle dir)
{
    int desc_idx = find_empty_desc_struct(desc_table);
    if (desc_idx < 0)
        return DESC_TABLE_ERROR_FULL;

    desc_init_dir(&desc_table->pool[desc_idx], dir);
    return desc_idx;
}
