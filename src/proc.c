#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "proc.h"

static void desc_free(Desc *desc, lfs_t *lfs, bool rst);
static bool accept_queue_empty(AcceptQueue *queue);

static Proc *current_proc___;

Proc *proc_current(void)
{
    return current_proc___;
}

static int socket_queue_init(SocketQueue *queue, int size)
{
    char *data = malloc(size);
    if (data == NULL)
        return -1; // TODO: this should abort
    queue->head = 0;
    queue->used = 0;
    queue->size = size;
    queue->data = data;
    return 0;
}

static void socket_queue_free(SocketQueue *queue)
{
    free(queue->data);
}

static char *socket_queue_read_buf(SocketQueue *queue, int *num)
{
    *num = queue->used;
    return queue->data + queue->head;
}

static void socket_queue_read_ack(SocketQueue *queue, int num)
{
    queue->head += num;
    queue->used -= num;
}

static int socket_queue_read(SocketQueue *queue, char *dst, int max)
{
    int num;
    char *src = socket_queue_read_buf(queue, &num);

    int copy = max;
    if (copy > num)
        copy = num;
    memcpy(dst, src, copy);

    socket_queue_read_ack(queue, copy);
    return copy;
}

static char *socket_queue_write_buf(SocketQueue *queue, int *cap)
{
    // Only write up to the free space
    if (*cap > queue->size - queue->used)
        *cap = queue->size - queue->used;

    int last = queue->head + queue->used;
    if (queue->size - last < *cap) {
        memmove(queue->data, queue->data + queue->head, queue->used);
        queue->head = 0;
    }

    return queue->data + queue->head + queue->used;
}

static void socket_queue_write_ack(SocketQueue *queue, int num)
{
    queue->used += num;
}

static int socket_queue_write(SocketQueue *queue, char *src, int len)
{
    char *dst = socket_queue_write_buf(queue, &len);
    memcpy(dst, src, len);
    socket_queue_write_ack(queue, len);
    return len;
}

static int socket_queue_move(SocketQueue *dst_queue, SocketQueue *src_queue, int max)
{
    int avail;
    char *src = socket_queue_read_buf(src_queue, &avail);
    if (avail > max)
        avail = max;
    char *dst = socket_queue_write_buf(dst_queue, &avail);
    memcpy(dst, src, avail);
    socket_queue_write_ack(dst_queue, avail);
    socket_queue_read_ack(src_queue, avail);
    return avail;
}

static bool socket_queue_full(SocketQueue *queue)
{
    return queue->used == queue->size;
}

static bool socket_queue_empty(SocketQueue *queue)
{
    return queue->used == 0;
}

static int block_device_read(const struct lfs_config *c,
    lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
{
    Proc *proc = c->context;

    // Block offset
    lfs_off_t abs_off = block * c->block_size + off;

    // Bounds check
    if (abs_off + size > (lfs_size_t) proc->disk_size)
        return LFS_ERR_IO;

    // Copy data from disk to buffer
    memcpy(buffer, proc->disk_data + abs_off, size);
    return LFS_ERR_OK;
}

static int block_device_prog(const struct lfs_config *c,
    lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size)
{
    Proc *proc = c->context;

    // Block ofset
    lfs_off_t abs_off = block * c->block_size + off;

    // Bounds check
    if (abs_off + size > (lfs_size_t) proc->disk_size)
        return LFS_ERR_IO;

    // Copy data from buffer to disk
    memcpy(proc->disk_data + abs_off, buffer, size);
    return LFS_ERR_OK;
}

static int block_device_erase(const struct lfs_config *c,
    lfs_block_t block)
{
    Proc *proc = c->context;

    // Block offset
    lfs_off_t abs_off = block * c->block_size;

    // Bounds check
    if (abs_off + c->block_size > (lfs_size_t) proc->disk_size)
        return LFS_ERR_IO;

    // Erase the block by setting all bytes to 0xFF (typical erased flash state)
    memset(proc->disk_data + abs_off, 0xFF, c->block_size);
    return LFS_ERR_OK;
}

static int block_device_sync(const struct lfs_config *c)
{
    // No-op for in-memory storage - nothing to flush
    (void) c;
    return LFS_ERR_OK;
}

static bool is_desc_idx_valid(Proc *proc, int desc_idx);

static bool is_connected_and_accepted(Desc *desc)
{
    assert(desc->type == DESC_SOCKET_C);

    return desc->peer && desc->peer->type != DESC_SOCKET_L;
}

static void
set_revents_in_poll_array(Proc *proc)
{
    for (int i = 0; i < proc->poll_count; i++) {

        int fd = proc->poll_array[i].fd;
        int events = proc->poll_array[i].events;

        if (!is_desc_idx_valid(proc, fd)) {
            assert(0); // TODO
        }
        Desc *desc = &proc->desc[fd];

        int revents = 0;
        switch (desc->type) {
        case DESC_SOCKET:
            // TODO
            break;
        case DESC_SOCKET_L:
            if (events & POLLIN) {
                if (!accept_queue_empty(&desc->accept_queue))
                    revents = POLLIN;
            }
            break;
        case DESC_SOCKET_C:
            if (events & POLLIN) {
                // TODO: should report prover events when hup and rst are set
                if (!socket_queue_empty(&desc->input) || desc->rst || desc->hup)
                    revents |= POLLIN;
            }
            if (events & POLLOUT) {
                if (!socket_queue_full(&desc->output)) {
                    if (is_connected_and_accepted(desc))
                        revents |= POLLOUT;
                }
            }
            break;
        case DESC_FILE:
            if (events & POLLIN) {
                revents |= POLLIN;
            }
            if (events & POLLOUT) {
                revents |= POLLOUT;
            }
            break;
        case DESC_DIRECTORY:
            if (events & POLLIN) {
                revents |= POLLIN;
            }
            if (events & POLLOUT) {
                revents |= POLLOUT;
            }
            break;
        default:
            assert(0);
        }

        proc->poll_array[i].revents = revents;
    }
}

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
    char **argv)
{
    proc->sim = sim;
    proc->init_func = init_func;
    proc->tick_func = tick_func;
    proc->free_func = free_func;
    proc->os = OS_UNSPECIFIED;
    proc->next_ephimeral_port = FIRST_EPHIMERAL_PORT;

    proc->num_addrs = num_addrs;
    memcpy(proc->addrs, addrs, num_addrs * sizeof(Addr));

    proc->current_time = 0;

    proc->num_desc = 0;
    for (int i = 0; i < PROC_DESC_LIMIT; i++)
        proc->desc[i].type = DESC_EMPTY;

    proc->disk_size = disk_size;
    proc->disk_data = malloc(disk_size);
    if (proc->disk_data == NULL)
        return -1;

    // Zero out memory to make sure operations are deterministic
    memset(proc->disk_data, 0, disk_size);

    proc->lfs_cfg = (struct lfs_config) {

        .context = proc,

        // block device operations
        .read  = block_device_read,
        .prog  = block_device_prog,
        .erase = block_device_erase,
        .sync  = block_device_sync,

        // block device configuration
        .read_size = 16,
        .prog_size = 16,
        .block_size = 4096,
        .block_count = 128,
        .cache_size = 16,
        .lookahead_size = 16,
        .block_cycles = 500,
    };

    int ret = lfs_mount(&proc->lfs, &proc->lfs_cfg);
    if (ret) {
        lfs_format(&proc->lfs, &proc->lfs_cfg); // TODO: can this fail?
        ret = lfs_mount(&proc->lfs, &proc->lfs_cfg);
        if (ret) {
            free(proc->disk_data);
            return -1;
        }
    }

    proc->poll_count = 0;
    proc->poll_timeout = -1;

    void *state = malloc(state_size);
    if (state == NULL) {
        lfs_unmount(&proc->lfs);
        free(proc->disk_data);
        return -1;
    }

    current_proc___ = proc;
    ret = init_func(state, argc, argv, proc->poll_array, PROC_DESC_LIMIT, &proc->poll_count, &proc->poll_timeout);
    current_proc___ = NULL;
    if (ret < 0) {
        free(state);
        lfs_unmount(&proc->lfs);
        free(proc->disk_data);
        return -1;
    }

    proc->state = state;
    return 0;
}

void proc_free(Proc *proc)
{
    current_proc___ = proc;
    proc->free_func(proc->state);
    current_proc___ = NULL;

    free(proc->state);

    lfs_unmount(&proc->lfs);
    free(proc->disk_data);

    for (int i = 0; i < PROC_DESC_LIMIT; i++)
        if (proc->desc[i].type != DESC_EMPTY)
            desc_free(&proc->desc[i], &proc->lfs, true);
}

int proc_restart(Proc *proc, bool wipe_disk)
{
    // Free the current state
    current_proc___ = proc;
    proc->free_func(proc->state);
    current_proc___ = NULL;
    free(proc->state);

    // Close all descriptors
    for (int i = 0; i < PROC_DESC_LIMIT; i++) {
        if (proc->desc[i].type != DESC_EMPTY) {
            desc_free(&proc->desc[i], &proc->lfs, true);
            proc->desc[i].type = DESC_EMPTY;
        }
    }
    proc->num_desc = 0;

    // Unmount filesystem
    lfs_unmount(&proc->lfs);

    // Optionally wipe the disk
    if (wipe_disk) {
        memset(proc->disk_data, 0, proc->disk_size);
    }

    // Remount filesystem
    int ret = lfs_mount(&proc->lfs, &proc->lfs_cfg);
    if (ret) {
        lfs_format(&proc->lfs, &proc->lfs_cfg);
        ret = lfs_mount(&proc->lfs, &proc->lfs_cfg);
        if (ret)
            return -1;
    }

    // Reset other state
    proc->os = OS_UNSPECIFIED;
    proc->next_ephimeral_port = FIRST_EPHIMERAL_PORT;
    proc->current_time = 0;
    proc->poll_count = 0;
    proc->poll_timeout = -1;

    // TODO: Allocate and initialize new state
    //
    // Note: We don't have access to state_size, argc, argv here
    // This function assumes proc_init was already called with valid values
    // and we need to re-run init_func with stored argc/argv
    // For now, we assume state can be re-allocated with the same size
    assert(0);

    return 0;
}

void proc_advance_network(Proc *proc)
{
    // TODO: the changes of this function should not
    //       depend on how many times it is called but
    //       how much time has passed
    for (int i = 0, j = 0; j < proc->num_desc; i++) {

        Desc *desc = &proc->desc[i];
        if (desc->type == DESC_EMPTY)
            continue;
        j++;

        if (desc->type != DESC_SOCKET_C)
            continue;

        if (desc->peer == NULL) {
            // Not connected
            if (!desc->rst && !desc->hup) {
                // Still waiting
                // TODO: try to complete
            }
        } else {
            if (desc->peer->type == DESC_SOCKET_C) {
                // Receive some bytes from peer

                Nanos elapsed = proc->current_time - desc->connect_time;
                uint64_t max_transf = (desc->bytes_per_sec * elapsed) / 1000000000;

                int transf = 0;
                if (desc->num_transf < max_transf)
                    transf = max_transf - desc->num_transf;

                int num = socket_queue_move(&desc->input, &desc->peer->output, transf);
                desc->num_transf += transf;
            }
        }
    }
}

int proc_tick(Proc *proc)
{
    set_revents_in_poll_array(proc);
    current_proc___ = proc;
    int ret = proc->tick_func(proc->state, proc->poll_array, PROC_DESC_LIMIT, &proc->poll_count, &proc->poll_timeout);
    current_proc___ = NULL;
    if (ret < 0)
        return -1;
    return 0;
}

bool proc_ready(Proc *proc)
{
    // If poll timeout is 0, always ready
    if (proc->poll_timeout == 0)
        return true;

    // Check if any polled descriptors have pending events
    for (int i = 0; i < proc->poll_count; i++) {

        int fd = proc->poll_array[i].fd;
        int events = proc->poll_array[i].events;

        if (!is_desc_idx_valid(proc, fd))
            continue;

        Desc *desc = &proc->desc[fd];

        switch (desc->type) {
        case DESC_SOCKET_L:
            if (events & POLLIN) {
                if (!accept_queue_empty(&desc->accept_queue))
                    return true;
            }
            break;
        case DESC_SOCKET_C:
            if (events & POLLIN) {
                if (!socket_queue_empty(&desc->input) || desc->rst || desc->hup)
                    return true;
            }
            if (events & POLLOUT) {
                if (!socket_queue_full(&desc->output) && is_connected_and_accepted(desc))
                return true;
            }
            break;
        case DESC_FILE:
        case DESC_DIRECTORY:
            // Files and directories are always ready
            if (events & (POLLIN | POLLOUT))
                return true;
            break;
        default:
            break;
        }
    }

    return false;
}

static bool addr_eql(Addr a1, Addr a2)
{
    if (a1.family != a2.family)
        return false;
    if (a1.family == ADDR_FAMILY_IPV4)
        return !memcmp(&a1.ipv4, &a2.ipv4, sizeof(AddrIPv4));
    assert(a1.family == ADDR_FAMILY_IPV6);
    return !memcmp(&a1.ipv6, &a2.ipv6, sizeof(AddrIPv6));
}

bool proc_has_addr(Proc *proc, Addr addr)
{
    for (int i = 0; i < proc->num_addrs; i++) {
        if (addr_eql(proc->addrs[i], addr))
            return true;
    }
    return false;
}

static int accept_queue_init(AcceptQueue *queue, int capacity)
{
    Desc **entries = malloc(sizeof(Desc*));
    if (entries == NULL)
        return -1;
    queue->head = 0;
    queue->count = 0;
    queue->capacity = capacity;
    queue->entries = entries;
    return 0;
}

static void accept_queue_free(AcceptQueue *queue)
{
    free(queue->entries);
}

static Desc **accept_queue_peek(AcceptQueue *queue, int idx)
{
    if (idx >= queue->count)
        return NULL;
    return &queue->entries[(queue->head + idx) % queue->capacity];
}

static void accept_queue_remove(AcceptQueue *queue, Desc *desc)
{
    int i = 0;
    while (i < queue->count && desc != *accept_queue_peek(queue, i))
        i++;

    if (i == queue->count)
        return; // Not found

    while (i < queue->count-1) {
        *accept_queue_peek(queue, i) = *accept_queue_peek(queue, i+1);
        i++;
    }

    queue->count--;
}

static int accept_queue_push(AcceptQueue *queue, Desc *desc)
{
    if (queue->count == queue->capacity)
        return -1;
    int tail = (queue->head + queue->count) % queue->capacity;
    queue->entries[tail] = desc;
    queue->count++;
    return 0;
}

static int accept_queue_pop(AcceptQueue *queue, Desc **desc)
{
    if (queue->count == 0)
        return -1;
    *desc = queue->entries[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;
    return 0;
}

static bool accept_queue_empty(AcceptQueue *queue)
{
    return queue->count == 0;
}

static void reset_peer(Desc *desc)
{
    assert(desc->type == DESC_SOCKET_C);
    desc->peer = NULL;
    desc->rst = true;
    desc->hup = false;
}

static void close_peer(Desc *desc)
{
    assert(desc->type == DESC_SOCKET_C);
    desc->peer = NULL;
    desc->rst = false;
    desc->hup = true;
}

// If the descriptor is a connection socket and rst=true,
// the peer connection will be marked as "reset" instead
// of simply closed.
static void desc_free(Desc *desc, lfs_t *lfs, bool rst)
{
    switch (desc->type) {
    case DESC_EMPTY:
        break;
    case DESC_SOCKET:
        break;
    case DESC_SOCKET_L:
        // Update the other ends of the connections waiting to be accepted
        for (int i = 0; i < desc->accept_queue.count; i++)
            reset_peer(*accept_queue_peek(&desc->accept_queue, i));
        accept_queue_free(&desc->accept_queue);
        break;
    case DESC_SOCKET_C:
        if (desc->peer) {
            // A connection was previously established.
            // We need to update the other end of the connection.
            Desc *peer = desc->peer;
            if (peer->type == DESC_SOCKET_L) {
                // Connection was waiting to be accepted
                accept_queue_remove(&peer->accept_queue, desc);
            } else {
                assert(peer->type == DESC_SOCKET_C);
                if (rst) {
                    reset_peer(peer);
                } else {
                    close_peer(peer);
                }
            }
        }
        socket_queue_free(&desc->input);
        socket_queue_free(&desc->output);
        break;
    case DESC_FILE:
        lfs_file_close(lfs, &desc->file);
        break;
    case DESC_DIRECTORY:
        lfs_dir_close(lfs, &desc->dir);
        break;
    default:
        break;
    }
    desc->type = DESC_EMPTY;
}

static Nanos pick_time_duration(Proc *proc)
{
    (void) proc;
    return 20;
}

Nanos proc_time(Proc *proc)
{
    Nanos time = proc->current_time;
    proc->current_time += pick_time_duration(proc);
    return time;
}

static int find_empty_desc_struct(Proc *proc)
{
    if (proc->num_desc == PROC_DESC_LIMIT)
        return -1;

    int i = 0;
    while (proc->desc[i].type != DESC_EMPTY)
        i++;

    return i;
}

static Nanos pick_create_socket_duration(Proc *proc)
{
    (void) proc;
    return 500;
}

int proc_create_socket(Proc *proc, AddrFamily family)
{
    int desc_idx = find_empty_desc_struct(proc);
    if (desc_idx < 0)
        return PROC_ERROR_FULL;
    Desc *desc = &proc->desc[desc_idx];

    desc->type = DESC_SOCKET;
    desc->non_blocking = false;
    desc->is_explicitly_bound = false;
    desc->bound_addr = (Addr) { .family=family };
    desc->bound_port = 0;

    proc->current_time += pick_create_socket_duration(proc);
    return desc_idx;
}

static bool is_socket(Desc *desc)
{
    return desc->type == DESC_SOCKET
        || desc->type == DESC_SOCKET_L
        || desc->type == DESC_SOCKET_C;
}

static bool is_desc_idx_valid(Proc *proc, int desc_idx)
{
    // Out of bounds
    if (desc_idx < 0 || desc_idx >= PROC_DESC_LIMIT)
        return false;

    // Not in use
    if (proc->desc[desc_idx].type == DESC_EMPTY)
        return false;

    return true;
}

static Nanos pick_close_duration(Proc *proc)
{
    (void) proc;
    return 400;
}

int proc_close(Proc *proc, int desc_idx, bool expect_socket)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;

    if (expect_socket) {
        if (!is_socket(&proc->desc[desc_idx]))
            return PROC_ERROR_NOTSOCK;
    }

    desc_free(&proc->desc[desc_idx], &proc->lfs, false);

    proc->current_time += pick_close_duration(proc);
    return 0;
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

static bool is_zero_addr(Addr addr)
{
    char *p;
    int   n;
    if (addr.family == ADDR_FAMILY_IPV4) {
        p = (char*) &addr.ipv4;
        n = sizeof(addr.ipv4);
    } else {
        assert(addr.family == ADDR_FAMILY_IPV6);
        p = (char*) &addr.ipv6;
        n = sizeof(addr.ipv6);
    }
    for (int i = 0; i < n; i++) {
        if (p[i] != 0)
            return false;
    }
    return true;
}

static bool addr_in_use(Proc *proc, Addr addr, uint16_t port)
{
    assert(port != 0);

    if (is_zero_addr(addr)) {
        // Any address may conflict with the zero address,
        // which means we only need to compare ports.
        for (int i = 0; i < PROC_DESC_LIMIT; i++) {
            if (proc->desc[i].bound_port == port)
                return true;
        }
    } else {
        for (int i = 0; i < PROC_DESC_LIMIT; i++) {
            if (is_bound_to(&proc->desc[i], addr, port))
                return true;
        }
    }

    return false;
}

// Returns 0 on error
static uint16_t choose_ephimeral_port(Proc *proc, Addr addr)
{
    uint16_t first = proc->next_ephimeral_port;
    uint16_t *next = &proc->next_ephimeral_port;
    do {
        uint16_t port = (*next)++;
        if (!addr_in_use(proc, addr, port))
            return port;
    } while (*next != first);
    return 0;
}

static bool interf_exists_locally(Proc *proc, Addr addr)
{
    for (int i = 0; i < proc->num_addrs; i++)
        if (addr_eql(proc->addrs[i], addr))
            return true;
    return false;
}

static Nanos pick_bind_duration(Proc *proc)
{
    (void) proc;
    return 200;
}

int proc_bind(Proc *proc, int desc_idx, Addr addr, uint16_t port)
{
    /////////////////////////////////////////////////////////
    // Check index

    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    /////////////////////////////////////////////////////////
    // Check descriptor

    if (!is_socket(desc))
        return PROC_ERROR_NOTSOCK;

    if (proc->desc[desc_idx].type != DESC_SOCKET)
        return PROC_ERROR_CANTBIND;

    if (desc->is_explicitly_bound)
        return PROC_ERROR_CANTBIND;

    /////////////////////////////////////////////////////////
    // Check address

    if (addr.family != desc->bound_addr.family)
        return PROC_ERROR_BADFAM;

    if (!interf_exists_locally(proc, addr))
        return PROC_ERROR_NOTAVAIL;

    /////////////////////////////////////////////////////////
    // Check port

    if (port == 0) {
        port = choose_ephimeral_port(proc, addr);
        if (port == 0)
            return PROC_ERROR_NOTAVAIL;
    } else {
        if (addr_in_use(proc, addr, port))
            return PROC_ERROR_ADDRUSED;
    }

    /////////////////////////////////////////////////////////
    // Perform the binding

    desc->is_explicitly_bound = true;
    desc->bound_addr = addr;
    desc->bound_port = port;

    /////////////////////////////////////////////////////////
    proc->current_time += pick_bind_duration(proc);
    return 0;
}

static Nanos pick_listen_duration(Proc *proc)
{
    (void) proc;
    return 200;
}

int proc_listen(Proc *proc, int desc_idx, int backlog)
{
    if (backlog <= 0)
        backlog = DEFAULT_BACKLOG;

    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    if (desc->type != DESC_SOCKET) {
        if (is_socket(desc))
            return PROC_ERROR_BADARG;
        return PROC_ERROR_NOTSOCK;
    }

    if (!desc->is_explicitly_bound) {
        // We need to bind implicitly
        //
        // The bound_addr field already contains the right
        // family and a zero address. The port is 0, which
        // is not a valid value.
        desc->bound_port = choose_ephimeral_port(proc, desc->bound_addr);
        if (desc->bound_port == 0)
            return PROC_ERROR_ADDRUSED;
    }

    if (accept_queue_init(&desc->accept_queue, backlog) < 0)
        return PROC_ERROR_NOMEM;

    desc->type = DESC_SOCKET_L;

    proc->current_time += pick_listen_duration(proc);
    return 0;
}

static Nanos pick_accept_duration(Proc *proc)
{
    (void) proc;
    return 1000;
}

int proc_accept(Proc *proc, int desc_idx, Addr *addr, uint16_t *port)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    if (desc->type != DESC_SOCKET_L) {
        if (is_socket(desc))
            return PROC_ERROR_BADARG;
        return PROC_ERROR_NOTSOCK;
    }

    // TODO: check that the socket is non-blocking

    int new_desc_idx = find_empty_desc_struct(proc);
    if (new_desc_idx < 0)
        return PROC_ERROR_FULL;
    Desc *new_desc = &proc->desc[new_desc_idx];

    Desc *peer;
    if (accept_queue_pop(&desc->accept_queue, &peer) < 0)
        return PROC_ERROR_WOULDBLOCK;

    *addr = peer->bound_addr;
    *port = peer->bound_port;

    new_desc->type = DESC_SOCKET_C;
    new_desc->non_blocking = false;
    new_desc->connect_addr = peer->bound_addr;
    new_desc->connect_port = peer->bound_port;
    new_desc->connect_time = proc->current_time;
    new_desc->connect_delay = 0;
    new_desc->num_transf = 0;
    new_desc->bytes_per_sec = 100000; // TODO: pick this at random
    new_desc->peer = peer;
    new_desc->rst  = false;
    new_desc->hup  = false;
    socket_queue_init(&new_desc->input, 1<<12);
    socket_queue_init(&new_desc->output, 1<<12);

    proc->current_time += pick_accept_duration(proc);
    return new_desc_idx;
}

static Nanos pick_connect_delay(Proc *proc)
{
    return 10000000; // TODO: make this random
}

static Nanos pick_connect_duration(Proc *proc)
{
    (void) proc;
    return 10000;
}

// TODO: check error codes returned by this function
int proc_connect(Proc *proc, int desc_idx,
    Addr addr, uint16_t port)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    if (desc->type != DESC_SOCKET) {
        if (is_socket(desc))
            return PROC_ERROR_BADARG;
        return PROC_ERROR_NOTSOCK;
    }

    if (!desc->is_explicitly_bound) {
        // We need to bind implicitly
        //
        // The bound_addr field already contains the right
        // family and a zero address. The port is 0, which
        // is not a valid value.
        desc->bound_port = choose_ephimeral_port(proc, desc->bound_addr);
        if (desc->bound_port == 0)
            return PROC_ERROR_ADDRUSED;
    }

    // TODO: some percent of times connect() should resolve immediately

    desc->connect_addr = addr;
    desc->connect_port = port;
    desc->connect_time  = proc->current_time;
    desc->connect_delay = pick_connect_delay(proc);
    desc->num_transf = 0;
    desc->bytes_per_sec = 100000; // TODO: pick this at random
    desc->peer = NULL;
    desc->rst = false;
    desc->hup = false;
    socket_queue_init(&desc->input, 1<<12);
    socket_queue_init(&desc->output, 1<<12);

    desc->type = DESC_SOCKET_C;

    proc->current_time += pick_connect_duration(proc);
    return 0;
}

static Nanos pick_open_file_duration(Proc *proc)
{
    (void) proc;
    return 1500;
}

int proc_open_file(Proc *proc, char *path, int flags)
{
    int desc_idx = find_empty_desc_struct(proc);
    if (desc_idx < 0)
        return PROC_ERROR_FULL;
    Desc *desc = &proc->desc[desc_idx];

    int converted_flags = 0; // TODO: convert flags

    int ret = lfs_file_open(&proc->lfs, &desc->file, path, converted_flags);
    if (ret < 0) {
        assert(0); // TODO
    }

    desc->type = DESC_FILE;
    desc->non_blocking = false;

    proc->current_time += pick_open_file_duration(proc);
    return desc_idx;
}

static Nanos pick_open_dir_duration(Proc *proc)
{
    (void) proc;
    return 1500;
}

int proc_open_dir(Proc *proc, char *path)
{
    int desc_idx = find_empty_desc_struct(proc);
    if (desc_idx < 0)
        return PROC_ERROR_FULL;
    Desc *desc = &proc->desc[desc_idx];

    int ret = lfs_dir_open(&proc->lfs, &desc->dir, path);
    if (ret < 0) {
        assert(0); // TODO
    }

    desc->type = DESC_DIRECTORY;
    desc->non_blocking = false;

    proc->current_time += pick_open_dir_duration(proc);
    return desc_idx;
}

static int recv_inner(Desc *desc, char *dst, int len)
{
    // TODO: check that the descriptor is non-blocking

    if (desc->peer == NULL) {
        if (desc->rst)
            return PROC_ERROR_RESET;
        if (desc->hup)
            return PROC_ERROR_HANGUP;
        return PROC_ERROR_NOTCONN;
    }

    int ret = socket_queue_read(&desc->input, dst, len);
    if (ret == 0)
        return PROC_ERROR_WOULDBLOCK;

    return ret;
}

static int send_inner(Desc *desc, char *src, int len)
{
    // TODO: check that the descriptor is non-blocking

    if (desc->peer == NULL) {
        if (desc->rst)
            return PROC_ERROR_RESET;
        if (desc->hup)
            return PROC_ERROR_HANGUP;
        return PROC_ERROR_NOTCONN;
    }

    int ret = socket_queue_write(&desc->output, src, len);
    if (ret == 0)
        return PROC_ERROR_WOULDBLOCK;

    return ret;
}

static Nanos pick_read_duration(Proc *proc)
{
    (void) proc;
    return 400;
}

int proc_read(Proc *proc, int desc_idx, char *dst, int len)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    int num = 0;
    if (desc->type == DESC_SOCKET_C) {
        num = recv_inner(desc, dst, len);
    } else if (desc->type == DESC_FILE) {
        // TODO: what if the file wasn't open for reading?
        lfs_ssize_t ret = lfs_file_read(&proc->lfs, &desc->file, dst, len);
        if (ret < 0)
            return PROC_ERROR_IO;
        num = ret;
    } else {
        if (desc->type == DESC_DIRECTORY)
            return PROC_ERROR_ISDIR;
        return PROC_ERROR_BADARG;
    }

    proc->current_time += pick_read_duration(proc);
    return num;
}

static Nanos pick_write_duration(Proc *proc)
{
    (void) proc;
    return 400;
}

int proc_write(Proc *proc, int desc_idx, char *src, int len)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    int num = 0;
    if (desc->type == DESC_SOCKET_C) {
        num = send_inner(desc, src, len);
    } else if (desc->type == DESC_FILE) {
        // TODO: what if the file wasn't open for writing?
        lfs_ssize_t ret = lfs_file_write(&proc->lfs, &desc->file, src, len);
        if (ret < 0)
            return PROC_ERROR_IO; // TODO: this may be imprecise
        num = ret;
    } else {
        return PROC_ERROR_BADIDX;
    }

    proc->current_time += pick_write_duration(proc);
    return num;
}

static Nanos pick_recv_duration(Proc *proc)
{
    (void) proc;
    return 300;
}

int proc_recv(Proc *proc, int desc_idx, char *dst, int len)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    int num = 0;
    if (desc->type == DESC_SOCKET_C) {
        num = recv_inner(desc, dst, len);
    } else {
        if (!is_socket(desc))
            return PROC_ERROR_NOTSOCK;
        assert(0); // TODO
    }

    proc->current_time += pick_recv_duration(proc);
    return num;
}

static Nanos pick_send_duration(Proc *proc)
{
    (void) proc;
    return 300;
}

int proc_send(Proc *proc, int desc_idx, char *src, int len)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    int num = 0;
    if (desc->type == DESC_SOCKET_C) {
        num = send_inner(desc, src, len);
    } else {
        assert(0); // TODO
    }

    proc->current_time += pick_send_duration(proc);
    return num;
}
