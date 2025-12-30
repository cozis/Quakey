#include "sim.h"
#include "3p/rpmalloc.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

// Forward-declare here to avoid including stdlib.h
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
}

static int parse_ipv4(char *src, int len, int *pcur, AddrIPv4 *ipv4)
{
    int cur = *pcur;

	unsigned int out = 0;
	int i = 0;
	for (;;) {

		if (cur == len || !is_digit(src[cur]))
			return -1;

		int b = 0;
		do {
			int x = src[cur++] - '0';
			if (b > (UINT8_MAX - x) / 10)
				return -1;
			b = b * 10 + x;
		} while (cur < len && is_digit(src[cur]));

		out <<= 8;
		out |= (unsigned char) b;

		i++;
		if (i == 4)
			break;

		if (cur == len || src[cur] != '.')
			return -1;
		cur++;
	}

	ipv4->data = out;

	*pcur = cur;
	return 0;
}

static int hex_digit_to_int(char c)
{
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= '0' && c <= '9') return c - '0';
	return -1;
}

static int parse_ipv6_comp(char *src, int len, int *pcur)
{
    int cur = *pcur;

	unsigned short buf;
	if (cur == len || !is_hex_digit(src[cur]))
		return -1;
	buf = hex_digit_to_int(src[cur]);
	cur++;

	if (cur == len || !is_hex_digit(src[cur])) {
	    *pcur = cur;
		return buf;
	}
	buf <<= 4;
	buf |= hex_digit_to_int(src[cur]);
	cur++;

	if (cur == len || !is_hex_digit(src[cur])) {
	    *pcur = cur;
		return buf;
	}
	buf <<= 4;
	buf |= hex_digit_to_int(src[cur]);
	cur++;

	if (cur == len || !is_hex_digit(src[cur])) {
	    *pcur = cur;
		return buf;
	}
	buf <<= 4;
	buf |= hex_digit_to_int(src[cur]);
	cur++;

	*pcur = cur;
	return (int) buf;
}

static int parse_ipv6(char *src, int len, int *pcur, AddrIPv6 *ipv6)
{
    int cur = *pcur;

	unsigned short head[8];
	unsigned short tail[8];
	int head_len = 0;
	int tail_len = 0;

	if (len - cur > 1
		&& src[cur+0] == ':'
		&& src[cur+1] == ':')
		cur += 2;
	else {

		for (;;) {

			int ret = parse_ipv6_comp(src, len, &cur);
			if (ret < 0) return ret;

			head[head_len++] = (unsigned short) ret;
			if (head_len == 8) break;

			if (cur == len || src[cur] != ':')
				return -1;
			cur++;

			if (cur < len && src[cur] == ':') {
				cur++;
				break;
			}
		}
	}

	if (head_len < 8) {
		while (cur < len && is_hex_digit(src[cur])) {

			int ret = parse_ipv6_comp(src, len, &cur);
			if (ret < 0) return ret;

			tail[tail_len++] = (unsigned short) ret;
			if (head_len + tail_len == 8) break;

			if (cur == len || src[cur] != ':')
				break;
			cur++;
		}
	}

	for (int i = 0; i < head_len; i++)
		ipv6->data[i] = head[i];

	for (int i = 0; i < 8 - head_len - tail_len; i++)
		ipv6->data[head_len + i] = 0;

	for (int i = 0; i < tail_len; i++)
		ipv6->data[8 - tail_len + i] = tail[i];

	*pcur = cur;
	return 0;
}

int addr_parse(char *src, Addr *dst)
{
    int cur = 0;
    int len = strlen(src);

    if (parse_ipv4(src, len, &cur, &dst->ipv4) == 0) {
        dst->family = ADDR_FAMILY_IPV4;
        return 0;
    }

    cur = 0;
    if (parse_ipv6(src, len, &cur, &dst->ipv6) == 0) {
        dst->family = ADDR_FAMILY_IPV6;
        return 0;
    }

    return -1;
}

int quakey_init(Quakey **psim)
{
    Quakey *sim = rpmalloc(sizeof(Quakey));
    if (sim == NULL)
        return -1;

    sim->next_pid = PID_MIN;
    sim->num_procs = 0;
    sim->max_procs = 0;
    sim->procs = NULL;

    *psim = sim;
    return 0;
}

void quakey_free(Quakey *sim)
{
    for (int i = 0; i < sim->num_procs; i++)
        proc_free(sim->procs[i]);

    rpfree(sim->procs);
    rpfree(sim);
}

int quakey_spawn(Quakey *sim, QuakeySpawnConfig config, char *arg)
{
    Proc *proc = rpmalloc(sizeof(Proc));
    if (proc == NULL)
        return -1;

    if (config.num_addrs > PROC_IPADDR_LIMIT) {
        rpfree(proc);
        return -1;
    }
    Addr parsed_addrs[PROC_IPADDR_LIMIT];
    for (int i = 0; i < config.num_addrs; i++) {
        if (addr_parse(config.addrs[i], &parsed_addrs[i]) < 0) {
            rpfree(proc);
            return -1;
        }
    }

    int ret = proc_init(
        proc, sim,
        config.state_size,
        config.init_func,
        config.tick_func,
        config.free_func,
        parsed_addrs,
        config.num_addrs,
        config.disk_size,
        arg
    );
    if (ret < 0) {
        rpfree(proc);
        return -1;
    }

    if (sim->num_procs == sim->max_procs) {
        int max_procs = sim->max_procs ? 2 * sim->max_procs : 8;
        Proc **procs = rprealloc(sim->procs, sizeof(Proc*) * max_procs);
        if (procs == NULL) {
            proc_free(proc);
            return -1;
        }
        sim->max_procs = max_procs;
        sim->procs = procs;
    }

    sim->procs[sim->num_procs++] = proc;
    return 0;
}

static int compare_proc_times(const void *p1, const void *p2)
{
    Proc *proc1 = *(Proc**)p1;
    Proc *proc2 = *(Proc**)p2;
    if (proc1->current_time < proc2->current_time) return -1;
    if (proc1->current_time > proc2->current_time) return  1;
    return 0;
}

bool quakey_schedule_one(Quakey *sim)
{
    if (sim->num_procs == 0)
        return false;

    for (int i = 0; i < sim->num_procs; i++)
        proc_advance_network(sim->procs[i]);

    // Sort processes based on their time
    qsort(sim->procs, sim->num_procs, sizeof(Proc*), compare_proc_times);

    // Process the next ready process
    for (int i = 0; i < sim->num_procs; i++) {
        Proc *proc = sim->procs[i];
        if (proc_ready(proc)) {
            if (proc_tick(proc) < 0) {
                assert(0); // TODO
            }
            return true;
        }
    }

    // If we reached this point, no processes were
    // ready, so advance the time until a timeout occurs

    // Find the process with the most imminent wakeup time
    Proc *chosen_proc = NULL;
    Nanos chosen_wakeup = 0;
    for (int i = 0; i < sim->num_procs; i++) {

        Proc *proc = sim->procs[i];
        if (proc->poll_timeout < 0)
            continue; // No wakeup time set for this process

        Nanos wakeup_time = proc->poll_call_time + proc->poll_timeout * 1000000;
        assert(wakeup_time > proc->current_time);

        if (chosen_proc == NULL || wakeup_time < chosen_wakeup) {
            chosen_proc = proc;
            chosen_wakeup = wakeup_time;
        }
    }
    if (chosen_proc == NULL)
        return false;

    for (int i = 0; i < sim->num_procs; i++)
        if (sim->procs[i]->current_time < chosen_wakeup)
            sim->procs[i]->current_time = chosen_wakeup;

    proc_tick(chosen_proc);
    return true;
}

int sim_find_host(Quakey *sim, Addr addr)
{
    for (int i = 0; i < sim->num_procs; i++)
        if (proc_has_addr(sim->procs[i], addr))
            return i;
    return -1;
}

////////////////////////////////////////////////////////
// PROC

static void desc_free(Desc *desc, lfs_t *lfs, bool rst);
static int  accept_queue_push(AcceptQueue *queue, Desc *desc);
static bool accept_queue_empty(AcceptQueue *queue);
static bool is_bound_to(Desc *desc, Addr addr, uint16_t port);

static Proc *current_proc___;

Proc *proc_current(void)
{
    return current_proc___;
}

static int socket_queue_init(SocketQueue *queue, int size)
{
    char *data = rpmalloc(size);
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
    rpfree(queue->data);
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

    // Block offset
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

static int split_args(char *arg, char **argv, int max_argc)
{
    int argc = 0;
    for (int cur = 0, len = strlen(arg);; ) {

        while (cur < len && (arg[cur] == ' ' || arg[cur] == '\t'))
            cur++;

        if (cur == len)
            break;

        int off = cur;

        while (cur < len && arg[cur] != ' ' && arg[cur] != '\t')
            cur++;

        if (cur < len) {
            arg[cur] = '\0';
            cur++;
        }

        if (argc == max_argc)
            return -1;
        argv[argc++] = arg + off;
    }

    return argc;
}

int proc_init(Proc *proc,
    Quakey *sim,
    int state_size,
    QuakeyInitFunc init_func,
    QuakeyTickFunc tick_func,
    QuakeyFreeFunc free_func,
    Addr *addrs,
    int   num_addrs,
    int   disk_size,
    char *arg)
{
    proc->sim = sim;

    proc->arg = strdup(arg);
    if (proc->arg == NULL)
        return -1;
    proc->argc = split_args(proc->arg, proc->argv, PROC_ARGC_LIMIT);
    if (proc->argc < 0)
        return -1;

    proc->init_func = init_func;
    proc->tick_func = tick_func;
    proc->free_func = free_func;
    proc->os = OS_UNSPECIFIED;
    proc->next_ephemeral_port = FIRST_EPHEMERAL_PORT;

    proc->num_addrs = num_addrs;
    memcpy(proc->addrs, addrs, num_addrs * sizeof(Addr));

    proc->current_time = 0;

    proc->num_desc = 0;
    for (int i = 0; i < PROC_DESC_LIMIT; i++) {
        proc->desc[i].proc = proc;
        proc->desc[i].type = DESC_EMPTY;
    }

    proc->disk_size = disk_size;
    proc->disk_data = rpmalloc(disk_size);
    if (proc->disk_data == NULL) {
        rpfree(proc->arg);
        return -1;
    }

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
            rpfree(proc->disk_data);
            rpfree(proc->arg);
            return -1;
        }
    }

    proc->poll_count = 0;
    proc->poll_timeout = -1;
    proc->poll_call_time = 0;
    proc->errno_ = 0;

    void *state = rpmalloc(state_size);
    if (state == NULL) {
        lfs_unmount(&proc->lfs);
        rpfree(proc->disk_data);
        rpfree(proc->arg);
        return -1;
    }

    current_proc___ = proc;
    ret = init_func(state, proc->argc, proc->argv, proc->poll_array, PROC_DESC_LIMIT, &proc->poll_count, &proc->poll_timeout);
    current_proc___ = NULL;
    if (ret < 0) {
        rpfree(state);
        lfs_unmount(&proc->lfs);
        rpfree(proc->disk_data);
        rpfree(proc->arg);
        return -1;
    }

    proc->state = state;
    proc->state_size = state_size;
    return 0;
}

void proc_free(Proc *proc)
{
    current_proc___ = proc;
    proc->free_func(proc->state);
    current_proc___ = NULL;

    rpfree(proc->arg);

    rpfree(proc->state);

    lfs_unmount(&proc->lfs);
    rpfree(proc->disk_data);

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
    rpfree(proc->state);

    // Close all descriptors
    for (int i = 0; i < PROC_DESC_LIMIT; i++)
        if (proc->desc[i].type != DESC_EMPTY)
            desc_free(&proc->desc[i], &proc->lfs, true);
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
    proc->next_ephemeral_port = FIRST_EPHEMERAL_PORT;
    proc->current_time = 0;
    proc->poll_count = 0;
    proc->poll_timeout = -1;
    proc->poll_call_time = 0;
    proc->errno_ = 0;

    // Allocate and initialize new state

    void *state = rpmalloc(proc->state_size);
    if (state == NULL) {
        lfs_unmount(&proc->lfs);
        rpfree(proc->disk_data);
        return -1;
    }

    current_proc___ = proc;
    ret = proc->init_func(state, proc->argc, proc->argv, proc->poll_array, PROC_DESC_LIMIT, &proc->poll_count, &proc->poll_timeout);
    current_proc___ = NULL;
    if (ret < 0) {
        rpfree(state);
        lfs_unmount(&proc->lfs);
        rpfree(proc->disk_data);
        return -1;
    }

    proc->state = state;
    return 0;
}

void proc_advance_network(Proc *proc)
{
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
                if (desc->connect_time + desc->connect_delay < proc->current_time) {

                    // Resolve connect()

                    int idx = sim_find_host(proc->sim, desc->connect_addr);
                    if (idx < 0) {
                        desc->rst = true; // TODO: this isn't exactly correct. This should mark that the host is unreachable
                        continue;
                    }
                    Proc *peer_proc = proc->sim->procs[idx];

                    Desc *peer = proc_find_desc_bound_to(peer_proc, desc->connect_addr, desc->connect_port);
                    if (peer == NULL) {
                        // Peer host exists but the port isn't open. Reset the connection.
                        desc->rst = true;
                        continue;
                    }

                    assert(peer->type == DESC_SOCKET_L);
                    if (accept_queue_push(&peer->accept_queue, desc) < 0) {
                        // Accept queue is full
                        desc->rst = true;
                        continue;
                    }

                    desc->peer = peer; // Resolved!
                }
            }
        } else {
            if (desc->peer->type == DESC_SOCKET_C) {
                // Receive some bytes from peer

                // Preserve causality by considering the lower time
                // of the communicating processes
                Nanos effective_time = MIN(proc->current_time, desc->peer->proc->current_time);

                Nanos elapsed = effective_time - desc->connect_time;
                uint64_t max_transf = (desc->bytes_per_sec * elapsed) / 1000000000;

                int transf = 0;
                if (desc->num_transf < max_transf)
                    transf = max_transf - desc->num_transf;

                int num = socket_queue_move(&desc->input, &desc->peer->output, transf);
                desc->num_transf += num;
            }
        }
    }
}

int proc_tick(Proc *proc)
{
    proc->poll_call_time = proc->current_time;
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

int *proc_errno_ptr(Proc *proc)
{
    return &proc->errno_;
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

Desc *proc_find_desc_bound_to(Proc *proc, Addr addr, uint16_t port)
{
    for (int i = 0, j = 0; j < proc->num_desc; i++) {

        Desc *desc = &proc->desc[i];
        if (desc->type == DESC_EMPTY)
            continue;
        j++;

        if (is_bound_to(desc, addr, port))
            return desc;
    }

    return NULL;
}

static int accept_queue_init(AcceptQueue *queue, int capacity)
{
    Desc **entries = rpmalloc(capacity * sizeof(Desc*));
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
    rpfree(queue->entries);
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
    proc->num_desc++;

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
    proc->num_desc--;

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
static uint16_t choose_ephemeral_port(Proc *proc, Addr addr)
{
    uint16_t first = proc->next_ephemeral_port;
    uint16_t *next = &proc->next_ephemeral_port;
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
        port = choose_ephemeral_port(proc, addr);
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
        desc->bound_port = choose_ephemeral_port(proc, desc->bound_addr);
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

    Addr local_addr = desc->bound_addr;
    if (is_zero_addr(local_addr)) {
        assert(proc->num_addrs > 0);
        local_addr = proc->addrs[0];
    }

    new_desc->type = DESC_SOCKET_C;
    new_desc->non_blocking = false;
    new_desc->bound_addr = local_addr;
    new_desc->bound_port = desc->bound_port;
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
    proc->num_desc++;

    // Update the peer's end of the connection
    peer->peer = new_desc;

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
        desc->bound_port = choose_ephemeral_port(proc, desc->bound_addr);
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

    int ret = lfs_file_open(&proc->lfs, &desc->file, path, flags);
    if (ret < 0) {
        assert(0); // TODO
    }

    desc->type = DESC_FILE;
    desc->non_blocking = false;
    proc->num_desc++;

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
    proc->num_desc++;

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

static Nanos pick_mkdir_duration(Proc *proc)
{
    (void) proc;
    return 100000;
}

int proc_mkdir(Proc *proc, char *path)
{
    int ret = lfs_mkdir(&proc->lfs, path);
    if (ret < 0) {
        switch (ret) {
        case LFS_ERR_EXIST:
            return PROC_ERROR_EXISTS;
        case LFS_ERR_NOENT:
            return PROC_ERROR_NOENT;
        default:
            return PROC_ERROR_IO;
        }
    }
    proc->current_time += pick_mkdir_duration(proc);
    return 0;
}

static Nanos pick_remove_duration(Proc *proc)
{
    (void) proc;
    return 300000;
}

int proc_remove(Proc *proc, char *path)
{
    int ret = lfs_remove(&proc->lfs, path);
    if (ret < 0) {
        switch (ret) {
        case LFS_ERR_NOENT:
            return PROC_ERROR_NOENT;
        case LFS_ERR_NOTEMPTY:
            return PROC_ERROR_NOTEMPTY;
        default:
            return PROC_ERROR_IO;
        }
    }
    proc->current_time += pick_remove_duration(proc);
    return 0;
}

static Nanos pick_rename_duration(Proc *proc)
{
    (void) proc;
    return 300000;
}

int proc_rename(Proc *proc, char *oldpath, char *newpath)
{
    int ret = lfs_rename(&proc->lfs, oldpath, newpath);
    if (ret < 0) {
        switch (ret) {
        case LFS_ERR_NOENT:
            return PROC_ERROR_NOENT;
        case LFS_ERR_EXIST:
            return PROC_ERROR_EXIST;
        case LFS_ERR_NOTEMPTY:
            return PROC_ERROR_NOTEMPTY;
        case LFS_ERR_ISDIR:
            return PROC_ERROR_ISDIR;
        default:
            return PROC_ERROR_IO;
        }
    }
    proc->current_time += pick_rename_duration(proc);
    return 0;
}

static Nanos pick_fileinfo_duration(Proc *proc)
{
    (void) proc;
    return 1000;
}

int proc_fileinfo(Proc *proc, int desc_idx, FileInfo *info)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    switch (desc->type) {
    case DESC_FILE:
        {
            lfs_soff_t size = lfs_file_size(&proc->lfs, &desc->file);
            if (size < 0)
                return PROC_ERROR_IO;
            info->size   = size;
            info->is_dir = false;
        }
        break;
    case DESC_DIRECTORY:
        {
            info->size   = 0;
            info->is_dir = true;
        }
        break;
    default:
        return PROC_ERROR_BADIDX;
    }

    proc->current_time += pick_fileinfo_duration(proc);
    return 0;
}

static Nanos pick_lseek_duration(Proc *proc)
{
    (void) proc;
    return 100;
}

int proc_lseek(Proc *proc, int desc_idx, int64_t offset, int whence)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    if (desc->type != DESC_FILE)
        return PROC_ERROR_BADIDX;

    int lfs_whence;
    switch (whence) {
    case PROC_SEEK_SET:
        lfs_whence = LFS_SEEK_SET;
        break;
    case PROC_SEEK_CUR:
        lfs_whence = LFS_SEEK_CUR;
        break;
    case PROC_SEEK_END:
        lfs_whence = LFS_SEEK_END;
        break;
    default:
        return PROC_ERROR_BADARG;
    }

    lfs_soff_t ret = lfs_file_seek(&proc->lfs, &desc->file, (lfs_soff_t) offset, lfs_whence);
    if (ret < 0)
        return PROC_ERROR_BADARG;

    proc->current_time += pick_lseek_duration(proc);
    return ret;
}

static Nanos pick_fsync_duration(Proc *proc)
{
    (void) proc;
    return 500000;
}

int proc_fsync(Proc *proc, int desc_idx)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    if (desc->type != DESC_FILE)
        return PROC_ERROR_BADIDX;

    int ret = lfs_file_sync(&proc->lfs, &desc->file);
    if (ret < 0)
        return PROC_ERROR_IO;

    proc->current_time += pick_fsync_duration(proc);
    return 0;
}

static Nanos pick_setdescflags_duration(Proc *proc)
{
    (void) proc;
    return 500;
}

int proc_setdescflags(Proc *proc, int desc_idx, int flags)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    // TODO: check the descriptor type

    desc->non_blocking = (flags & PROC_FLAG_NONBLOCK) != 0;

    proc->current_time += pick_setdescflags_duration(proc);
    return 0;
}

static Nanos pick_getdescflags_duration(Proc *proc)
{
    (void) proc;
    return 500;
}

int proc_getdescflags(Proc *proc, int desc_idx)
{
    if (!is_desc_idx_valid(proc, desc_idx))
        return PROC_ERROR_BADIDX;
    Desc *desc = &proc->desc[desc_idx];

    // TODO: check the descriptor type

    int flags = 0;
    if (desc->non_blocking)
        flags |= PROC_FLAG_NONBLOCK;

    proc->current_time = pick_getdescflags_duration(proc);
    return flags;
}
