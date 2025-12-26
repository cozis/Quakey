#include <assert.h>

#include "sim.h"
#include "proc.h"
#include "3p/rpmalloc.h"

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

int quakey_sim_init(QuakeySim **psim)
{
    QuakeySim *sim = rpmalloc(sizeof(QuakeySim));
    if (sim == NULL)
        return -1;

    sim->next_pid = PID_MIN;
    sim->current_time_ns = START_TIME;
    sim->next_proc = 0;
    sim->num_procs = 0;
    sim->max_procs = 0;
    sim->procs = NULL;

    *psim = sim;
    return 0;
}

void quakey_sim_free(QuakeySim *sim)
{
    for (int i = 0; i < sim->num_procs; i++)
        proc_free(sim->procs[i]);

    rpfree(sim->procs);
}

int quakey_sim_spawn(QuakeySim *sim, QuakeySpawnConfig config, char *arg)
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
        rpfree(arg);
        rpfree(proc);
        return -1;
    }

    if (sim->num_procs == sim->max_procs) {
        int max_procs = sim->max_procs ? 2 * sim->max_procs : 8;
        Proc **procs = rprealloc(sim->procs, sizeof(Proc*) * max_procs);
        if (procs == NULL) {
            rpfree(arg);
            proc_free(proc);
            return -1;
        }
        sim->max_procs = max_procs;
        sim->procs = procs;
    }

    sim->procs[sim->num_procs++] = proc;

    rpfree(arg);
    return 0;
}

bool quakey_sim_schedule_one(QuakeySim *sim)
{
    if (sim->num_procs == 0)
        return false;

    for (int i = 0; i < sim->num_procs; i++)
        proc_advance_network(sim->procs[i]);

    assert(sim->next_proc >= 0);
    assert(sim->next_proc < sim->num_procs);

    // Process the next ready process
    for (int i = 0; i < sim->num_procs; i++) {

        Proc *proc = sim->procs[sim->next_proc];
        if (proc_ready(proc)) {

            // TODO: with a certain probability, restart the process

            if (proc_tick(proc) < 0) {
                assert(0); // TODO
            }
            return true;
        }

        sim->next_proc = (sim->next_proc + 1) % sim->num_procs;
    }

    return false;
}

int sim_find_host(QuakeySim *sim, Addr addr)
{
    for (int i = 0; i < sim->num_procs; i++)
        if (proc_has_addr(sim->procs[i], addr))
            return i;
    return -1;
}
