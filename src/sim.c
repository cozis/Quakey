#include <assert.h>
#include <stdlib.h>

#include "sim.h"
#include "proc.h"

int quakey_sim_init(QuakeySim **psim)
{
    QuakeySim *sim = malloc(sizeof(QuakeySim));
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
}

#define SPAWN_ARG_LIMIT 128

int quakey_sim_spawn(QuakeySim *sim, QuakeySpawnConfig config, char *arg)
{
    Proc *proc = malloc(sizeof(Proc));
    if (proc == NULL)
        return -1;

    if (config.num_addrs > PROC_IPADDR_LIMIT) {
        free(proc);
        return -1;
    }
    Addr parsed_addrs[PROC_IPADDR_LIMIT];
    for (int i = 0; i < config.num_addrs; i++) {
        if (addr_parse(config.addrs[i], &parsed_addrs[i]) < 0) {
            free(proc);
            return -1;
        }
    }

    arg = strdup(arg);
    int argc = 0;
    char *argv[SPAWN_ARG_LIMIT];
    for (int cur = 0, len = strlen(arg);; ) {

        while (cur < len && (arg[cur] == ' ' || arg[cur] == '\t'))
            cur++;

        if (cur == len)
            break;

        int off = cur;

        while (cur < len && arg[cur] != ' ' && arg[cur] != '\t')
            cur++;

        arg[cur] = '\0';
        cur++;

        if (argc == SPAWN_ARG_LIMIT) {
            free(arg);
            free(proc);
            return -1;
        }
        argv[argc++] = arg + off;
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
        argc,
        argv
    );
    if (ret < 0) {
        free(arg);
        free(proc);
        return -1;
    }

    if (sim->num_procs == sim->max_procs) {
        int max_procs = sim->max_procs ? 2 * sim->max_procs : 8;
        Proc **procs = realloc(sim->procs, sizeof(Proc*) * max_procs);
        if (procs == NULL) {
            free(arg);
            proc_free(proc);
            return -1;
        }
        sim->max_procs = max_procs;
        sim->procs = procs;
    }

    sim->procs[sim->num_procs++] = proc;

    free(arg);
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
