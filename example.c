#include <quakey.h>

static int example_proc_init(void *state, int argc, char **argv,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout)
{
    (void) state;
    (void) argc;
    (void) argv;
    (void) pdata;
    (void) pcap;
    (void) pnum;
    (void) timeout;
    // TODO
    return -1;
}

static int example_proc_tick(void *state, struct pollfd *pdata,
    int pcap, int *pnum, int *timeout)
{
    (void) state;
    (void) pdata;
    (void) pcap;
    (void) pnum;
    (void) timeout;
    // TODO
    return -1;
}

static int example_proc_free(void *state)
{
    (void) state;
    // TODO
    return -1;
}

int main(void)
{
    Quakey *sim;
    if (quakey_init(&sim) < 0)
        return -1;

    QuakeySpawn config = {
        .state_size = 0,
        .init_func = example_proc_init,
        .tick_func = example_proc_tick,
        .free_func = example_proc_free,
        .addrs = (char*[]) { "127.0.0.2" },
        .num_addrs = 1,
        .disk_size = 1<<20,
    };
    quakey_spawn(sim, config, "");

    for (;;)
        quakey_schedule_one(sim);

    quakey_free(sim);
    return 0;
}
