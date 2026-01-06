
#ifdef MAIN_SIMULATION
#include <quakey.h>
#else
#include <stdio.h>
#endif

#include "client.h"

int client_init(void *state, int argc, char **argv,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    printf("init client\n");
    *pnum = 0;
    *timeout = 1000;
    return 0;
}

int client_tick(void *state, struct pollfd *pdata,
    int pcap, int *pnum, int *timeout)
{
    printf("tick client (%d ms)\n", (int) (get_current_time() / 1000000));
    *pnum = 0;
    *timeout = 1000;
    return 0;
}

int client_free(void *state)
{
    printf("free client\n");
    return 0;
}
