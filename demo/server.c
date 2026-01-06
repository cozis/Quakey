
#ifdef MAIN_SIMULATION
#include <quakey.h>
#else
#include <stdio.h>
#endif

#include "utils.h"
#include "server.h"

int server_init(void *state, int argc, char **argv,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    printf("init server\n");
    *pnum = 0;
    *timeout = 1000;
    return 0;
}

int server_tick(void *state, struct pollfd *pdata,
    int pcap, int *pnum, int *timeout)
{
    printf("tick server (%d ms)\n", (int) (get_current_time() / 1000000));
    *pnum = 0;
    *timeout = 1000;
    return 0;
}

int server_free(void *state)
{
    printf("free server\n");
    return 0;
}