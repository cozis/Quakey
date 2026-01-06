#ifndef SERVER_INCLUDED
#define SERVER_INCLUDED

struct pollfd;

typedef struct {
} Server;

int server_init(void *state, int argc, char **argv,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int server_tick(void *state, struct pollfd *pdata,
    int pcap, int *pnum, int *timeout);

int server_free(void *state);

#endif // SERVER_INCLUDED