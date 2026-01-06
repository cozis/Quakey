#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

struct pollfd;

typedef struct {
} Client;

int client_init(void *state, int argc, char **argv,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int client_tick(void *state, struct pollfd *pdata,
    int pcap, int *pnum, int *timeout);

int client_free(void *state);

#endif // CLIENT_INCLUDED