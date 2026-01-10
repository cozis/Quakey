#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

#include <stdbool.h>

struct pollfd;

typedef struct {
    int fd;
    bool connected;

    int  input_used;
    char input[1<<9];

    int  output_used;
    char output[1<<9];

    int next_word;
} Client;

int client_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap,
    int *pnum, int *timeout);

int client_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int client_free(void *state);

#endif // CLIENT_INCLUDED