#ifndef SERVER_INCLUDED
#define SERVER_INCLUDED

struct pollfd;

typedef struct {

    int listen_fd;
    int client_fd;

    int  input_used;
    char input[1<<9];

    int  output_used;
    char output[1<<9];
} Server;

int server_init(void *state, int argc, char **argv,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int server_tick(void *state, struct pollfd *pdata,
    int pcap, int *pnum, int *timeout);

int server_free(void *state);

#endif // SERVER_INCLUDED