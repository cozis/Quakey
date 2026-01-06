#include <assert.h>
#include <string.h>
#ifdef MAIN_SIMULATION
#   define QUAKEY_ENABLE_MOCKS
#   include <quakey.h>
#else
#   include <stdio.h>
#   ifdef _WIN32
#       include <winsock2.h>
#   else
#      include <poll.h>
#      include <errno.h>
#      include <unistd.h>
#      include <sys/socket.h>
#      include <arpa/inet.h>
#   endif
#endif

#include "utils.h"
#include "client.h"

static int send_new_message(Client *client)
{
    char *words[] = {
        "Red\n",
        "Blue\n",
        "Green\n",
        "Yellow\n"
    };
    char *word = words[client->next_word++];
    int   wlen = strlen(word);
    if (client->next_word == (int) (sizeof(words)/sizeof(words[0])))
        client->next_word = 0;

    if (wlen > (int) sizeof(client->output) - client->output_used)
        return -1;
    memcpy(client->output + client->output_used, word, wlen);
    client->output_used += wlen;

    printf("client :: sent [%.*s]\n", wlen-1, word);
    return 0;
}

int client_init(void *state, int argc, char **argv,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    Client *client = state;

    client->fd = -1;
    client->connected = false;
    client->input_used = 0;
    client->output_used = 0;
    client->next_word = 0;

    (void) argc; // TODO: use these
    (void) argv;

    char addr[] = "127.0.0.3";
    int  port   = 8080;

    client->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->fd < 0) {
        printf("Couldn't create socket\n");
        return -1;
    }

    struct sockaddr_in connect_buf;
    connect_buf.sin_family = AF_INET;
    connect_buf.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &connect_buf.sin_addr) != 1) {
        printf("Couldn't parse address\n");
        return -1;
    }
    int ret = connect(client->fd, (struct sockaddr*) &connect_buf, sizeof(connect_buf));
    if (ret == 0) {
        // Resolved immediately
        client->connected = true;
        printf("Connection to server resolved immediately\n");
    } else {
        if (errno != EINPROGRESS) {
#ifdef _WIN32
            closesocket(client->fd);
#else
            close(client->fd);
#endif
            return -1;
        }
        // Still pending
        printf("Connection to server is in progress\n");
    }

    printf("Client initialized\n");

    if (send_new_message(client) < 0)
        return -1;

    *pnum = 0;
    if (pcap > 0) {
        pdata[0].fd = client->fd;
        pdata[0].events = POLLOUT;
        pdata[0].revents = 0;
        *pnum = 1;
    }
    *timeout = -1;
    return 0;
}

static int process_message(Client *client)
{
    int i = 0;
    while (i < client->input_used && client->input[i] != '\n')
        i++;
    if (i == client->input_used) {
        if (client->input_used == sizeof(client->input))
            return -1;
        return 0;
    }
    i++; // Consume the \n

    char *str = client->input;
    int   len = i;

    printf("client :: Received [%.*s]\n", len-1, str);

    memmove(client->input, client->input + i, client->input_used - i);
    client->input_used -= i;

    if (send_new_message(client) < 0)
        return -1;

    return 1;
}

int client_tick(void *state, struct pollfd *pdata,
    int pcap, int *pnum, int *timeout)
{
    Client *client = state;

    if (pdata[0].revents & (POLLOUT | POLLERR)) {
        if (!client->connected) {
            int err;
            socklen_t len = sizeof(err);
            if (getsockopt(client->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                // TODO: connection failed
                printf("client :: Couldn't get connection result\n");
                return -1;
            }
            if (err != 0) {
                // TODO: connection failed
                printf("client :: Couldn't establish connection to the server\n");
                return -1;
            }

            printf("client :: Connection established\n");
            client->connected = true;
        }
        int sent = 0;
        while (sent < client->output_used) {
            int ret = send(
                client->fd,
                client->output + sent,
                client->output_used - sent,
                0
            );
            if (ret < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                    break;
                printf("client :: send() failed\n");
                return -1;
            }
            sent += ret;
        }
        memmove(
            client->output,
            client->output + sent,
            client->output_used - sent
        );
        client->output_used -= sent;
    }

    if (pdata[0].revents & POLLIN) {
        for (;;) {
            if (client->input_used == sizeof(client->input)) {
                printf("client :: Bad recv() into full buffer\n");
                return -1;
            }
            int ret = recv(
                client->fd,
                client->input + client->input_used,
                sizeof(client->input) - client->input_used,
                0
            );
            if (ret == 0) {
                // TODO
            }
            if (ret < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                    break;
                printf("client :: send() failed\n");
                return -1;
            }
            client->input_used += ret;

            for (;;) {
                int ret = process_message(client);
                if (ret < 0) {
                    printf("client :: Bad message\n");
                    return -1;
                }
                if (ret == 0)
                    break;
                assert(ret == 1);
            }
        }
    }

    *pnum = 0;
    if (pcap > 0) {
        int events = POLLIN;
        if (client->output_used > 0)
            events |= POLLOUT;
        pdata[0].fd = client->fd;
        pdata[0].events = events;
        pdata[0].revents = 0;
        *pnum = 1;
    }
    *timeout = -1;
    return 0;
}

int client_free(void *state)
{
    Client *client = state;
#ifdef _WIN32
    closesocket(client->fd);
#else
    close(client->fd);
#endif
    return 0;
}
