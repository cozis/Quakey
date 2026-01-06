#include <stddef.h>
#include <string.h>
#include <assert.h>
#ifdef MAIN_SIMULATION
#   define QUAKEY_ENABLE_MOCKS
#   include <quakey.h>
#else
#   include <stdio.h>
#   ifdef _WIN32
#       include <winsock2.h>
#   else
#       include <poll.h>
#       include <errno.h>
#       include <unistd.h>
#       include <sys/socket.h>
#       include <arpa/inet.h>
#   endif
#endif

#include "utils.h"
#include "server.h"

int server_init(void *state, int argc, char **argv,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    Server *server = state;

    server->listen_fd = -1;
    server->client_fd = -1;
    server->input_used = 0;
    server->output_used = 0;

    (void) argc; // TODO: use these
    (void) argv;

    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd < 0)
        return -1;

    int port = 8080;

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_port   = htons(port);
    bind_buf.sin_addr.s_addr = INADDR_ANY;
    if (bind(server->listen_fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) {
#ifdef _WIN32
        closesocket(server->listen_fd);
#else
        close(server->listen_fd);
#endif
        return -1;
    }

    int backlog = 32;
    if (listen(server->listen_fd, backlog) < 0) {
#ifdef _WIN32
        closesocket(server->listen_fd);
#else
        close(server->listen_fd);
#endif
        return -1;
    }

    printf("Server initialized\n");

    if (pcap > 0) {
        pdata[0].fd = server->listen_fd;
        pdata[0].events = POLLIN;
        pdata[0].revents = 0;
        *pnum = 1;
    }
    *timeout = -1;
    return 0;
}

static int process_message(Server *server)
{
    int i = 0;
    while (i < server->input_used && server->input[i] != '\n')
        i++;
    if (i == server->input_used) {
        if (server->input_used == sizeof(server->input))
            return -1;
        return 0;
    }
    i++; // Consume the \n

    char *str = server->input;
    int   len = i;

    printf("server :: Received [%.*s]\n", len-1, str);

    if ((int) sizeof(server->output) - server->output_used < len)
        return -1; // Not enough space in the output buffer

    memcpy(server->output + server->output_used, str, len);
    server->output_used += len;

    memmove(server->input, server->input + i, server->input_used - i);
    server->input_used -= i;

    return 1;
}

int server_tick(void *state, struct pollfd *pdata,
    int pcap, int *pnum, int *timeout)
{
    Server *server = state;

    if (server->client_fd < 0) {
        if (pdata[0].revents & POLLIN) {
            int fd = accept(server->listen_fd, NULL, NULL);
            if (fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    printf("server :: accept() failure\n");
                    return -1;
                }
                *pnum = 0;
                if (pcap > 0) {
                    pdata[0].fd = server->listen_fd;
                    pdata[0].events = POLLIN;
                    pdata[0].revents = 0;
                    *pnum = 1;
                }
            } else {
                server->client_fd = fd;
                *pnum = 0;
                if (pcap > 0) {
                    int events = POLLIN;
                    if (server->output_used > 0)
                        events |= POLLOUT;
                    pdata[0].fd = server->client_fd;
                    pdata[0].events = events;
                    pdata[0].revents = 0;
                    *pnum = 1;
                }
            }
        } else {
            *pnum = 0;
            if (pcap > 0) {
                pdata[0].fd = server->listen_fd;
                pdata[0].events = POLLIN;
                pdata[0].revents = 0;
                *pnum = 1;
            }
        }
    } else {

        if (pdata[0].revents & (POLLIN | POLLERR)) {
            for (;;) {
                if (server->input_used == sizeof(server->input)) {
                    printf("server :: Invalid recv into full buffer\n");
                    return -1;
                }
                int ret = recv(
                    server->client_fd,
                    server->input + server->input_used,
                    sizeof(server->input) - server->input_used,
                    0
                );
                if (ret == 0) {
                    // TODO
                }
                if (ret < 0) {
                    if (errno == EWOULDBLOCK || errno == EAGAIN)
                        break;
                    printf("server :: send() failed\n");
                    return -1;
                }
                server->input_used += ret;

                for (;;) {
                    int ret = process_message(server);
                    if (ret < 0) {
                        printf("server :: Invalid message\n");
                        return -1;
                    }
                    if (ret == 0)
                        break;
                    assert(ret == 1);
                }
            }
        }

        if (pdata[0].revents & POLLOUT) {
            int sent = 0;
            while (sent < server->output_used) {
                int ret = send(
                    server->client_fd,
                    server->output + sent,
                    server->output_used - sent,
                    0
                );
                if (ret < 0) {
                    if (errno == EWOULDBLOCK || errno == EAGAIN)
                        break;
                    printf("server :: send() failed\n");
                    return -1;
                }
                sent += ret;
            }
            memmove(
                server->output,
                server->output + sent,
                server->output_used - sent
            );
            server->output_used -= sent;
        }

        *pnum = 0;
        if (pcap > 0) {
            int events = POLLIN;
            if (server->output_used > 0)
                events |= POLLOUT;
            pdata[0].fd = server->client_fd;
            pdata[0].events = events;
            pdata[0].revents = 0;
            *pnum = 1;
        }
    }

    *timeout = -1;
    return 0;
}

int server_free(void *state)
{
    Server *server = state;

#ifdef _WIN32
    closesocket(server->listen_fd);
#else
    close(server->listen_fd);
#endif

    if (server->client_fd > -1) {
#ifdef _WIN32
        closesocket(server->listen_fd);
#else
        close(server->listen_fd);
#endif
    }

    printf("free server\n");
    return 0;
}