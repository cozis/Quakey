
#ifdef MAIN_SIMULATION
#include <quakey.h>
#else
#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif
#define POLL_CAPACITY 1024
#endif

#include "client.h"
#include "server.h"

#ifdef MAIN_SERVER
int main(int argc, char **argv)
{
    int ret;
    Server state;

    struct pollfd poll_array[POLL_CAPACITY];
    int poll_count;
    int poll_timeout;

    ret = server_init(
        &state,
        argc,
        argv,
        poll_array,
        POLL_CAPACITY,
        &poll_count,
        &poll_timeout
    );
    if (ret < 0)
        return -1;

    for (;;) {

#ifdef _WIN32
        WSAPoll(poll_array, poll_count, poll_timeout);
#else
        poll(poll_array, poll_count, poll_timeout);
#endif

        ret = server_tick(
            &state,
            poll_array,
            POLL_CAPACITY,
            &poll_count,
            &poll_timeout
        );
        if (ret < 0)
            return -1;
    }

    server_free(&state);
    return 0;
}
#endif

#ifdef MAIN_CLIENT
int main(int argc, char **argv)
{
    int ret;
    Client state;

    struct pollfd poll_array[POLL_CAPACITY];
    int poll_count;
    int poll_timeout;

    ret = client_init(
        &state,
        argc,
        argv,
        poll_array,
        POLL_CAPACITY,
        &poll_count,
        &poll_timeout
    );
    if (ret < 0)
        return -1;

    for (;;) {

#ifdef _WIN32
        WSAPoll(poll_array, poll_count, poll_timeout);
#else
        poll(poll_array, poll_count, poll_timeout);
#endif

        ret = client_tick(
            &state,
            poll_array,
            POLL_CAPACITY,
            &poll_count,
            &poll_timeout
        );
        if (ret < 0)
            return -1;
    }

    client_free(&state);
    return 0;
}
#endif

#ifdef MAIN_SIMULATION
int main(void)
{
    Quakey *quakey;
    int ret = quakey_init(&quakey);
    if (ret < 0)
        return -1;

    // Client
    {
        QuakeySpawn config = {
            .state_size = sizeof(Client),
            .init_func  = client_init,
            .tick_func  = client_tick,
            .free_func  = client_free,
            .addrs      = (char*[]) { "127.0.0.2" },
            .num_addrs  = 1,
            .disk_size  = 1<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "");
    }

    // Server
    {
        QuakeySpawn config = {
            .state_size = sizeof(Server),
            .init_func  = server_init,
            .tick_func  = server_tick,
            .free_func  = server_free,
            .addrs      = (char*[]) { "127.0.0.3" },
            .num_addrs  = 1,
            .disk_size  = 1<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "");
    }

    for (;;)
        quakey_schedule_one(quakey);

    quakey_free(quakey);
    return 0;
}
#endif // MAIN_SIMULATION
