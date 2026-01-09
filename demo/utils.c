
#ifdef MAIN_SIMULATION
#define QUAKEY_ENABLE_MOCKS
#include <quakey.h>
#else
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#include <fcntl.h>
#endif
#endif

#include <stdint.h>

#include "utils.h"

// Returns the current time in nanoseconds since
// an unspecified time in the past (useful to calculate
// elapsed time intervals)
Time get_current_time(void)
{
#ifdef _WIN32
    {
        int64_t count;
        int64_t freq;
        int ok;

        ok = QueryPerformanceCounter((LARGE_INTEGER*) &count);
        if (!ok) return INVALID_TIME;

        ok = QueryPerformanceFrequency((LARGE_INTEGER*) &freq);
        if (!ok) return INVALID_TIME;

        uint64_t res = 1000000000 * (double) count / freq;
        return res;
    }
#else
    {
        struct timespec time;

        if (clock_gettime(CLOCK_REALTIME, &time))
            return INVALID_TIME;

        uint64_t res;

        uint64_t sec = time.tv_sec;
        if (sec > UINT64_MAX / 1000000000)
            return INVALID_TIME;
        res = sec * 1000000000;

        uint64_t nsec = time.tv_nsec;
        if (res > UINT64_MAX - nsec)
            return INVALID_TIME;
        res += nsec;

        return res;
    }
#endif
}

int set_socket_blocking(SOCKET sock, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR)
        return -1;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (value) flags &= ~O_NONBLOCK;
    else       flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
#endif

    return 0;
}