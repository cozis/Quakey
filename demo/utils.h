#ifndef UTILS_INCLUDED
#define UTILS_INCLUDED

#include <stdbool.h>

#ifdef _WIN32
#define SOCKET void*
#else
#define SOCKET int
#endif

typedef unsigned long long Time;

#define INVALID_TIME (~(Time) 0)

Time get_current_time(void);
int set_socket_blocking(SOCKET sock, bool value);

#endif // UTILS_INCLUDED