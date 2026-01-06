#ifndef UTILS_INCLUDED
#define UTILS_INCLUDED

typedef unsigned long long Time;

#define INVALID_TIME (~(Time) 0)

Time get_current_time(void);

#endif // UTILS_INCLUDED