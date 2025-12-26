#ifndef POLL_INCLUDED
#define POLL_INCLUDED

struct pollfd {
	int fd;
	short events;
	short revents;
};

enum {
    POLLIN  = 1<<0,
    POLLOUT = 1<<1,
};

#endif // POLL_INCLUDED