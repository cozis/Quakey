#ifndef QUAKEY_INCLUDED
#define QUAKEY_INCLUDED

#include <stdbool.h>

// Opaque simulation type
typedef struct Quakey Quakey;

// Start a simulation
int quakey_init(Quakey **psim);

// Stop a simulation
void quakey_free(Quakey *sim);

// Forward-declared for QuakeyInitFunc and QuakeyTickFunc
struct pollfd;

// Function pointers to a simulated program's code
typedef int (*QuakeyInitFunc)(void *state, int argc, char **argv, struct pollfd *pdata, int pcap, int *pnum, int *timeout);
typedef int (*QuakeyTickFunc)(void *state, struct pollfd *pdata, int pcap, int *pnum, int *timeout);
typedef int (*QuakeyFreeFunc)(void *state);

typedef struct {

    int state_size;

    // Pointers to program code
    QuakeyInitFunc init_func;
    QuakeyTickFunc tick_func;
    QuakeyFreeFunc free_func;

    // Network addresses enabled on the process
    char **addrs;
    int num_addrs;

    // Disk size for the process
    int disk_size;

} QuakeySpawnConfig;

// Add a program to the simulation
int quakey_spawn(Quakey *sim, QuakeySpawnConfig config, char *arg);

// Schedule and executes one program, then returns
bool quakey_schedule_one(Quakey *sim);

#endif // QUAKEY_INCLUDED
