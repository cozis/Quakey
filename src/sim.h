#ifndef SIM_INCLUDED
#define SIM_INCLUDED

#include <stdint.h>
#include <limits.h>
#include <quakey.h>

#include "proc.h"

#define PID_MIN 300
#define PID_MAX 10000
#define START_TIME 1

_Static_assert(PID_MIN >= 0);
_Static_assert(PID_MAX <= INT_MAX);

struct QuakeySim {

    // The next candidate program ID
    //
    // Program ID are allocated from PID_MIN to
    // PID_MAX (inclusive) with wrap-around.
    int next_pid;

    // Current simulation time in nanoseconds
    uint64_t current_time_ns;

    // Next process to be scheduled
    int next_proc;

    // List of process states. The "procs" array is
    // dynamically allocated. The "max_procs"
    // variable is its capacity while "num_procs"
    // is the number of its used slots.
    //
    // It's important to use an array of pointers
    // so that process tables don't move in memory.
    // This allows descriptors from different processes
    // to point to each others safely.
    int num_procs;
    int max_procs;
    Proc **procs;
};

// Returns the index of the host associated to the
// given address. If no host is found, -1 is returned
int sim_find_host(QuakeySim *sim, Addr addr);

#endif // SIM_INCLUDED