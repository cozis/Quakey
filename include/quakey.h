#ifndef QUAKEY_INCLUDED
#define QUAKEY_INCLUDED

#include <stdbool.h>
#include <stdint.h>

// Opaque simulation type
typedef struct Quakey Quakey;

// Number of nanoseconds (simulation time)
typedef uint64_t QuakeyNanos;

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

////////////////////////////////////////////////////////
// EVENT BUS API
//
// The event bus allows processes to communicate via time-tagged
// events. Events can only be consumed by a process when its
// current simulation time exceeds the event's time tag. This
// ensures causal ordering in the simulation.

// Maximum size of event data payload
#define QUAKEY_EVENT_DATA_MAX 256

// Event structure for inter-process communication
typedef struct {
    // Time tag of the event. A process can only consume this
    // event when its current_time > time_tag.
    QuakeyNanos time_tag;

    // Index of the source process (-1 for external events)
    int src_proc_idx;

    // Index of the destination process (-1 for broadcast)
    int dst_proc_idx;

    // Event type identifier (application-defined)
    int type;

    // Event data payload
    int  data_size;
    char data[QUAKEY_EVENT_DATA_MAX];
} QuakeyEvent;

// Publish an event from the currently executing process.
// The event's time_tag is set to the current process's time.
// Use dst_proc_idx = -1 for broadcast events.
// Returns 0 on success, -1 on failure.
int quakey_publish_event(int dst_proc_idx, int type,
    void *data, int data_size);

// Publish an event with a specific time tag from the currently
// executing process. This allows scheduling events in the future.
// Use dst_proc_idx = -1 for broadcast events.
// Returns 0 on success, -1 on failure.
int quakey_publish_event_at(int dst_proc_idx, int type,
    void *data, int data_size, QuakeyNanos time_tag);

// Consume the next available event for the currently executing process.
// Only events with time_tag < current_time are available.
// Returns 0 on success (event copied to *event), -1 if no event available.
int quakey_consume_event(QuakeyEvent *event);

// Check if there are any events available for the currently executing process.
bool quakey_has_events(void);

// Get the time of the next event for the currently executing process.
// Returns UINT64_MAX if no events are pending.
QuakeyNanos quakey_next_event_time(void);

// Get the current simulation time for the currently executing process.
QuakeyNanos quakey_current_time(void);

#endif // QUAKEY_INCLUDED
