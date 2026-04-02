---
name: quakey
description: Use when writing, adapting, or debugging code that uses the Quakey deterministic simulation testing framework. Covers simulation harness setup, adapting application code to run inside Quakey, fault injection, invariant checking, and build configuration.
---

## Overview

Quakey is a C framework for testing distributed systems by running multiple simulated nodes in a single process with fully controlled, deterministic I/O. Given the same seed, every simulation run produces identical results, making rare bugs reproducible.

- Multiple virtual nodes ("hosts") run cooperatively inside one OS process — no threads.
- All I/O (sockets, files, clocks, memory) is replaced with in-process mocks via preprocessor macros.
- Time is discrete and event-driven: it only advances when all hosts are blocked.
- A seeded PRNG controls all randomness (network delays, fault injection decisions).
- Faults (node crashes, network partitions) are injected deterministically.

## Files

```
quakey/
  include/quakey.h   — public API and mock macro definitions
  src/quakey.c       — scheduler, event loop, mock network/time
  src/mockfs.h       — mock filesystem header
  src/mockfs.c       — in-memory filesystem implementation
```

## Core API

```c
// Simulation lifecycle
int          quakey_init(Quakey **quakey, QuakeyUInt64 seed);
void         quakey_free(Quakey *quakey);

// Spawn a virtual node
QuakeyNode   quakey_spawn(Quakey *quakey, QuakeySpawn config, char *arg);

// Run one scheduling step (returns 0 when simulation should stop)
int          quakey_schedule_one(Quakey *quakey);

// Simulated time in nanoseconds
QuakeyUInt64 quakey_current_time(Quakey *quakey);

// Inspect hosts from test harness
int          quakey_num_hosts(Quakey *quakey);
void        *quakey_host_state(Quakey *quakey, int idx);  // NULL if dead
int          quakey_host_is_dead(Quakey *quakey, int idx);
const char  *quakey_host_name(Quakey *quakey, int idx);

// Access node state from a QuakeyNode handle
void        *quakey_node_state(QuakeyNode node);

// Fault injection control
void         quakey_set_max_crashes(Quakey *quakey, int max_crashes);
void         quakey_network_partitioning(Quakey *quakey, bool enabled);

// Deterministic random number
QuakeyUInt64 quakey_random(void);

// Signals: nodes → test harness
void         quakey_signal(char *name);                    // call from tick_func
int          quakey_get_signal(Quakey *quakey, QuakeySignal *signal);

// Host context (required when calling mocks from outside scheduler)
void         quakey_enter_host(QuakeyNode node);
void         quakey_leave_host(void);
```

## QuakeySpawn config

```c
typedef struct {
    char           *name;        // debug label (static lifetime)
    int             state_size;  // bytes of opaque application state
    QuakeyInitFunc  init_func;   // called once on spawn (and after crash)
    QuakeyTickFunc  tick_func;   // called each scheduling step
    QuakeyFreeFunc  free_func;   // called on quakey_free()
    char          **addrs;       // network addresses ("127.0.0.1", etc.)
    int             num_addrs;
    int             disk_size;   // bytes of persistent virtual disk
} QuakeySpawn;
```

## Callback signatures

```c
// init_func: called on first spawn and after each crash/restart
int my_init(void *state, int argc, char **argv,
            void **ctxs, struct pollfd *pdata, int pcap,
            int *pnum, int *timeout);

// tick_func: called each time the host is scheduled
int my_tick(void *state, void **ctxs,
            struct pollfd *pdata, int pcap, int *pnum, int *timeout);

// free_func: called on quakey_free()
int my_free(void *state);
```

- `pdata`/`pcap`/`pnum` — poll array. The host fills it with fds and events to wait on.
- `timeout` — milliseconds until next tick; -1 = wait forever, 0 = immediate.
- `ctxs` — per-fd context pointers (parallel array to pdata, managed by application).

## Enabling mocks

Define `QUAKEY_ENABLE_MOCKS` before including the header in any translation unit that should use mocked system calls:

```c
#define QUAKEY_ENABLE_MOCKS
#include <quakey.h>
```

This replaces `socket`, `open`, `read`, `write`, `malloc`, `clock_gettime`, etc. with mock implementations via `#define`. Application code calls the standard names; macros redirect them transparently.

Do **not** define `QUAKEY_ENABLE_MOCKS` in the test harness file — only in the application source files under test.

Use `QUAKEY_SIGNAL(name)` (not `quakey_signal()` directly) inside application code so it compiles cleanly in both simulation and production builds.

## Persistent vs volatile state

- **Disk** (`disk_size` bytes): survives node crashes. Backed by MockFS.
- **Memory** (`state_size` bytes + anything malloc'd): wiped on crash.
- **Sockets/connections**: closed and cleaned up on crash.

After a crash, `init_func` is called again with the same args. Applications can read disk to reconstruct in-memory state, exercising the recovery path.

## Fault injection

| Fault | Behaviour |
|-------|-----------|
| Node crash | All sockets closed, in-memory state wiped, disk preserved. Node restarts after 1–10 s simulated delay. |
| Network partition | Pairs of hosts that cannot communicate. Partitions drift gradually (one link added/removed every 100–500 ms). |
| Network delay | All connect/send operations delayed 0–100 ms. |

Enable probabilistic fault injection at compile time with `-DFAULT_INJECTION`.

## Build

Compile application files with `-DQUAKEY_ENABLE_MOCKS`, link against `quakey/src/quakey.c` and `quakey/src/mockfs.c`:

```makefile
my_server.o: my_server.c
	$(CC) -Iquakey/include -DQUAKEY_ENABLE_MOCKS -c -o $@ $<

test_main.o: test_main.c
	$(CC) -Iquakey/include -c -o $@ $<

test: test_main.o my_server.o quakey/src/quakey.c quakey/src/mockfs.c
	$(CC) -o $@ $^
```

---

## Workflow: adapting application code to run in Quakey

1. **Guard mock includes** — wrap the Quakey include so production builds are unaffected:
   ```c
   #ifdef SIMULATION
   #define QUAKEY_ENABLE_MOCKS
   #endif
   #include <quakey.h>
   ```

2. **Replace blocking I/O with poll-based I/O** — Quakey schedules one tick at a time; any blocking call (blocking `read`, `sleep`, etc.) will stall the entire simulation. All waiting must go through the poll array.

3. **Implement the three callbacks**:
   - `init_func` — open sockets/files, populate the initial poll array, set timeout.
   - `tick_func` — handle ready events, update the poll array, return.
   - `free_func` — release resources (called on `quakey_free`, not on crash).

4. **Use `QUAKEY_SIGNAL`** instead of `quakey_signal` directly so code compiles in both simulation and production modes.

5. **Parse node identity from `arg`** — `quakey_spawn` passes a single string; use it to convey addresses, peer lists, node IDs, or any other per-node config.

## Workflow: writing a simulation test harness

1. Include `<quakey.h>` without `QUAKEY_ENABLE_MOCKS` in the harness file.
2. Call `quakey_init` with a seed. Accept the seed as a CLI argument so any failing run can be reproduced exactly.
3. Spawn all nodes before starting the loop. Spawn order affects scheduling order.
4. Run the loop:
   ```c
   while (quakey_current_time(q) < time_limit_ns) {
       quakey_schedule_one(q);
       check_invariants(q);
       drain_signals(q);
   }
   ```
5. Check invariants **outside** `quakey_schedule_one` — reading another host's state from inside a `tick_func` is unsafe.
6. Use `quakey_host_state(q, idx)` returning `NULL` as the signal that a node is currently dead/restarting; skip it in invariant checks.

## Workflow: invariant checking

- Maintain a **shadow log** in the harness: as entries become committed on any node, append them to the shadow. Verify that later commits from other nodes agree with the shadow prefix.
- Separate **per-node safety** checks (local consistency) from **cross-node agreement** checks (distributed correctness).
- Use `quakey_enter_host` / `quakey_leave_host` if invariant checking needs to call mock filesystem functions to inspect a node's disk state.

## Workflow: debugging a failing simulation

1. Note the seed printed at startup (or passed via CLI).
2. Re-run with the same seed — the failure will reproduce identically.
3. Add `QUAKEY_SIGNAL("checkpoint")` calls in the application at key points to narrow down where things go wrong.
4. Reduce the time limit to stop the simulation closer to the failure.
5. Add assertions directly in `tick_func` for local invariants that should never be violated.
6. Compile without `FAULT_INJECTION` to rule out crash/partition interaction.

## Common mistakes

- **Calling `quakey_random()` from harness context between spawns**: safe. Calling it from multiple hosts in non-deterministic order: breaks reproducibility. Keep random calls inside `tick_func` or harness, not in both.
- **Forgetting `quakey_enter_host`**: mock calls from harness context without entering a host will crash.
- **Blocking in `tick_func`**: any real `sleep`, blocking `recv`, or blocking `read` stalls the whole simulation.
- **Sharing pointers between hosts**: each host has its own address space conceptually; in practice they share the process heap, but writing to another host's state from `tick_func` is a data race against the scheduler.
- **Using real `time()` or `rand()`**: bypasses determinism. Use `quakey_current_time` and `quakey_random` instead.
