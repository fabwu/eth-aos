/**
 * \file
 * \brief Management and spawning of processes.
 */

#ifndef _INIT_PROCESS_H_
#define _INIT_PROCESS_H_

#include <string.h>
#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_protocol.h>
#include <aos/core_state.h>
#include <spawn/spawn.h>
#include <spawn/argv.h>
#include <machine/atomic.h>
#include <grading.h>

#include "spawn.h"

#define INIT_PROCESS_PIN_TO_CORE 0

struct process_node {
    domainid_t pid;
    coreid_t core_id;
    char name[DISP_NAME_LEN];
    struct process_node *next;
};

struct process_state {
    struct slab_allocator slabs;
    struct process_node *head;  ///< Linked list of process nodes.
    size_t node_count; ///< Amount of nodes present in linked list.
};

/**
 * \brief Initialise process management.
 */
void process_init(void);

void process_handle_lmp_request(uintptr_t message_type, struct lmp_recv_msg *msg,
                           struct lmp_chan *lmp_chan);

void process_handle_ump_request(uintptr_t message_type, uint8_t *buf);

/**
 * \brief Can be called by init on bsp core to spawn a process
 */
errval_t process_spawn_init(char *name);

/**
 * \brief Spawns process.
 */
errval_t process_spawn_rpc(struct aos_chan *chan, coreid_t core_id);

/**
 * \brief Get LMP channel for the given pid.
 */
errval_t process_get_lmp_chan(domainid_t pid, struct lmp_chan *chan);

/**
 * \brief Add process to running processes.
 * This function is already called from process_spawn_rpc.
 */
errval_t process_add(domainid_t pid, coreid_t core_id, char *name);

/**
 * \brief Remove process from running processes.
 */
errval_t process_exit(domainid_t pid);

/**
 * \brief Send pids of all running processes to the given channel.
 */
errval_t process_get_all_pids_rpc(struct aos_chan *chan);

/**
 * \brief Return name of the running process with given pid.
 */
errval_t process_get_name_rpc(struct aos_chan *chan, domainid_t pid);

#endif
