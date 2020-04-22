/**
 * \file
 * \brief Management and spawning of processes.
 */

#ifndef _INIT_PROCESS_H_
#define _INIT_PROCESS_H_

#include <string.h>
#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <spawn/argv.h>
#include <machine/atomic.h>
#include <grading.h>

// TODO: Could be improved by using an AVL tree or similar instead of a linked list
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

/**
 * \brief Spawns process.
 */
errval_t process_spawn_rpc(struct lmp_chan *chan, coreid_t core_id);

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
errval_t process_get_all_pids_rpc(struct lmp_chan *chan);

/**
 * \brief Return name of the running process with given pid.
 */
errval_t process_get_name_rpc(struct lmp_chan *chan, domainid_t pid);

#endif
