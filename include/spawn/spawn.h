/**
 * \file
 * \brief create child process library
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_SPAWN_H_
#define _INIT_SPAWN_H_

#include "aos/slot_alloc.h"
#include "aos/paging.h"


struct spawninfo {
    // Information about the binary
    char *binary_name;  // Name of the binary

    void *module_base;
    size_t module_size;

    struct cnoderef page_cnode_ref;
    struct cnoderef task_cnode_ref;
    struct capref cspace;
    struct paging_state paging;
    genvaddr_t entrypoint;

    struct capref dispatcher;
    struct capref dispframe;
    void *dispbase;

    struct capref child_dispatcher;
    struct capref child_dispframe;
    struct capref selfep;
    struct capref init_client_ep;
    struct capref init_server_ep;
    lvaddr_t child_dispframe_map;
    lvaddr_t child_args_addr;
};

// Start a child process using the multiboot command line. Fills in si.
errval_t spawn_load_by_name(char *binary_name, struct spawninfo *si, uint32_t *pid);

// Start a child process using the multiboot information, but custom arguments.
errval_t spawn_load_by_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid);

#endif /* _INIT_SPAWN_H_ */
