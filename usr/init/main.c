/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <mm/mm.h>
#include <spawn/spawn.h>
#include <grading.h>
#include <aos/core_state.h>

#include "mem_alloc.h"
#include "rpc.h"

#define INIT_EXECUTE_MEMORYTEST 1
#define INIT_EXECUTE_SPAWNTEST 0

struct bootinfo *bi;

coreid_t my_core_id;

struct lmp_state lmp_state;

static errval_t init_spawn(char *name, domainid_t *pid) {
    errval_t err = SYS_ERR_OK;
    struct spawninfo *si = (struct spawninfo *)malloc(sizeof(struct spawninfo));
    if (si == NULL) {
        return INIT_ERR_PREPARE_SPAWN;
    }

    err = rpc_create_child_channel_to_init(&si->initep);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_PREPARE_SPAWN);
        goto out;
    }

    err = spawn_load_by_name(name, si, pid);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_SPAWN);
        goto out;
    }

out:
    free(si);
    return err;
}

static int bsp_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo *)strtol(argv[1], NULL, 10);
    assert(bi);

    err = initialize_ram_alloc();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_ram_alloc");
        return -1;
    }

    err = rpc_initialize_lmp(&lmp_state);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_lmp failed");
        return -1;
    }

    // Grading
    grading_test_early();

    if (INIT_EXECUTE_MEMORYTEST) {
        init_spawn("memeater", NULL);
    }

    if (INIT_EXECUTE_SPAWNTEST) {
        init_spawn("spawnTester", NULL);
    }

    // TODO: Spawn system processes, boot second core etc. here

    // Grading
    grading_test_late();

    debug_printf("Message handler loop\n");
    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }

    return EXIT_SUCCESS;
}

static int app_main(int argc, char *argv[])
{
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();
    return LIB_ERR_NOT_IMPLEMENTED;
}

int main(int argc, char *argv[])
{
    errval_t err;


    /* Set the core id in the disp_priv struct */
    err = invoke_kernel_get_core_id(cap_kernel, &my_core_id);
    assert(err_is_ok(err));
    disp_set_core_id(my_core_id);

    debug_printf("init: on core %" PRIuCOREID ", invoked as:", my_core_id);
    for (int i = 0; i < argc; i++) {
        printf(" %s", argv[i]);
    }
    printf("\n");
    fflush(stdout);

    if (my_core_id == 0)
        return bsp_main(argc, argv);
    else
        return app_main(argc, argv);
}
