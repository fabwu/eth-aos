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
#include <aos/coreboot.h>
#include <barrelfish_kpi/startup_arm.h>
#include <machine/atomic.h>

#include "mem_alloc.h"
#include "rpc.h"
#include "process.h"

#define INIT_EXECUTE_MEMORYTEST 0
#define INIT_EXECUTE_SPAWNTEST 0
#define INIT_EXECUTE_SHELL 1

struct bootinfo *bi;

coreid_t my_core_id;

struct lmp_state lmp_state;

static errval_t init_spawn(char *name, domainid_t *pid) {
    errval_t err = SYS_ERR_OK;
    struct spawninfo *si = (struct spawninfo *)malloc(sizeof(struct spawninfo));
    if (si == NULL) {
        return INIT_ERR_PREPARE_SPAWN;
    }

    dispatcher_node_ref node_ref;
    err = rpc_create_child_channel_to_init(&si->initep, &node_ref);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_PREPARE_SPAWN);
        goto out;
    }

    domainid_t domain_id;
    err = spawn_load_by_name(name, si, &domain_id);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_SPAWN);
        goto out;
    }

    if (pid != NULL) {
        *pid = domain_id;
    }

    rpc_dispatcher_node_set_pid(node_ref, domain_id);

    err = process_add(domain_id, my_core_id, name);
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

    process_init();

    // Grading
    grading_test_early();

    // allocate urpc frame
    struct capref urpc_frame;
    size_t urpc_frame_size;
    err = frame_alloc(&urpc_frame, BASE_PAGE_SIZE, &urpc_frame_size);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }
    struct frame_identity urpc_frame_id;
    err = frame_identify(urpc_frame, &urpc_frame_id);
    // initialize urpc frame
    struct urpc_data *urpc;
    err = paging_map_frame(get_current_paging_state(), (void **)&urpc,
                           urpc_frame_size, urpc_frame, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't map URPC frame\n");
        return EXIT_FAILURE;
    }
    memset(urpc, 0, urpc_frame_size);
    urpc_frame_core1 = urpc;

    // boot second core
    err = coreboot(1, "boot_armv8_generic", "cpu_imx8x", "init", urpc_frame_id);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't boot second core");
        return -1;
    }

    if (INIT_EXECUTE_MEMORYTEST) {
        err = init_spawn("memeater", NULL);
        if(err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't spawn memeater");
        }
    }

    if (INIT_EXECUTE_SPAWNTEST) {
        init_spawn("spawnTester", NULL);
    }

    if (INIT_EXECUTE_SHELL) {
        err = init_spawn("shell", NULL);
        if(err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't spawn shell");
        }
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

    struct urpc_data *urpc = (struct urpc_data *)MON_URPC_VBASE;

    while (true) {
        // wait for message
        DEBUG_PRINTF("core %u: waiting for commands...\n", disp_get_current_core_id());
        while (urpc->flag == 0);

        // ensure flag is read before msg is read
        dmb(sy);
        DEBUG_PRINTF("received command: %s\n", urpc->msg);

        urpc->err = SYS_ERR_OK;
        // ensure ret is written before flag is written
        dmb(sy);
        urpc->flag = 0;
    }

    return EXIT_SUCCESS;
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
