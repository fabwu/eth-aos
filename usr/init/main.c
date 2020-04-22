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
#include <aos/kernel_cap_invocations.h>

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

//FIXME Pass these with boot param or URPC
#define CORE0_BASE 0x806b2000
#define CORE0_SIZE 1077252095

#define CORE1_BASE 0xc0a0b000
#define CORE1_SIZE 1077252096

static int bsp_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo *)strtol(argv[1], NULL, 10);
    assert(bi);

    // FIXME Just print the value for now...
    genpaddr_t ram_base = -1;
    size_t ram_size = 0;

    for (int i = 0; i < bi->regions_length; i++) {
        struct mem_region mr = bi->regions[i];
        if (mr.mr_type == RegionType_Empty) {
            if (ram_base != -1) {
                USER_PANIC("More than one region of RAM -> add to mm");
            }

            ram_base = mr.mr_base;
            ram_size = mr.mr_base;
        }
    }

    assert(ram_base != -1);
    assert(ram_size > 0);

    size_t cut = ram_size / 2;
    genpaddr_t core0_base = ram_base;
    size_t core0_size = cut - 1;

    genpaddr_t core1_base = core0_base + cut;
    size_t core1_size = cut;

    DEBUG_PRINTF("core0 %p/%lld\n", core0_base, core0_size);
    DEBUG_PRINTF("core1 %p/%lld\n", core1_base, core1_size);
    // FIXME END

    // TODO One could retype this cap to the correct size
    struct capref mem_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };

    err = initialize_ram_alloc(mem_cap, CORE0_BASE, CORE0_SIZE);
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
    errval_t err;
    coreid_t coreid = disp_get_current_core_id();

    // init mm
    struct capref mem_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };

    err = ram_forge(mem_cap, CORE1_BASE, CORE1_SIZE, coreid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't create cap for physical memory\n");
        return -EXIT_FAILURE;
    }

    err = initialize_ram_alloc(mem_cap, CORE1_BASE, CORE1_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_ram_alloc");
        return -EXIT_FAILURE;
    }

    // create frame to bootinfo
    // TODO get these from bsp
    genpaddr_t bi_addr = 0x80212000;
    size_t bi_size = 16384;
    err = frame_forge(cap_bootinfo, bi_addr, bi_size, coreid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't create frame for bootinfo\n");
        return -EXIT_FAILURE;
    }
    err = paging_map_frame(get_current_paging_state(), (void **)&bi, bi_size,
                           cap_bootinfo, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't map bootinfo frame\n");
        return -EXIT_FAILURE;
    }

    // create an L2 cnode for the modules
    struct capref cap_module_cnode = { .cnode = cnode_root, .slot = ROOTCN_SLOT_MODULECN };
    cslot_t retslots;
    err = cnode_create_raw(cap_module_cnode, &cnode_module, ObjType_L2CNode,
                           L2_CNODE_SLOTS, &retslots);
    if (err_is_fail(err) || retslots != L2_CNODE_SLOTS) {
        DEBUG_ERR(err, "Couldn't create L2 cnode for modules");
        return -EXIT_FAILURE;
    }

    // create frame for mmstrings
    genpaddr_t mmstrings_addr = 0x806b2000;
    size_t mmstrings_size = 4096;

    cap_mmstrings.cnode = cnode_module;
    err = frame_forge(cap_mmstrings, mmstrings_addr, mmstrings_size, coreid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ASDASDASD");
        return -EXIT_FAILURE;
    }

    // create dev frames for modules
    for (int i = 0; i < bi->regions_length; ++i) {
        struct mem_region mr = bi->regions[i];
        if (mr.mr_type == RegionType_Module) {
            DEBUG_PRINTF("base %p size %lld consumed %d modsize %lld moddata %p modslot "
                         "%d\n",
                         mr.mr_base, mr.mr_bytes, mr.mr_consumed, mr.mrmod_size,
                         mr.mrmod_data, mr.mrmod_slot);
            struct capref mod_devframe = { .cnode = cnode_module, .slot = mr.mrmod_slot };

            size_t aligned_size = ROUND_UP(mr.mrmod_size, BASE_PAGE_SIZE);
            err = devframe_forge(mod_devframe, mr.mr_base, aligned_size, coreid);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Couldn't create devframe for module at addr %p\n",
                          mr.mr_base);
                return -EXIT_FAILURE;
            }
        }
    }

    err = rpc_initialize_lmp(&lmp_state);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_lmp failed");
        return -EXIT_FAILURE;
    }

    process_init();

    struct spawninfo *si = (struct spawninfo *)malloc(sizeof(struct spawninfo));
    if (si == NULL) {
        return INIT_ERR_PREPARE_SPAWN;
    }

    err = init_spawn("memeater", NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't spawn memeater");
        return -EXIT_FAILURE;
    }

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
