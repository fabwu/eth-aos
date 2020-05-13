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
#include <aos/ump.h>
#include <aos/lmp_protocol.h>
#include <aos/aos_protocol.h>
#include <mm/mm.h>
#include <grading.h>
#include <aos/core_state.h>
#include <aos/coreboot.h>
#include <barrelfish_kpi/startup_arm.h>
#include <machine/atomic.h>
#include <aos/kernel_cap_invocations.h>

#include "mem_alloc.h"
#include "rpc.h"
#include "spawn.h"
#include "process.h"

#define INIT_EXECUTE_MEMORYTEST 0
#define INIT_EXECUTE_FS 0
#define INIT_EXECUTE_SPAWNTEST 0
#define INIT_EXECUTE_NAMESERVICETEST 0
#define INIT_EXECUTE_SHELL 0

#define INIT_UMP_BUF_COREBOOT_LENGTH 6

struct bootinfo *bi;

coreid_t my_core_id;

static int bsp_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo *)strtol(argv[1], NULL, 10);
    assert(bi);

    // TODO: Move the value gathering code (below) for starting core 1 into an own function
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
    cut = ROUND_DOWN(cut, BASE_PAGE_SIZE);
    genpaddr_t bsp_ram_base = ram_base;
    size_t bsp_ram_size = ram_size - cut;

    genpaddr_t app_ram_base = ROUND_UP(bsp_ram_base + cut, BASE_PAGE_SIZE);
    size_t app_ram_size = cut;

    struct frame_identity bootinfo_id;
    err = frame_identify(cap_bootinfo, &bootinfo_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't identify bootinfo frame\n");
        return -EXIT_FAILURE;
    }

    struct frame_identity mmstrings_id;
    err = frame_identify(cap_mmstrings, &mmstrings_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't identify mmstrings frame\n");
        return -EXIT_FAILURE;
    }

    DEBUG_PRINTF("PASS THESE TO CORE1 RAM %p/%lld\n", app_ram_base, app_ram_size);
    DEBUG_PRINTF("PASS THESE TO CORE1 BOOTINFO %p/%lld\n", bootinfo_id.base,
                 bootinfo_id.bytes);
    DEBUG_PRINTF("PASS THESE TO CORE1 MMSTRINGS  %p/%lld\n", mmstrings_id.base,
                 mmstrings_id.bytes);

    struct capref mem_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };

    err = initialize_ram_alloc(mem_cap, bsp_ram_base, bsp_ram_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_ram_alloc");
        return -1;
    }

    process_init();

    // Grading
    grading_test_early();

    // allocate urpc frame
    struct capref urpc_frame;
    size_t urpc_frame_size;
    err = frame_alloc(&urpc_frame, MON_URPC_SIZE, &urpc_frame_size);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }
    if (urpc_frame_size < MON_URPC_SIZE) {
        return LIB_ERR_FRAME_ALLOC;
    }

    struct frame_identity urpc_frame_id;
    err = frame_identify(urpc_frame, &urpc_frame_id);
    // initialize urpc frame
    void *urpc;
    err = paging_map_frame(get_current_paging_state(), &urpc, urpc_frame_size, urpc_frame,
                           NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't map URPC frame\n");
        return EXIT_FAILURE;
    }
    memset(urpc, 0, urpc_frame_size);

    // FIXME: Use constatns instead of magic numbers
    assert(64 * 64 * 2 == MON_URPC_SIZE);
    aos_ump_init(&ump, urpc, urpc + (MON_URPC_SIZE >> 1), 64, 64);

    uint64_t ump_buf[INIT_UMP_BUF_COREBOOT_LENGTH];
    ump_buf[0] = app_ram_base;
    ump_buf[1] = app_ram_size;
    ump_buf[2] = bootinfo_id.base;
    ump_buf[3] = bootinfo_id.bytes;
    ump_buf[4] = mmstrings_id.base;
    ump_buf[5] = mmstrings_id.bytes;

    aos_ump_enqueue(&ump, ump_buf, INIT_UMP_BUF_COREBOOT_LENGTH * sizeof(uint64_t));

    // boot second core
 //   err = coreboot(1, "boot_armv8_generic", "cpu_imx8x", "init", urpc_frame_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't boot second core\n");
        return -1;
    }

    err = init_spawn_by_name("nameserver", NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't spawn nameserver\n");
        return -EXIT_FAILURE;
    }

    if (INIT_EXECUTE_MEMORYTEST) {
        err = init_spawn_by_name("memeater", NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't spawn memeater\n");
        }
    }

    if (INIT_EXECUTE_FS) {
        err = init_spawn("filereader", NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't initialise filesystem\n");
        }
    }

    if (INIT_EXECUTE_SPAWNTEST) {
        err = init_spawn_by_name("spawnTester", NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't spawn spawntester\n");
        }
    }

    if (INIT_EXECUTE_NAMESERVICETEST) {
        err = init_spawn_by_name("nameservicetest", NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't spawn nameservicetest\n");
        }
    }

    if (INIT_EXECUTE_SHELL) {
        err = init_spawn_by_name("shell", NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't spawn shell");
        }
    }

    // Grading
    grading_test_late();

    aos_protocol_set_ump(&ump);
    rpc_ump_start_handling();
    lmp_protocol_set_ump_dispatch(true);

    // Do event_dispatch and ump dispatch forever
    aos_protocol_wait_for(NULL);

    return EXIT_SUCCESS;
}

static int app_main(int argc, char *argv[])
{
    errval_t err;
    coreid_t coreid = disp_get_current_core_id();

    // init memory manager
    // (we have to do this before creating bootinfo because we need slot allocator)
    struct capref mem_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };

    void *urpc = (void *)MON_URPC_VBASE;
    aos_ump_init(&ump, urpc + (MON_URPC_SIZE >> 1), urpc, 64, 64);

    uint64_t ump_buf[INIT_UMP_BUF_COREBOOT_LENGTH];
    aos_ump_dequeue(&ump, ump_buf, INIT_UMP_BUF_COREBOOT_LENGTH * sizeof(uint64_t));

    genpaddr_t app_ram_base = ump_buf[0];
    size_t app_ram_size = ump_buf[1];
    genpaddr_t bi_addr = ump_buf[2];
    size_t bi_size = ump_buf[3];
    genpaddr_t mmstrings_addr = ump_buf[4];
    size_t mmstrings_size = ump_buf[5];

    DEBUG_PRINTF("CORE 1 Received: RAM %p/%lld\n", app_ram_base, app_ram_size);
    DEBUG_PRINTF("CORE 1 Received: BOOTINFO %p/%lld\n", bi_addr, bi_size);
    DEBUG_PRINTF("CORE 1 Received: MMSTRINGS  %p/%lld\n", mmstrings_addr, mmstrings_size);

    err = ram_forge(mem_cap, app_ram_base, app_ram_size, coreid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't create cap for physical memory\n");
        return -EXIT_FAILURE;
    }

    err = initialize_ram_alloc(mem_cap, app_ram_base, app_ram_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_ram_alloc");
        return -EXIT_FAILURE;
    }

    // create frame to bootinfo
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

    // create an L2 cnode for modules
    struct capref cap_module_cnode = { .cnode = cnode_root, .slot = ROOTCN_SLOT_MODULECN };
    cslot_t retslots;
    err = cnode_create_raw(cap_module_cnode, &cnode_module, ObjType_L2CNode,
                           L2_CNODE_SLOTS, &retslots);
    if (err_is_fail(err) || retslots != L2_CNODE_SLOTS) {
        DEBUG_ERR(err, "Couldn't create L2 cnode for modules");
        return -EXIT_FAILURE;
    }

    // create frame for mmstrings
    cap_mmstrings.cnode = cnode_module;
    err = frame_forge(cap_mmstrings, mmstrings_addr, mmstrings_size, coreid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't create frame for mmstrings");
        return -EXIT_FAILURE;
    }

    // create dev frames for modules
    for (int i = 0; i < bi->regions_length; ++i) {
        struct mem_region mr = bi->regions[i];
        if (mr.mr_type == RegionType_Module) {
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

    grading_setup_app_init(bi);

    grading_test_early();

    grading_test_late();

    DEBUG_PRINTF("Message handler loop\n");
    aos_protocol_set_ump(&ump);
    rpc_ump_start_handling();
    lmp_protocol_set_ump_dispatch(true);

    // Do event_dispatch and ump dispatch forever
    aos_protocol_wait_for(NULL);

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

    // set init selfep
    err = cap_retype(cap_selfep, cap_dispatcher, 0, ObjType_EndPointLMP, 0, 1);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    if (my_core_id == 0)
        return bsp_main(argc, argv);
    else
        return app_main(argc, argv);
}
