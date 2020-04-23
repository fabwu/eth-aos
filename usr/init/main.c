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

static errval_t init_spawn(char *name, domainid_t *pid)
{
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

    // FIXME BEGIN Just print the value for now...
    // we have to pass core1_base and core1_size to the other core somehow
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
    genpaddr_t bsp_ram_base = ram_base;
    size_t bsp_ram_size = cut - 1;

    genpaddr_t app_ram_base = bsp_ram_base + cut;
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
    // FIXME END

    struct capref mem_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };

    err = initialize_ram_alloc(mem_cap, bsp_ram_base, bsp_ram_size);
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
    struct urpc_data *urpc;
    err = paging_map_frame(get_current_paging_state(), (void **)&urpc, urpc_frame_size,
                           urpc_frame, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't map URPC frame\n");
        return EXIT_FAILURE;
    }
    memset(urpc, 0, urpc_frame_size);

    // FIXME: Use constatns instead of magic numbers
    assert(64 * 64 * 2 == MON_URPC_SIZE);
    aos_ump_init(&ump, (void *)urpc, ((void *)urpc) + (MON_URPC_SIZE >> 1), 64, 64);

    // TODO: Move to separate urpc file
    uint64_t ump_size = aos_ump_get_capacity(&ump);
    // FIXME: Improve (use smaller buffer)
    uint8_t ump_buf[ump_size];
    size_t offset = 0;
    *(genpaddr_t *)ump_buf = app_ram_base;
    offset += sizeof(genpaddr_t);
    *(size_t *)(ump_buf + offset) = app_ram_size;
    offset += sizeof(size_t);
    *(genpaddr_t *)(ump_buf + offset) = bootinfo_id.base;
    offset += sizeof(genpaddr_t);
    *(gensize_t *)(ump_buf + offset) = bootinfo_id.bytes;
    offset += sizeof(gensize_t);
    *(genpaddr_t *)(ump_buf + offset) = mmstrings_id.base;
    offset += sizeof(genpaddr_t);
    *(gensize_t *)(ump_buf + offset) = mmstrings_id.bytes;
    offset += sizeof(gensize_t);

    aos_ump_enqueue(&ump, ump_buf, offset);

    // boot second core
    err = coreboot(1, "boot_armv8_generic", "cpu_imx8x", "init", urpc_frame_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't boot second core");
        return -1;
    }

    if (INIT_EXECUTE_MEMORYTEST) {
        err = init_spawn("memeater", NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't spawn memeater");
        }
    }

    if (INIT_EXECUTE_SPAWNTEST) {
        init_spawn("spawnTester", NULL);
    }

    if (INIT_EXECUTE_SHELL) {
        err = init_spawn("shell", NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't spawn shell");
        }
    }

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
    errval_t err;
    coreid_t coreid = disp_get_current_core_id();

    // init memory manager
    // (we have to do this before creating bootinfo because we need slot allocator)
    struct capref mem_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };

    struct urpc_data *urpc = (struct urpc_data *)MON_URPC_VBASE;
    aos_ump_init(&ump, ((void *)urpc) + (MON_URPC_SIZE >> 1), (void *)urpc, 64, 64);

    // TODO: Move to separate urpc file
    uint64_t ump_size = aos_ump_get_capacity(&ump);
    // FIXME: Improve (use smaller buffer)
    uint8_t ump_buf[ump_size];
    aos_ump_dequeue(&ump, ump_buf, ump_size);

    size_t offset = 0;
    genpaddr_t app_ram_base = *(genpaddr_t *)ump_buf;
    offset += sizeof(genpaddr_t);
    size_t app_ram_size = *(size_t *)(ump_buf + offset);
    offset += sizeof(size_t);
    genpaddr_t bi_addr = *(genpaddr_t *)(ump_buf + offset);
    offset += sizeof(genpaddr_t);
    size_t bi_size = *(gensize_t *)(ump_buf + offset);
    offset += sizeof(gensize_t);
    genpaddr_t mmstrings_addr = *(genpaddr_t *)(ump_buf + offset);
    offset += sizeof(genpaddr_t);
    size_t mmstrings_size = *(gensize_t *)(ump_buf + offset);
    offset += sizeof(gensize_t);

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

    err = rpc_initialize_lmp(&lmp_state);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_lmp failed");
        return -EXIT_FAILURE;
    }

    process_init();

    grading_test_early();

    // Spawn memeater
    char *module_name = "memeater";
    domainid_t mem_pid;
    err = init_spawn(module_name, &mem_pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't spawn %s\n", module_name);
        // FIXME Error handling for urpc
        return -EXIT_FAILURE;
    }
    DEBUG_PRINTF("Spawend %s with pid %d\n", module_name, mem_pid);

    grading_test_late();

    DEBUG_PRINTF("Message handler loop\n");
    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        if (aos_ump_can_dequeue(&ump)) {
            DEBUG_PRINTF("received ump command\n");

            size_t cmd_len;
            aos_ump_dequeue(&ump, &cmd_len, sizeof(size_t));
            char *cmdline = (char *)malloc(cmd_len);

            for (size_t i = 0; i < cmd_len; i += ump_size) {
                aos_ump_dequeue(&ump, cmdline + i, MIN(cmd_len - i, ump_size));
            }

            // FIXME: Hotfix name extraction
            for (size_t i = 1; i < cmd_len; ++i) {
                if (cmdline[i] == ' ') {
                    cmdline[i] = '\0';
                }
            }

            domainid_t pid = 0;
            err = init_spawn(cmdline, &pid);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Couldn't spawn %s\n", cmdline);
                return -EXIT_FAILURE;
            } else {
                DEBUG_PRINTF("Spawned %s with pid %d\n", cmdline, pid);
            }

            // FIXME: Improve (use only 16 bytes instead of ump_size)
            uint8_t ump_buf2[ump_size];
            *((errval_t *)ump_buf2) = err;
            *((domainid_t *)(ump_buf2 + sizeof(errval_t))) = pid;
            aos_ump_enqueue(&ump, ump_buf2, ump_size);
        } else {
            err = event_dispatch_non_block(default_ws);
            if (err_is_fail(err) && err != LIB_ERR_NO_EVENT) {
                DEBUG_ERR(err, "in event_dispatch");
                abort();
            }
            thread_yield();
        }
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
