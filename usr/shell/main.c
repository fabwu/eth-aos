/**
 * \file
 * \brief Shell application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */


#include <stdio.h>
#include <aos/aos.h>
#include <aos/aos_rpc.h>

#define CMDLINE_LEN 100

int main(int argc, char *argv[])
{
    errval_t err;
    char cmdline[CMDLINE_LEN];
    coreid_t coreid = 1;
    uint32_t pid;

    struct aos_rpc *process_rpc = aos_rpc_get_process_channel();
    if (!process_rpc) {
        DEBUG_PRINTF("init RPC channel NULL?\n");
        return EXIT_FAILURE;
    }

#if 0
    memcpy(cmdline, "hello", strlen("hello") + 1);
    DEBUG_PRINTF("calling aos_rpc_process_spawn(cmd = '%s', core = %i)\n", cmdline, coreid);
    err = aos_rpc_process_spawn(process_rpc, cmdline, coreid, &pid);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("starting '%s' failed.\n", cmdline);
        return EXIT_FAILURE;
    }
    DEBUG_PRINTF("'%s' started successfully\n", cmdline);
#endif

    memcpy(cmdline, "memeater", strlen("memeater") + 1);
    DEBUG_PRINTF("calling aos_rpc_process_spawn(cmd = '%s', core = %i)\n", cmdline, coreid);
    err = aos_rpc_process_spawn(process_rpc, cmdline, coreid, &pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "starting '%s' failed.\n", cmdline);
        return -EXIT_FAILURE;
    }
    DEBUG_PRINTF("'%s' started successfully\n", cmdline);

    // I get a null pointer with this code (works on nameservicetest...)
/*    domainid_t *pids;
    size_t pid_count;
    DEBUG_PRINTF("calling aos_rpc_process_get_all_pids()\n");
    err = aos_rpc_process_get_all_pids(process_rpc, &pids, &pid_count);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("receiving PIDs failed\n");
        return EXIT_FAILURE;
    }
    DEBUG_PRINTF("List of processes:\n");
    for (int i = 0; i < pid_count; i++) {
        char *name;
        err = aos_rpc_process_get_name(process_rpc, pids[i], &name);
        if (err_is_fail(err)) {
            DEBUG_PRINTF("failed to get name of process 0x%lx\n", pids[i]);
            return EXIT_FAILURE;
        }
        DEBUG_PRINTF("  %s (PID = %llx, core = %u)\n", name, pids[i], (pids[i] >> 24) & 0xff);
    }*/

    return EXIT_SUCCESS;
}
