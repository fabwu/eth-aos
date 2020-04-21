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

int main(int argc, char *argv[])
{
    struct aos_rpc *process_rpc = aos_rpc_get_process_channel();
    if (!process_rpc) {
        DEBUG_PRINTF("init RPC channel NULL?\n");
        return EXIT_FAILURE;
    }

    errval_t err;
    uint32_t new_pid;
    char *cmdline = "hello arg1";
    coreid_t coreid = 1;
    DEBUG_PRINTF("calling aos_rpc_process_spawn(cmd = '%s', core = %i)\n", cmdline, coreid);
    err = aos_rpc_process_spawn(process_rpc, cmdline, coreid, &new_pid);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("starting 'hello' failed.\n");
        return EXIT_FAILURE;
    }
    DEBUG_PRINTF("'%s' started successfully (PID = %u)\n", cmdline, new_pid);

    return EXIT_SUCCESS;
}
