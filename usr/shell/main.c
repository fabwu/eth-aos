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
#include <aos/nameservice.h>
#include <spawn/argv.h>


nameservice_chan_t terminal_chan;

#define MAX_LINE_SIZE   4096
static char cmdline[MAX_LINE_SIZE + 1];

static void run_command(void)
{
    char **argv;
    char *argv_buf;
    int argc;

    argv = make_argv(cmdline, &argc, &argv_buf);
    if (argv == NULL || argc == 0) {
        return;
    }

    if (!strcmp(argv[0], "echo")) {
        for (int i = 1; i < argc; i++) {
            debug_printf("%s ", argv[i]);
        }
        debug_printf("\n");
    } else {
        debug_printf("Unrecognized command (try 'help')\n");
    }

    free_argv(argv, argv_buf);
}

int main(int argc, char *argv[])
{
    errval_t err;
    char cmdline_fixed[100];
    coreid_t coreid = 1;
    domainid_t pid;

    struct aos_rpc *process_rpc = aos_rpc_get_process_channel();
    if (!process_rpc) {
        DEBUG_PRINTF("init RPC channel NULL?\n");
        return EXIT_FAILURE;
    }

#if 0
    memcpy(cmdline_fixed, "hello", strlen("hello") + 1);
    DEBUG_PRINTF("calling aos_rpc_process_spawn(cmd = '%s', core = %i)\n", cmdline_fixed, coreid);
    err = aos_rpc_process_spawn(process_rpc, cmdline_fixed, coreid, &pid);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("starting '%s' failed.\n", cmdline_fixed);
        return EXIT_FAILURE;
    }
    DEBUG_PRINTF("'%s' started successfully\n", cmdline_fixed);
#endif

    memcpy(cmdline_fixed, "memeater", strlen("memeater") + 1);
    DEBUG_PRINTF("calling aos_rpc_process_spawn(cmd = '%s', core = %i)\n", cmdline_fixed, coreid);
    err = aos_rpc_process_spawn(process_rpc, cmdline_fixed, coreid, &pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "starting '%s' failed.\n", cmdline_fixed);
        return -EXIT_FAILURE;
    }
    DEBUG_PRINTF("'%s' started successfully\n", cmdline_fixed);

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

    while (1) {
        char *ret_str;
        ret_str = fgets(cmdline, sizeof(cmdline), stdin);
        if (ret_str == NULL) {
            debug_printf("Warning: Failed to get command line\n");
            continue;
        }

        debug_printf("\n");

        run_command();
    }

    return EXIT_SUCCESS;
}
