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

/* LED */
#define GPIO3_BASE          0x5D0B0000
#define GPIO3_SIZE          0x10000
#define GPIO3_DR_OFFSET     0x0
#define GPIO3_GDIR_OFFSET   0x4
#define PIN_LED4            (1 << 23)
static void *led_base;

static void led(bool on)
{
    volatile uint32_t *va_gdir, *va_dr;

    va_dr = led_base + GPIO3_DR_OFFSET;
    va_gdir = led_base + GPIO3_GDIR_OFFSET;

    *va_gdir |= PIN_LED4;

    if (on) {
        *va_dr |= PIN_LED4;
    } else {
        *va_dr &= ~PIN_LED4;
    }
}

static errval_t map_led_mem(void)
{
    struct aos_rpc *init_rpc = aos_rpc_get_init_channel();
    struct paging_state *st = get_current_paging_state();
    errval_t err;

    struct capref led_capref;
    err = aos_rpc_get_device_cap(init_rpc, GPIO3_BASE, GPIO3_SIZE, &led_capref);
    assert(err_is_ok(err));

    err = paging_map_frame_attr(st, &led_base, 8, led_capref,
                                VREGION_FLAGS_READ_WRITE_NOCACHE, NULL, NULL);
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}

static void run_command(void)
{
    char **argv;
    char *argv_buf;
    int argc;

    argv = make_argv(cmdline, &argc, &argv_buf);
    if (argv == NULL || argc == 0) {
        return;
    }

    if (!strcmp(argv[0], "help")) {
        printf("Usage:\n");
        printf("echo            - display a line of text\n");
        printf("led [on|off]    - turn the LED on/off\n");
    } else if (!strcmp(argv[0], "echo")) {
        for (int i = 1; i < argc; i++) {
            printf("%s ", argv[i]);
        }
        printf("\n");
    } else if (!strcmp(argv[0], "led")) {
        if (argc >= 2) {
            if (!strcmp(argv[1], "on"))
                led(1);
            else if (!strcmp(argv[1], "off"))
                led(0);
        }
    } else {
        printf("Unrecognized command (try 'help')\n");
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
        printf("init RPC channel NULL?\n");
        return EXIT_FAILURE;
    }

#if 0
    memcpy(cmdline_fixed, "hello", strlen("hello") + 1);
    printf("calling aos_rpc_process_spawn(cmd = '%s', core = %i)\n", cmdline_fixed, coreid);
    err = aos_rpc_process_spawn(process_rpc, cmdline_fixed, coreid, &pid);
    if (err_is_fail(err)) {
        printf("starting '%s' failed.\n", cmdline_fixed);
        return EXIT_FAILURE;
    }
    printf("'%s' started successfully\n", cmdline_fixed);
#endif

    memcpy(cmdline_fixed, "memeater", strlen("memeater") + 1);
    printf("calling aos_rpc_process_spawn(cmd = '%s', core = %i)\n", cmdline_fixed, coreid);
    err = aos_rpc_process_spawn(process_rpc, cmdline_fixed, coreid, &pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "starting '%s' failed.\n", cmdline_fixed);
        return -EXIT_FAILURE;
    }
    printf("'%s' started successfully\n", cmdline_fixed);

    // I get a null pointer with this code (works on nameservicetest...)
/*    domainid_t *pids;
    size_t pid_count;
    printf("calling aos_rpc_process_get_all_pids()\n");
    err = aos_rpc_process_get_all_pids(process_rpc, &pids, &pid_count);
    if (err_is_fail(err)) {
        printf("receiving PIDs failed\n");
        return EXIT_FAILURE;
    }
    printf("List of processes:\n");
    for (int i = 0; i < pid_count; i++) {
        char *name;
        err = aos_rpc_process_get_name(process_rpc, pids[i], &name);
        if (err_is_fail(err)) {
            printf("failed to get name of process 0x%lx\n", pids[i]);
            return EXIT_FAILURE;
        }
        printf("  %s (PID = %llx, core = %u)\n", name, pids[i], (pids[i] >> 24) & 0xff);
    }*/

    err = map_led_mem();
    if (err_is_fail(err)) {
        printf("failed to memory map LED\n");
        return EXIT_FAILURE;
    }

    while (1) {
        char *ret_str;
        ret_str = fgets(cmdline, sizeof(cmdline), stdin);
        if (ret_str == NULL) {
            printf("Warning: Failed to get command line\n");
            continue;
        }

        printf("\n");

        run_command();
    }

    return EXIT_SUCCESS;
}
