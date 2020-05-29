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
#include <aos/netservice.h>
#include <aos/systime.h>
#include <fs/fs.h>
#include <fs/dirent.h>
#include <spawn/argv.h>

#define SDCARD_PRESENT 1

static struct aos_rpc *process_rpc;

#define MAX_LINE_SIZE 4096
static char cmdline[MAX_LINE_SIZE + 1];

/* LED */
#define GPIO3_BASE 0x5D0B0000
#define GPIO3_SIZE 0x10000
#define GPIO3_DR_OFFSET 0x0
#define GPIO3_GDIR_OFFSET 0x4
#define PIN_LED4 (1 << 23)
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

static void ps(void)
{
    errval_t err;

    domainid_t *pids;
    size_t pid_count;
    err = aos_rpc_process_get_all_pids(process_rpc, &pids, &pid_count);
    if (err_is_fail(err)) {
        printf("receiving PIDs failed\n");
        return;
    }

    printf("Name             PID    Core\n");
    for (int i = 0; i < pid_count; i++) {
        char *name;
        err = aos_rpc_process_get_name(process_rpc, pids[i], &name);
        if (err_is_fail(err)) {
            printf("failed to get name of process 0x%lx\n", pids[i]);
            return;
        }
        printf("%s%*llx%8u\n", name, (20 - strlen(name)), pids[i], (pids[i] >> 12) & 0xff);
    }
}

static void ls(char *dir)
{
    errval_t err;
    fs_dirhandle_t dh;

    err = opendir(dir, &dh);
    if (err_is_fail(err)) {
        printf("opendir failed\n");
        return;
    }

    do {
        char *name;
        err = readdir(dh, &name);
        if (err_no(err) == FS_ERR_INDEX_BOUNDS) {
            break;
        } else if (err_is_fail(err)) {
            printf("readdir failed\n");
            return;
        } else {
            printf("%s\n", name);
        }
    } while (err_is_ok(err));
}

static void fs_mkdir(char *dir)
{
    errval_t err;

    err = mkdir(dir);
    if (err) {
        printf("mkdir failed\n");
        return;
    }
}

static void fs_rmdir(char *dir)
{
    errval_t err;

    err = rmdir(dir);
    if (err) {
        printf("rmdir failed\n");
        return;
    }
}

static void fs_rm(char *dir)
{
    errval_t err;

    err = rm(dir);
    if (err) {
        printf("rm failed\n");
        return;
    }
}

static void touch(char *path)
{
    errval_t err;

    FILE *f = fopen(path, "a");
    if (f == NULL) {
        printf("fopen failed\n");
        return;
    }

    err = fclose(f);
    if (err_is_fail(err)) {
        printf("fclose failed\n");
        return;
    }
}

static void cp(char *src_path, char *dst_path)
{
    errval_t err;

    void *buf = malloc(512 * sizeof(char));
    if (buf == NULL) {
        printf("malloc failed\n");
        return;
    }

    FILE *src = fopen(src_path, "r");
    if (src == NULL) {
        printf("fopen failed\n");
        return;
    }

    FILE *dst = fopen(dst_path, "w");
    if (dst == NULL) {
        printf("fopen failed\n");
        return;
    }

    while (true) {
        size_t read = fread(buf, 1, 512, src);
        err = ferror(src);
        if (err_is_fail(err)) {
            printf("fread failed\n");
            return;
        }

        if (read > 0) {
            size_t written = fwrite(buf, 1, read, dst);
            err = ferror(dst);
            if (err_is_fail(err) || written != read) {
                printf("fwrite failed\n");
                return;
            }
        } else {
            break;
        }
    }

    err = fclose(src);
    if (err_is_fail(err)) {
        printf("fclose failed\n");
        return;
    }

    err = fclose(dst);
    if (err_is_fail(err)) {
        printf("fclose failed\n");
        return;
    }

    free(buf);
}

static void cat(char *path)
{
    errval_t err;
    int res = 0;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        printf("fopen failed\n");
        return;
    }

    res = fseek(f, 0, SEEK_END);
    if (res) {
        printf("fseek failed\n");
        return;
    }

    size_t filesize = ftell(f);
    rewind(f);

    char *buf = calloc(filesize + 2, sizeof(char));
    if (buf == NULL) {
        printf("calloc failed\n");
        return;
    }

    size_t read = fread(buf, 1, filesize, f);

    *(buf + read) = '\0';
    debug_printf("%s\n", buf);

    free(buf);
    err = fclose(f);
    if (err_is_fail(err)) {
        printf("fclose failed\n");
        return;
    }
}

static errval_t run_process(coreid_t coreid, char **argv, char *argv_buf, int idx)
{
    errval_t err;

    // find where the command starts
    char *cmd = cmdline + (argv[idx] - argv_buf);

    domainid_t pid;
    err = aos_rpc_process_spawn(process_rpc, cmd, coreid, &pid);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

static void nslookup(char *name)
{
    errval_t err;
    printf("Looking up PID of service '%s'...\n", name);
    domainid_t did;
    err = nameservice_lookup_did(name, &did);

    if (err_is_fail(err)) {
        printf("\033[1;31mError\033[0m Couldn't find entry for service %s\n", name);
        return;
    }

    printf("\033[0;32mSuccess\033[0m Service '%s' is running at PID %p\n", name, did);

    return;
}

static void run_command(void)
{
    errval_t err;
    char **argv;
    char *argv_buf;
    int argc;
    int idx = 0;
    systime_t tstart, tend;
    bool time = false;

    argv = make_argv(cmdline, &argc, &argv_buf);
    if (argv == NULL || argc == 0) {
        return;
    }

    if (!strcmp(argv[idx], "time")) {
        if (argc < 2)
            return;
        time = true;
        tstart = systime_now();
        idx++;
    }

    if (!strcmp(argv[idx], "help")) {
        printf("Usage:\n");
        printf("arp                - print arp table\n");
        printf("echo               - display a line of text\n");
        printf("led [on|off]       - turn the LED on/off\n");
        printf("ps                 - list current processes\n");
        printf("ls [path]          - list directory contents\n");
        printf("touch [path]       - create file\n");
        printf("cat [path]         - read file\n");
        printf("cp [src_path] [dst_path] - read file\n");
        printf("rm [path]          - remove file\n");
        printf("mkdir [path]       - create directory\n");
        printf("rmdir [path]       - remove directory\n");
        printf("time [cmd]         - time a command\n");
        printf("udpecho [port]     - start udp echo server\n");
        printf("oncore [#] [cmd]   - run program on given core\n");
        printf("[cmd] [args]       - run a program with given arguments\n");
        printf("exit               - exit shell\n");
    } else if (!strcmp(argv[idx], "echo")) {
        for (int i = idx + 1; i < argc; i++) {
            printf("%s ", argv[i]);
        }
        printf("\n");
    } else if (!strcmp(argv[idx], "led")) {
        if (argc >= 2) {
            if (!strcmp(argv[idx + 1], "on"))
                led(1);
            else if (!strcmp(argv[idx + 1], "off"))
                led(0);
        }
    } else if (!strcmp(argv[idx], "ps")) {
        ps();
    } else if (!strcmp(argv[idx], "arp")) {
        err = netservice_arp_print_cache();
        if (err_is_fail(err)) {
            printf("Failed to print arp table\n");
        }
    } else if (!strcmp(argv[idx], "nslookup") && argc == 2) {
        nslookup(argv[idx + 1]);
    } else if (!strcmp(argv[idx], "ls") && argc == 2) {
        ls(argv[idx + 1]);
    } else if (!strcmp(argv[idx], "touch") && argc == 2) {
        touch(argv[idx + 1]);
    } else if (!strcmp(argv[idx], "cat") && argc == 2) {
        cat(argv[idx + 1]);
    } else if (!strcmp(argv[idx], "cp") && argc == 3) {
        cp(argv[idx + 1], argv[idx + 2]);
    } else if (!strcmp(argv[idx], "rm") && argc == 2) {
        fs_rm(argv[idx + 1]);
    } else if (!strcmp(argv[idx], "mkdir") && argc == 2) {
        fs_mkdir(argv[idx + 1]);
    } else if (!strcmp(argv[idx], "rmdir") && argc == 2) {
        fs_rmdir(argv[idx + 1]);
    } else if (!strcmp(argv[idx], "oncore") && argc >= 3) {
        unsigned coreid = argv[idx + 1][0] - 48;
        printf("coreid = %i\n", coreid);
        if (coreid > 1)
            goto out;
        run_process(coreid, argv, argv_buf, idx + 2);
    } else if (!strcmp(argv[idx], "exit")) {
        err = filesystem_unmount();
        if (err_is_fail(err)) {
            printf("Failed to unmount filesystem\n");
        }
        exit(0);
    } else {
        err = run_process(0, argv, argv_buf, idx);
        if (err_is_fail(err)) {
            printf("Unrecognized command (try 'help')\n");
            goto out;
        }
    }

    if (time) {
        tend = systime_now();
        printf("Time: %llu ms\n", systime_to_us(tend - tstart) / 1000);
    }

out:
    free_argv(argv, argv_buf);
}

int main(int argc, char *argv[])
{
    errval_t err;

    process_rpc = aos_rpc_get_process_channel();
    if (!process_rpc) {
        printf("failed to get process channel\n");
        return EXIT_FAILURE;
    }

#if SDCARD_PRESENT
    err = filesystem_init();
    if (err_is_fail(err)) {
        printf("failed to initialize filesystem\n");
        return EXIT_FAILURE;
    }
#endif

    err = map_led_mem();
    if (err_is_fail(err)) {
        printf("failed to memory map LED\n");
        return EXIT_FAILURE;
    }

    while (1) {
        printf(">\n");
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
