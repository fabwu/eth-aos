/**
 * \file
 * \brief Barrelfish library initialization.
 */

/*
 * Copyright (c) 2007-2019, ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>

#include <aos/aos.h>
#include <aos/dispatch.h>
#include <aos/curdispatcher_arch.h>
#include <aos/dispatcher_arch.h>
#include <barrelfish_kpi/dispatcher_shared.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/systime.h>
#include <barrelfish_kpi/domain_params.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <aos/lmp_protocol.h>

#include "threads_priv.h"
#include "init.h"

#if 0
#    define DEBUG_INIT_SETUP_RPC(fmt...) debug_printf(fmt);
#else
#    define DEBUG_INIT_SETUP_RPC(fmt...) ((void)0)
#endif

/// Are we the init domain (and thus need to take some special paths)?
static bool init_domain;

extern size_t (*_libc_terminal_read_func)(char *, size_t);
extern size_t (*_libc_terminal_write_func)(const char *, size_t);
extern void (*_libc_exit_func)(int);
extern void (*_libc_assert_func)(const char *, const char *, const char *, int);

void libc_exit(int);

__weak_reference(libc_exit, _exit);
void libc_exit(int status)
{
    debug_printf("libc exit NYI!\n");
    thread_exit(status);
    // If we're not dead by now, we wait
    while (1) {
    }
}

static void libc_assert(const char *expression, const char *file, const char *function,
                        int line)
{
    char buf[512];
    size_t len;

    /* Formatting as per suggestion in C99 spec 7.2.1.1 */
    len = snprintf(buf, sizeof(buf),
                   "Assertion failed on core %d in %.*s: %s,"
                   " function %s, file %s, line %d.\n",
                   disp_get_core_id(), DISP_NAME_LEN, disp_name(), expression, function,
                   file, line);
    sys_print(buf, len < sizeof(buf) ? len : sizeof(buf));
}

__attribute__((__used__)) static size_t syscall_terminal_write(const char *buf, size_t len)
{
    if (len) {
        return sys_print(buf, len);
    }
    return 0;
}

__attribute__((__used__)) static size_t dummy_terminal_read(char *buf, size_t len)
{
    debug_printf("Terminal read NYI!\n");
    return len;
}

static size_t aos_terminal_write(const char *buf, size_t len)
{
    if (len) {
        errval_t err;
        struct aos_rpc *chan = aos_rpc_get_serial_channel();

        assert(chan);

        while (--len) {
            err = aos_rpc_serial_putchar(chan, *buf++);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Couldn't send chararcter");
                return err;
            }
        }
    }
    return 0;
}

/* Set libc function pointers */
void barrelfish_libc_glue_init(void)
{
    // XXX: FIXME: Check whether we can use the proper kernel serial, and
    // what we need for that
    // TODO: change these to use the user-space serial driver if possible
    // TODO: set these functions
    _libc_terminal_read_func = dummy_terminal_read;
    if (init_domain) {
        _libc_terminal_write_func = syscall_terminal_write;
    } else {
        _libc_terminal_write_func = aos_terminal_write;
    }
    _libc_exit_func = libc_exit;
    _libc_assert_func = libc_assert;
    /* morecore func is setup by morecore_init() */

    // XXX: set a static buffer for stdout
    // this avoids an implicit call to malloc() on the first printf
    static char buf[BUFSIZ];
    setvbuf(stdout, buf, _IOLBF, sizeof(buf));
}

/** \brief Initialise libbarrelfish.
 *
 * This runs on a thread in every domain, after the dispatcher is setup but
 * before main() runs.
 */
errval_t barrelfish_init_onthread(struct spawn_domain_params *params)
{
    errval_t err;

    // do we have an environment?
    if (params != NULL && params->envp[0] != NULL) {
        extern char **environ;
        environ = params->envp;
    }

    // Init default waitset for this dispatcher
    struct waitset *default_ws = get_default_waitset();
    waitset_init(default_ws);

    // Initialize ram_alloc state
    ram_alloc_init();
    /* All domains use smallcn to initialize */
    err = ram_alloc_set(ram_alloc_fixed);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
    }

    err = paging_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VSPACE_INIT);
    }

    err = slot_alloc_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC_INIT);
    }

    err = morecore_init(BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_MORECORE_INIT);
    }

    lmp_endpoint_init();

    if (!init_domain) {
        struct lmp_chan chan_to_init;
        lmp_chan_init(&chan_to_init);

        /* create local endpoint */
        err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &chan_to_init.local_cap,
                              &chan_to_init.endpoint);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_ENDPOINT_CREATE);
        }

        /* set remote endpoint to init's endpoint */
        chan_to_init.remote_cap = cap_initep;

        // Registers initial slot (in aos_rpc another slot is reserved as soon as this
        // slot is used up)
        err = lmp_chan_alloc_recv_slot(&chan_to_init);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_LMP_CHAN_ALLOC_RECV_SLOT);
        }

        /* send local ep to init */
        err = lmp_protocol_send_cap(&chan_to_init, AOS_RPC_SETUP, chan_to_init.local_cap);
        if (err_is_fail(err)) {
            return err_push(err, AOS_ERR_INIT_SETUP_INITEP);
        }

        /* Wait for init to acknowledge receiving the endpoint */
        err = lmp_protocol_recv0(&chan_to_init, AOS_RPC_SETUP);
        if (err_is_fail(err)) {
            return err_push(err, AOS_ERR_INIT_SETUP_INITEP);
        }

        /* initialize init RPC client with lmp channel */
        /* set init RPC client in our program state */
        aos_rpc_set_init_channel(chan_to_init);

        // Get ram_alloc to use remote allocator
        ram_alloc_set(NULL);
        ram_free_set(NULL);

        // right now we don't have the nameservice & don't need the terminal
        // and domain spanning, so we return here
    }

    return SYS_ERR_OK;
}


/**
 *  \brief Initialise libbarrelfish, while disabled.
 *
 * This runs on the dispatcher's stack, while disabled, before the dispatcher is
 * setup. We can't call anything that needs to be enabled (ie. cap invocations)
 * or uses threads. This is called from crt0.
 */
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg);
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg)
{
    init_domain = init_dom_arg;
    disp_init_disabled(handle);
    thread_init_disabled(handle, init_dom_arg);
}
