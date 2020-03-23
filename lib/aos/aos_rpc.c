/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached license file.
 * if you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. attn: systems group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/core_state.h>

static void aos_rpc_recv_regular_closure(void *arg)
{
    errval_t err;
    struct dispatcher_node *node = (struct dispatcher_node *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(&node->chan, &msg, &cap);
    debug_printf("aos_rpc_recv_regular_closure called!\n");
    // Got message
    if (!err_is_fail(err)) {
        // TODO: implement protocol here
        debug_printf("aos_rpc_recv_regular_closure success!\n");
    } else if (lmp_err_is_transient(err)) {
        debug_printf("aos_rpc_recv_regular_closure retry!\n");
        // Want to receive further messages
        err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                     MKCLOSURE(aos_rpc_recv_regular_closure, node));
        if (!err_is_fail(err)) {
            return;
        }
    }

    DEBUG_ERR(err, "recv_real_closure failed hard");
}

static void aos_rpc_send_setup_closure(void *arg)
{
    errval_t err;
    struct lmp_chan *chan = (struct lmp_chan *)arg;
    // Bump child that this channel is now ready
    err = lmp_ep_send(chan->remote_cap, LMP_FLAG_SYNC, NULL_CAP, 1, 1, 0, 0, 0);
    debug_printf("aos_rpc_send_setup_closure called!\n");
    // Got message
    if (!err_is_fail(err)) {
        debug_printf("aos_rpc_send_setup_closure success!\n");
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(aos_rpc_recv_regular_closure, arg));
        if (!err_is_fail(err)) {
            return;
        }
    } else if (lmp_err_is_transient(err)) {
        debug_printf("aos_rpc_send_setup_closure retry!\n");
        // Want to receive further messages
        err = lmp_chan_register_send(chan, get_default_waitset(),
                                     MKCLOSURE(aos_rpc_send_setup_closure, arg));
        if (!err_is_fail(err)) {
            return;
        }
    }

    DEBUG_ERR(err, "aos_rpc_send_setup_closure failed hard!\n");
}

static void aos_rpc_recv_setup_closure(void *arg)
{
    errval_t err;

    struct lmp_chan *chan = (struct lmp_chan *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(chan, &msg, &cap);

    debug_printf("aos_rpc_recv_setup_closure called!\n");

    // Got message
    if (!err_is_fail(err)) {
        chan->remote_cap = cap;

        err = lmp_chan_alloc_recv_slot(chan);
        if (err_is_fail(err)) {
            goto fail;
        }

        // FIXME: shouldn't this loop in usr/init/main.c not also just execute a send close?
        debug_printf("aos_rpc_recv_setup_closure success!\n");
        err = lmp_ep_send(chan->remote_cap, LMP_FLAG_SYNC, NULL_CAP, 1, 1, 0, 0, 0);
        if (!err_is_fail(err)) {
            err = lmp_chan_register_recv(chan, get_default_waitset(),
                                         MKCLOSURE(aos_rpc_recv_regular_closure, arg));
            return;
        } else if (lmp_err_is_transient(err)) {
            err = lmp_chan_register_send(chan, get_default_waitset(),
                                         MKCLOSURE(aos_rpc_send_setup_closure, arg));
        }
    } else if (lmp_err_is_transient(err)) {
        debug_printf("aos_rpc_recv_setup_closure retry!\n");
        // Want to receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(aos_rpc_recv_setup_closure, arg));
        if (!err_is_fail(err)) {
            return;
        }
    }

fail:
    DEBUG_ERR(err, "aos_rpc_recv_setup_closure failed hard!\n");
}

errval_t aos_rpc_init2(struct lmp_state *st)
{
    errval_t err;
    st->head = NULL;
    slab_init(&st->slabs, sizeof(struct dispatcher_node), slab_default_refill);
    err = slab_default_refill(&st->slabs);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLAB_REFILL);
    }

    // init doesn't get a cap_selfep
    err = cap_retype(cap_selfep, cap_dispatcher, 0, ObjType_EndPointLMP, 0, 1);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    set_current_lmp_state(st);

    return SYS_ERR_OK;
}

errval_t aos_rpc_create_child_channel(struct capref child_ep_cap,
                                      struct capref *ret_init_ep_cap)
{
    // FIXME: cleanup upon err
    errval_t err;
    struct lmp_state *st = get_current_lmp_state();
    assert(st != NULL);

    struct dispatcher_node *node = slab_alloc(&st->slabs);
    if (node == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    node->next = st->head;
    st->head = node;

    node->state = DISPATCHER_DISCONNECTED;

    struct capref init_ep_cap;
    struct lmp_endpoint *init_ep;
    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &init_ep_cap, &init_ep);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_ENDPOINT_CREATE);
    }

    lmp_chan_init(&node->chan);

    node->chan.local_cap = init_ep_cap;
    // node->chan.remote_cap = child_ep_cap;
    node->chan.endpoint = init_ep;

    // FIXME: Shouldn't be necessary
    err = lmp_chan_alloc_recv_slot(&node->chan);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_ALLOC_RECV_SLOT);
    }

    err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                 MKCLOSURE(aos_rpc_recv_setup_closure, &node->chan));
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
    }

    *ret_init_ep_cap = init_ep_cap;

    return SYS_ERR_OK;
}

void aos_rpc_handler_print(char *string, uintptr_t *val, struct capref *cap)
{
    if (string) {
        debug_printf("||TEST %s length %zu \n", string, strlen(string));
    }

    if (val) {
        debug_printf("||TEST %d \n", *val);
    }


    if (cap && !capref_is_null(*cap)) {
        char buf[256];
        debug_print_cap_at_capref(buf, 256, *cap);
        debug_printf("||TEST %s \n", buf);
    }
}


errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    // TODO: implement functionality to send a number over the channel
    // given channel and wait until the ack gets returned.
    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    // TODO: implement functionality to send a string over the given channel
    // and wait for a response.
    return SYS_ERR_OK;
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // TODO: implement functionality to request a RAM capability over the
    // given channel and wait until it is delivered.
    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    // TODO implement functionality to request a character from
    // the serial driver.
    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // TODO implement functionality to send a character to the
    // serial port.
    return SYS_ERR_OK;
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    // TODO (M5): implement spawn new process rpc
    return SYS_ERR_OK;
}


errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    // TODO (M5): implement name lookup for process given a process id
    return SYS_ERR_OK;
}


errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    // TODO (M5): implement process id discovery
    return SYS_ERR_OK;
}


errval_t aos_rpc_get_device_cap(struct aos_rpc *rpc, lpaddr_t paddr, size_t bytes,
                                struct capref *ret_cap)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    // TODO: Return channel to talk to init process
    debug_printf("aos_rpc_get_init_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    // TODO: Return channel to talk to memory server process (or whoever
    // implements memory server functionality)
    debug_printf("aos_rpc_get_memory_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    // TODO: Return channel to talk to process server process (or whoever
    // implements process server functionality)
    debug_printf("aos_rpc_get_process_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    // TODO: Return channel to talk to serial driver/terminal process (whoever
    // implements print/read functionality)
    debug_printf("aos_rpc_get_serial_channel NYI\n");
    return NULL;
}

