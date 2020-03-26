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

struct lmp_msg_state {
    struct lmp_chan *chan;
    uint8_t message_type;
    struct capref cap;
    uintptr_t arg1;
    uintptr_t arg2;
    uintptr_t arg3;
    struct capref *ret_cap;
    uintptr_t *ret_arg1;
    uintptr_t *ret_arg2;
    uintptr_t *ret_arg3;
    bool done;
};

/// RPC channel to init
static struct aos_rpc rpc_init;

static errval_t aos_rpc_lmp_send(struct lmp_chan *chan, uint8_t message_type,
                                 struct capref cap, uintptr_t arg1, uintptr_t arg2,
                                 uintptr_t arg3);

#define aos_rpc_lmp_send_cap(chan, msg_type, send_cap)                                   \
    aos_rpc_lmp_send((chan), (msg_type), (send_cap), 0, 0, 0)
#define aos_rpc_lmp_send1(chan, msg_type, arg1)                                          \
    aos_rpc_lmp_send((chan), (msg_type), NULL_CAP, (arg1), 0, 0)
#define aos_rpc_lmp_send2(chan, msg_type, arg1, arg2)                                    \
    aos_rpc_lmp_send((chan), (msg_type), NULL_CAP, (arg1), (arg2), 0)
#define aos_rpc_lmp_send3(chan, msg_type, arg1, arg2, arg3)                              \
    aos_rpc_lmp_send((chan), (msg_type), NULL_CAP, (arg1), (arg2), (arg3))
#define aos_rpc_lmp_send_cap1(chan, msg_type, send_cap, arg1)                            \
    aos_rpc_lmp_send((chan), (msg_type), (send_cap), (arg1), 0, 0)
#define aos_rpc_lmp_send_cap2(chan, msg_type, send_cap, arg1, arg2)                      \
    aos_rpc_lmp_send((chan), (msg_type), (send_cap), (arg1), (arg2), 0)
#define aos_rpc_lmp_send_cap3(chan, msg_type, send_cap, arg1, arg2, arg3)                \
    aos_rpc_lmp_send((chan), (msg_type), (send_cap), (arg1), (arg2), (arg3))

static errval_t aos_rpc_lmp_call(struct lmp_chan *chan, uint8_t message_type,
                                 struct capref cap, uintptr_t arg1, uintptr_t arg2,
                                 uintptr_t arg3, struct capref *ret_cap,
                                 uintptr_t *ret_arg1, uintptr_t *ret_arg2,
                                 uintptr_t *ret_arg3);
// TODO How to deal with ret values in macro?

static void aos_rpc_send_closure(void *arg)
{
    errval_t err;

    struct lmp_msg_state *st = (struct lmp_msg_state *)arg;

    err = lmp_chan_send4(st->chan, LMP_SEND_FLAGS_DEFAULT, st->cap, st->message_type,
                         st->arg1, st->arg2, st->arg3);

    if (err_is_ok(err)) {
        st->done = true;
        return;
    } else if (lmp_err_is_transient(err)) {
        err = lmp_chan_register_send(st->chan, get_default_waitset(),
                                     MKCLOSURE(aos_rpc_send_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

    DEBUG_ERR(err, "send_closure failed hard");
}

static errval_t aos_rpc_lmp_send(struct lmp_chan *chan, uint8_t message_type,
                                 struct capref cap, uintptr_t arg1, uintptr_t arg2,
                                 uintptr_t arg3)
{
    errval_t err = SYS_ERR_OK;
    struct lmp_msg_state *state = (struct lmp_msg_state *)malloc(
        sizeof(struct lmp_msg_state));

    state->chan = chan;
    state->message_type = message_type;
    state->cap = cap;
    state->arg1 = arg1;
    state->arg2 = arg2;
    state->arg3 = arg3;
    state->done = false;

    aos_rpc_send_closure(state);

    struct waitset *default_ws = get_default_waitset();
    while (!state->done) {
        debug_printf("loop call\n");
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_EVENT_DISPATCH);
            goto out;
        }
    }

out:
    free(state);
    return err;
}

static void aos_rpc_call_recv_closure(void *arg)
{
    errval_t err;

    struct lmp_msg_state *st = (struct lmp_msg_state *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(st->chan, &msg, st->ret_cap);

    if (err_is_ok(err)) {
        if (!capref_is_null(*st->ret_cap)) {
            err = lmp_chan_alloc_recv_slot(st->chan);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Couldn't allocate slot for ret_cap");
            }
        }

        *st->ret_arg1 = msg.words[1];
        *st->ret_arg2 = msg.words[2];
        *st->ret_arg3 = msg.words[3];
        st->done = true;
        return;
    } else if (lmp_err_is_transient(err)) {
        err = lmp_chan_register_recv(st->chan, get_default_waitset(),
                                     MKCLOSURE(aos_rpc_call_recv_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

    DEBUG_ERR(err, "recv_closure failed hard");
}

static void aos_rpc_call_send_closure(void *arg)
{
    errval_t err;

    struct lmp_msg_state *st = (struct lmp_msg_state *)arg;

    err = lmp_chan_send4(st->chan, LMP_SEND_FLAGS_DEFAULT, st->cap, st->message_type,
                         st->arg1, st->arg2, st->arg3);

    if (err_is_ok(err)) {
        err = lmp_chan_register_recv(st->chan, get_default_waitset(),
                                     MKCLOSURE(aos_rpc_call_recv_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    } else if (lmp_err_is_transient(err)) {
        err = lmp_chan_register_send(st->chan, get_default_waitset(),
                                     MKCLOSURE(aos_rpc_call_send_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

    DEBUG_ERR(err, "send_closure failed hard");
}

static errval_t aos_rpc_lmp_call(struct lmp_chan *chan, uint8_t message_type,
                                 struct capref cap, uintptr_t arg1, uintptr_t arg2,
                                 uintptr_t arg3, struct capref *ret_cap,
                                 uintptr_t *ret_arg1, uintptr_t *ret_arg2,
                                 uintptr_t *ret_arg3)
{
    errval_t err = SYS_ERR_OK;
    struct lmp_msg_state *state = (struct lmp_msg_state *)malloc(
        sizeof(struct lmp_msg_state));

    state->chan = chan;
    state->message_type = message_type;
    state->cap = cap;
    state->arg1 = arg1;
    state->arg2 = arg2;
    state->arg3 = arg3;
    state->ret_cap = ret_cap;
    state->ret_arg1 = ret_arg1;
    state->ret_arg2 = ret_arg2;
    state->ret_arg3 = ret_arg3;
    state->done = false;

    aos_rpc_call_send_closure(state);

    struct waitset *default_ws = get_default_waitset();
    while (!state->done) {
        debug_printf("loop call\n");
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_EVENT_DISPATCH);
            goto out;
        }
    }

out:
    free(state);
    return err;
}

errval_t aos_rpc_set_init_channel(struct lmp_chan chan)
{
    // TODO Should we init the channel like this?
    struct aos_rpc *init_channel = aos_rpc_get_init_channel();
    init_channel->chan = chan;

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
    return aos_rpc_lmp_send1(&rpc->chan, AOS_RPC_MSG_SEND_NUMBER, num);
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
    errval_t err;
    uintptr_t ret_alignment = 0;
    uintptr_t ret_success = 0;
    err = aos_rpc_lmp_call(&rpc->chan, AOS_RPC_MSG_GET_RAM_CAP, NULL_CAP, bytes,
                           alignment, 0, ret_cap, ret_bytes, &ret_alignment, &ret_success);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_LMP_CALL);
    }

    // get ram cap failed
    if (!ret_success) {
        return AOS_ERR_RPC_GET_RAM_CAP_REMOTE_ERR;
    }

    // Didn't get what I wanted
    if (*ret_bytes != bytes) {
        // TODO: call aos_rpc_return_ram_cap to clean up
        return AOS_ERR_RPC_GET_RAM_CAP_REMOTE_ERR;
    }

    char buf[256];
    debug_print_cap_at_capref(buf, 256, *ret_cap);

    DEBUG_PRINTF("ANSWER >>> bytes: %d %s\n", *ret_bytes, buf);
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
    return &rpc_init;
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    // FIXME return channel to memory server domain
    return &rpc_init;
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

