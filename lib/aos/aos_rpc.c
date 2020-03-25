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

/// RPC channel to init
static struct aos_rpc rpc_init;

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

static errval_t aos_lmp_send(struct lmp_chan *chan, uint8_t message_type,
                             struct capref cap, uintptr_t arg1, uintptr_t arg2,
                             uintptr_t arg3)
{
    errval_t err;
    uintptr_t meta_data = (uintptr_t)message_type;
    uint8_t num_retries = 10;

    do {
        err = lmp_chan_send4(chan, LMP_SEND_FLAGS_DEFAULT, cap, meta_data, arg1, arg2,
                             arg3);
        if (err_is_fail(err)) {
            --num_retries;
            DEBUG_ERR(err, "Couldn't send message (%d retries left). Trying again...",
                      num_retries);
        }
    } while (err_is_fail(err) && (num_retries > 0));

    if (num_retries == 0) {
        DEBUG_ERR(err, "No retries left. Giving up...");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t aos_lmp_call(struct lmp_chan *chan, uint8_t message_type,
                             struct capref cap, uintptr_t arg1, uintptr_t arg2,
                             uintptr_t arg3, struct capref *ret_cap, uintptr_t *ret_arg1,
                             uintptr_t *ret_arg2, uintptr_t *ret_arg3)
{
    // XXX This is maybe too simple but it works as long as call is blocking and
    //    the remote ep sends the answers in the correct order
    errval_t err;

    err = aos_lmp_send(chan, message_type, cap, arg1, arg2, arg3);

    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    //FIXME Rewrite this using lmp_recv_register and event_dispatch
    do {
        // block until message is available
        err = lmp_chan_recv(chan, &msg, ret_cap);
    } while (err == LIB_ERR_NO_LMP_MSG);

    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_RECV);
    }

    *ret_arg1 = msg.words[1];
    *ret_arg2 = msg.words[2];
    *ret_arg3 = msg.words[3];

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    // TODO: implement functionality to send a number over the channel
    // given channel and wait until the ack gets returned.
    return aos_lmp_send(&rpc->chan, 1, NULL_CAP, num, 0, 0);
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

    uintptr_t arg2 = 0;
    uintptr_t arg3 = 0;
    aos_lmp_call(&rpc->chan, 2, NULL_CAP, bytes, alignment, 0, ret_cap, ret_bytes, &arg2,
                 &arg3);

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
    //FIXME return channel to memory server domain
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

