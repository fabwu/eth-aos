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
#include <aos/lmp_protocol.h>
#include <aos/aos_rpc.h>

/// RPC channel to init
static struct aos_rpc rpc_init;

static void aos_rpc_assert(struct aos_rpc *rpc)
{
    assert(rpc != NULL);
    assert(rpc->chan.endpoint != NULL);
    assert(!capref_is_null(rpc->chan.remote_cap));
    assert(!capref_is_null(rpc->chan.local_cap));
}

void aos_rpc_set_init_channel(struct lmp_chan chan)
{
    rpc_init.chan = chan;
}

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    // Protocol
    // Request: AOS_RPC_SEND_NUMBER, number
    // Response: None

    aos_rpc_assert(rpc);
    return lmp_protocol_send1(&rpc->chan, AOS_RPC_SEND_NUMBER, num);
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    // Protocol
    // Requests: send_string(AOS_RPC_SEND_STRING, string)
    // (Up to strlen(string) / 4 + 2 messages are sent)
    // Response: None

    aos_rpc_assert(rpc);
    return lmp_protocol_send_string(&rpc->chan, AOS_RPC_SEND_STRING, string);
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // Protocol
    // Request: AOS_RPC_GET_RAM_CAP, size, alignment
    // Response: AOS_RPC_GET_RAM_CAP, size, alignment, success
    // Response Cap: Aquired RAM capability

    errval_t err;
    aos_rpc_assert(rpc);

    // Request ram cap
    err = lmp_protocol_send2(&rpc->chan, AOS_RPC_GET_RAM_CAP, bytes, alignment);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_RAM_CAP);
    }

    // Handle response
    uintptr_t ret_size = 0;
    uintptr_t ret_alignment = 0;
    uintptr_t ret_success = 0;
    err = lmp_protocol_recv_cap3(&rpc->chan, AOS_RPC_GET_RAM_CAP, ret_cap, &ret_size,
                                 &ret_alignment, &ret_success);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_RAM_CAP);
    } else if (!ret_success) {
        return AOS_ERR_RPC_GET_RAM_CAP_REMOTE_ERR;
    }

    // Not passing ret_bytes directly because of mismatching types
    *ret_bytes = ret_size;

    // Did not get enough bytes
    if (*ret_bytes < bytes) {
        // TODO: call aos_rpc_return_ram_cap to clean up
        return AOS_ERR_RPC_GET_RAM_CAP_REMOTE_ERR;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_free_ram_cap(struct aos_rpc *rpc, genpaddr_t addr)
{
    // Protocol
    // FIXME: Send a cap instead of the physical address
    // Request: AOS_RPC_FREE_RAM_CAP, physical address
    // Response: AOS_RPC_FREE_RAM_CAP, physical address, success

    errval_t err;
    aos_rpc_assert(rpc);

    // Try freeing RAM
    err = lmp_protocol_send1(&rpc->chan, AOS_RPC_FREE_RAM_CAP, addr);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_FREE_RAM_CAP);
    }

    // Handle response
    uintptr_t ret_addr = 0;
    uintptr_t ret_success = 0;
    err = lmp_protocol_recv2(&rpc->chan, AOS_RPC_FREE_RAM_CAP, &ret_addr, &ret_success);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_FREE_RAM_CAP);
    } else if (!ret_success) {
        return AOS_ERR_RPC_FREE_RAM_CAP_REMOTE_ERR;
    }

    // Didn't get what I wanted
    if (ret_addr != addr) {
        return AOS_ERR_RPC_FREE_RAM_CAP_REMOTE_ERR;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    // Protocol
    // FIXME: Not implemented
    // Request: AOS_RPC_SERIAL_GETCHAR
    // TODO: Response: AOS_RPC_SERIAL_GETCHAR, char

    aos_rpc_assert(rpc);
    return lmp_protocol_send0(&rpc->chan, AOS_RPC_SERIAL_GETCHAR);
}

errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // Protocol
    // FIXME: Send pid of process, so serial service can add line buffer per child
    // Request: AOS_RPC_SERIAL_GETCHAR, char
    // Response: None

    aos_rpc_assert(rpc);
    return lmp_protocol_send1(&rpc->chan, AOS_RPC_SERIAL_PUTCHAR, c);
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    // Protocol
    // Requests:
    //     AOS_RPC_PROCESS_SPAWN, core id
    //     send_string(AOS_RPC_PROCESS_SPAWN_CMD, cmdline)
    // Response: AOS_RPC_PROCESS_SPAWN, domain id, success

    errval_t err;
    aos_rpc_assert(rpc);
    uintptr_t ret_pid = 0;
    uintptr_t ret_success = 0;

    // Request process spawn on specified core
    err = lmp_protocol_send1(&rpc->chan, AOS_RPC_PROCESS_SPAWN, core);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
    }

    // Send commandline that should be used to spawn process
    err = lmp_protocol_send_string(&rpc->chan, AOS_RPC_PROCESS_SPAWN_CMD, cmdline);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
    }

    // Get pid and success information
    err = lmp_protocol_recv2(&rpc->chan, AOS_RPC_PROCESS_SPAWN, &ret_pid, &ret_success);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
    } else if (!ret_success) {
        *newpid = 0;
        return AOS_ERR_RPC_SPAWN_PROCESS;
    }

    // Not passing newpid directly because of mismatching types
    *newpid = ret_pid;

    return SYS_ERR_OK;
}

errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    // Protocol
    // Request: AOS_RPC_PROCESS_GET_NAME, pid
    // Responses:
    //     AOS_RPC_PROCESS_GET_NAME, success
    //     recv_string(AOS_RPC_PROCESS_GET_NAME_STR, &name)

    errval_t err;
    aos_rpc_assert(rpc);

    err = lmp_protocol_send1(&rpc->chan, AOS_RPC_PROCESS_GET_NAME, pid);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_NAME);
    }

    uintptr_t success;
    err = lmp_protocol_recv1(&rpc->chan, AOS_RPC_PROCESS_GET_NAME, &success);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_NAME);
    }
    if (!success) {
        return AOS_ERR_RPC_GET_NAME;
    }

    char * ret_name;
    err = lmp_protocol_recv_string(&rpc->chan, AOS_RPC_PROCESS_GET_NAME_STR, &ret_name);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_NAME);
    }

    if (name != NULL) {
        *name = ret_name;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    // Protocol
    // Request: AOS_RPC_PROCESS_GET_ALL_PIDS
    // Respons: recv_bytes(AOS_RPC_PROCESS_GET_ALL_PIDS, &pid_count, &pids)

    errval_t err;
    aos_rpc_assert(rpc);

    err = lmp_protocol_send0(&rpc->chan, AOS_RPC_PROCESS_GET_ALL_PIDS);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_PIDS);
    }

    size_t size;
    uint8_t * bytes;
    err = lmp_protocol_recv_bytes(&rpc->chan, AOS_RPC_PROCESS_GET_ALL_PIDS, &size, &bytes);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_PIDS);
    }
    
    assert(size % sizeof(domainid_t) == 0);

    if (pid_count != NULL) {
        *pid_count = size / sizeof(domainid_t);
    }
    if (pids != NULL) {
        *pids = (domainid_t *)bytes;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_process_exit(struct aos_rpc *rpc)
{
    // Protocol
    // Request: AOS_RPC_PROCESS_EXIT
    // Responses: None

    return lmp_protocol_send0(&rpc->chan, AOS_RPC_PROCESS_EXIT);
}

errval_t aos_rpc_get_device_cap(struct aos_rpc *rpc, lpaddr_t paddr, size_t bytes,
                                struct capref *ret_cap)
{
    // Protocol
    // FIXME: Not implemented
    // TODO: Request: AOS_RPC_GET_DEVICE_CAP, physical address, size
    // TODO: Response: AOS_RPC_GET_DEVICE_CAP, physical address, size, success
    // TODO: Response Cap: Aquired Device Cap

    aos_rpc_assert(rpc);
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
    // FIXME: return channel to memory server domain
    return &rpc_init;
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    // FIXME: return channel to process server domain
    return &rpc_init;
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    // FIXME: return channel to terminal server domain
    return &rpc_init;
}
