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

void aos_rpc_init(void)
{
    //FIXME Use different init on second core
    rpc_init.recv_id = 0x0;
    rpc_init.send_id = disp_get_domain_id();
    set_init_rpc(&rpc_init);
}

static uint64_t create_header(struct aos_rpc *rpc, uint16_t msg_type) {
    return AOS_RPC_HEADER(rpc->send_id, rpc->recv_id, msg_type);
}

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    // Protocol
    // Request: AOS_RPC_SEND_NUMBER, number
    // Response: None
    return lmp_protocol_send1(get_init_client_chan(), create_header(rpc, AOS_RPC_SEND_NUMBER), num);
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    // Protocol
    // Requests: send_string(AOS_RPC_SEND_STRING, string)
    // (Up to strlen(string) / 4 + 2 messages are sent)
    // Response: None
    return lmp_protocol_send_string(get_init_client_chan(), create_header(rpc, AOS_RPC_SEND_STRING), string);
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // Protocol
    // Request: AOS_RPC_GET_RAM_CAP, size, alignment
    // Response: AOS_RPC_GET_RAM_CAP, size, alignment, success
    // Response Cap: Aquired RAM capability

    errval_t err;

    // Request ram cap
    err = lmp_protocol_send2(get_init_client_chan(), create_header(rpc, AOS_RPC_GET_RAM_CAP), bytes, alignment);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_RAM_CAP);
    }

    // Handle response
    uintptr_t ret_size = 0;
    uintptr_t ret_alignment = 0;
    uintptr_t ret_success = 0;
    err = lmp_protocol_recv_cap3(get_init_client_chan(),
                                 create_header(rpc, AOS_RPC_GET_RAM_CAP), ret_cap,
                                 &ret_size, &ret_alignment, &ret_success);
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

    // Try freeing RAM
    err = lmp_protocol_send1(get_init_client_chan(), create_header(rpc, AOS_RPC_FREE_RAM_CAP), addr);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_FREE_RAM_CAP);
    }

    // Handle response
    uintptr_t ret_addr = 0;
    uintptr_t ret_success = 0;
    err = lmp_protocol_recv2(get_init_client_chan(), create_header(rpc, AOS_RPC_FREE_RAM_CAP), &ret_addr, &ret_success);
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
    return lmp_protocol_send0(get_init_client_chan(), create_header(rpc, AOS_RPC_SERIAL_GETCHAR));
}

errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // Protocol
    // FIXME: Send pid of process, so serial service can add line buffer per child
    // Request: AOS_RPC_SERIAL_GETCHAR, char
    // Response: None
    return lmp_protocol_send1(get_init_client_chan(), create_header(rpc, AOS_RPC_SERIAL_PUTCHAR), c);
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
    assert(newpid != NULL);
    uintptr_t ret_pid = 0;
    uintptr_t ret_success = 0;

    // Request process spawn on specified core
    err = lmp_protocol_send1(get_init_client_chan(), create_header(rpc, AOS_RPC_PROCESS_SPAWN), core);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
    }

    // Send commandline that should be used to spawn process
    err = lmp_protocol_send_string(get_init_client_chan(), create_header(rpc, AOS_RPC_PROCESS_SPAWN_CMD), cmdline);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
    }

    // Get pid and success information
    err = lmp_protocol_recv2(get_init_client_chan(), create_header(rpc, AOS_RPC_PROCESS_SPAWN), &ret_pid, &ret_success);
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

    err = lmp_protocol_send1(get_init_client_chan(), create_header(rpc, AOS_RPC_PROCESS_GET_NAME), pid);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_NAME);
    }

    uintptr_t success;
    err = lmp_protocol_recv1(get_init_client_chan(), create_header(rpc, AOS_RPC_PROCESS_GET_NAME), &success);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_NAME);
    }
    if (!success) {
        return AOS_ERR_RPC_GET_NAME;
    }

    char * ret_name;
    err = lmp_protocol_recv_string(get_init_client_chan(),
                                   create_header(rpc, AOS_RPC_PROCESS_GET_NAME_STR),
                                   &ret_name);
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

    err = lmp_protocol_send0(get_init_client_chan(),
                             create_header(rpc, AOS_RPC_PROCESS_GET_ALL_PIDS));
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_PIDS);
    }

    size_t size;
    uint8_t * bytes;
    err = lmp_protocol_recv_bytes(get_init_client_chan(),
                                  create_header(rpc, AOS_RPC_PROCESS_GET_ALL_PIDS), &size,
                                  &bytes);
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
    return lmp_protocol_send0(get_init_client_chan(),
                              create_header(rpc, AOS_RPC_PROCESS_EXIT));
}

errval_t aos_rpc_get_device_cap(struct aos_rpc *rpc, lpaddr_t paddr, size_t bytes,
                                struct capref *ret_cap)
{
    // Protocol
    // Request: AOS_RPC_GET_DEVICE_CAP, physical address, size
    // Response: AOS_RPC_GET_DEVICE_CAP, physical address, size, success
    // Response Cap: Aquired Device Cap
    errval_t err;

    // Request ram cap
    err = lmp_protocol_send2(get_init_client_chan(),
                             create_header(rpc, AOS_RPC_GET_DEVICE_CAP), paddr, bytes);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_DEVICE_CAP);
    }

    // Handle response
    uintptr_t ret_paddr = 0;
    uintptr_t ret_bytes = 0;
    uintptr_t ret_success = 0;
    err = lmp_protocol_recv_cap3(get_init_client_chan(),
                                 create_header(rpc, AOS_RPC_GET_DEVICE_CAP), ret_cap,
                                 &ret_paddr, &ret_bytes, &ret_success);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_RAM_CAP);
    } else if (!ret_success) {
        return AOS_ERR_RPC_GET_DEVICE_CAP_REMOTE_ERR;
    }

    if (ret_paddr != paddr) {
        return AOS_ERR_RPC_GET_DEVICE_CAP_REMOTE_ERR;
    }

    if (ret_bytes < bytes) {
        return AOS_ERR_RPC_GET_DEVICE_CAP_REMOTE_ERR;
    }

    return SYS_ERR_OK;
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
