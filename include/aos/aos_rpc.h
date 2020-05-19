/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _LIB_BARRELFISH_AOS_MESSAGES_H
#define _LIB_BARRELFISH_AOS_MESSAGES_H

#include <aos/aos.h>
#include <aos/lmp_protocol.h>

typedef uintptr_t aos_rpc_header_t;
typedef uint8_t  aos_rpc_msg_t;

#define AOS_RPC_BUFFER_SIZE             3*sizeof(uintptr_t)

// Header
// 64-bit word
// 8-bit msg type (lsb)
// 16-bit sender did
// 16-bit recv did
// 24-bit not used
#define AOS_RPC_HEADER(sender, receiver, type) ( \
            ( (aos_rpc_header_t) (sender   & 0xffff) << 24 ) | \
            ( (aos_rpc_header_t) (receiver & 0xffff) << 8 )  | \
            ( type & 0xff ) \
        )

// extract sender from header
#define AOS_RPC_HEADER_SEND(header) ((header >> 24) & 0xffff)

// extract receiver from header
#define AOS_RPC_HEADER_RECV(header) ((header >> 8) & 0xffff)

// extract message type from header
#define AOS_RPC_HEADER_MSG(header) (header & 0xff)

#define AOS_RPC_CORE_ID(domainid) ( (domainid & 0xffff) >> 15)

// Message types

#define AOS_RPC_SEND_NUMBER              0x01
#define AOS_RPC_SEND_STRING              0x02
#define AOS_RPC_GET_RAM_CAP              0x03
#define AOS_RPC_FREE_RAM_CAP             0x04
#define AOS_RPC_SERIAL_GETCHAR           0x05
#define AOS_RPC_SERIAL_PUTCHAR           0x06
#define AOS_RPC_PROCESS_SPAWN            0x07
#define AOS_RPC_PROCESS_SPAWN_CMD        0x08
#define AOS_RPC_PROCESS_GET_NAME         0x09
#define AOS_RPC_PROCESS_GET_NAME_STR     0x0a
#define AOS_RPC_PROCESS_GET_ALL_PIDS     0x0b
#define AOS_RPC_GET_DEVICE_CAP           0x0c
#define AOS_RPC_PROCESS_EXIT             0x0d
#define AOS_RPC_PROCESS_SPAWN_REMOTE     0x0e
#define AOS_RPC_PROCESS_SPAWN_REMOTE_CMD 0x0f
#define AOS_RPC_MSG_NS_REGISTER          0x10
#define AOS_RPC_MSG_NS_LOOKUP            0x11

#define AOS_RPC_SETUP                    0xff

/* An RPC binding, which may be transported over LMP or UMP. */
struct aos_rpc {
    domainid_t send_id;
    domainid_t recv_id;
};

/**
 * \brief Set channel to init
 */
void aos_rpc_init(void);

/**
 * \brief Send a number.
 */
errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t val);

/**
 * \brief Send a string.
 */
errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string);

/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *retcap, size_t *ret_bytes);

/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_free_ram_cap(struct aos_rpc *rpc, genpaddr_t addr);

/**
 * \brief Get one character from the serial port
 */
errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc);

/**
 * \brief Send one character to the serial port
 */
errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c);

/**
 * \brief Request that the process manager start a new process
 * \arg name the name of the process that needs to be spawned (without a
 *           path prefix)
 * \arg newpid the process id of the newly-spawned process
 */
errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *name, coreid_t core,
                               domainid_t *newpid);

/**
 * \brief Get name of process with the given PID.
 * \arg pid the process id to lookup
 * \arg name A null-terminated character array with the name of the process
 * that is allocated by the rpc implementation. Freeing is the caller's
 * responsibility.
 */
errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name);

/**
 * \brief Get PIDs of all running processes.
 * \arg pids An array containing the process ids of all currently active
 * processes. Will be allocated by the rpc implementation. Freeing is the
 * caller's  responsibility.
 * \arg pid_count The number of entries in `pids' if the call was successful
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count);

/**
 * \brief Remove process from the running processes.
 */
errval_t aos_rpc_process_exit(struct aos_rpc *rpc);

/**
 * \brief Request a device cap for the given region.
 * @param chan  the rpc channel
 * @param paddr physical address of the device
 * @param bytes number of bytes of the device memory
 * @param frame returned frame
 */
errval_t aos_rpc_get_device_cap(struct aos_rpc *rpc, lpaddr_t paddr, size_t bytes,
                                struct capref *frame);

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void);

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void);

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void);

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void);

#endif  // _LIB_BARRELFISH_AOS_MESSAGES_H
