/**
 * \file
 * \brief rpc functions
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_RPC_H_
#define _INIT_RPC_H_

#include <stdio.h>
#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/aos_rpc.h>
#include <aos/ump.h>
#include <grading.h>

#include  "spawn.h"

void rpc_ump_start_handling(void);
errval_t rpc_create_child_channel_to_init(struct spawn_node *node);
extern struct aos_ump ump;

#endif
