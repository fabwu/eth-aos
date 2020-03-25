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

#include <stdio.h>
#include <aos/aos.h>
#include <aos/core_state.h>

errval_t rpc_initialize_lmp(struct lmp_state *lmp_state);
errval_t rpc_create_child_channel_to_init(struct capref *ret_init_ep_cap);

