/**
 * \file
 * \brief ram allocator functions
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_TERMINAL_H_
#define _INIT_TERMINAL_H_

#include <aos/aos.h>
#include <aos/lmp_protocol.h>

errval_t terminal_init(void);
void terminal_getchar(struct lmp_chan *chan);
void terminal_putchar(char c, domainid_t pid);

#endif /* _INIT_TERMINAL_H_ */
