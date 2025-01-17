/**
 * \file
 * \brief RAM allocator code (client-side)
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2011, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/core_state.h>

/* remote (indirect through a channel) version of ram_alloc, for most domains */
static errval_t ram_alloc_remote(struct capref *ret, size_t size, size_t alignment)
{
    errval_t err;
    struct aos_rpc *mem_channel = aos_rpc_get_memory_channel();

    size_t retbytes;
    err = aos_rpc_get_ram_cap(mem_channel, size, alignment, ret, &retbytes);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_GET_RAM_CAP);
    }
    // TODO: if request couldn't be fulfilled, error out
    assert(size == retbytes);

    return SYS_ERR_OK;
}

static errval_t ram_free_remote(genpaddr_t addr)
{
    errval_t err;
    struct aos_rpc *mem_channel = aos_rpc_get_memory_channel();

    DEBUG_PRINTF("Free RAM");
    err = aos_rpc_free_ram_cap(mem_channel, addr);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_RPC_FREE_RAM_CAP);
    }

    return SYS_ERR_OK;
}


void ram_set_affinity(uint64_t minbase, uint64_t maxlimit)
{
    struct ram_alloc_state *ram_alloc_state = get_ram_alloc_state();
    ram_alloc_state->default_minbase = minbase;
    ram_alloc_state->default_maxlimit = maxlimit;
}

void ram_get_affinity(uint64_t *minbase, uint64_t *maxlimit)
{
    struct ram_alloc_state *ram_alloc_state = get_ram_alloc_state();
    *minbase  = ram_alloc_state->default_minbase;
    *maxlimit = ram_alloc_state->default_maxlimit;
}

#define OBJSPERPAGE_CTE         (1 << (BASE_PAGE_BITS - OBJBITS_CTE))

errval_t ram_alloc_fixed(struct capref *ret, size_t size, size_t alignment)
{
    struct ram_alloc_state *state = get_ram_alloc_state();

    debug_printf("size: 0x%"PRIx64" alignment: 0x%"PRIx64"\n", size, alignment);
    if (size == BASE_PAGE_SIZE && alignment <= BASE_PAGE_SIZE) {
        // XXX: Return error if check to see if out of slots
        assert(state->base_capnum < OBJSPERPAGE_CTE);
        ret->cnode = cnode_base;
        ret->slot  = state->base_capnum++;
        return SYS_ERR_OK;
    } else {
        return LIB_ERR_RAM_ALLOC_WRONG_SIZE;
    }
}

#include <stdio.h>
#include <string.h>

/**
 * \brief Allocates aligned memory in the form of a RAM capability
 *
 * \param ret  Pointer to capref struct, filled-in with allocated cap location
 * \param size Amount of RAM to allocate, in bytes
 * \param alignment Alignment of RAM to allocate
 *              slot used for the cap in #ret, if any
 */
errval_t ram_alloc_aligned(struct capref *ret, size_t size, size_t alignment)
{
    struct ram_alloc_state *ram_alloc_state = get_ram_alloc_state();
    assert(ram_alloc_state->ram_alloc_func != NULL);
    errval_t err = ram_alloc_state->ram_alloc_func(ret, size, alignment);
#if 0
    if(err_is_fail(err)) {
      DEBUG_ERR(err, "failed to allocate 2^%" PRIu32 " Bytes of RAM",
                size_bits);
      printf("callstack: %p %p %p %p\n",
	     __builtin_return_address(0),
	     __builtin_return_address(1),
	     __builtin_return_address(2),
	     __builtin_return_address(3));
    }
#endif
    return err;
}

/**
 * \brief Allocates memory in the form of a RAM capability
 *
 * \param ret Pointer to capref struct, filled-in with allocated cap location
 * \param size Amount of RAM to allocate, in bytes.
 *              slot used for the cap in #ret, if any
 */
errval_t ram_alloc(struct capref *ret, size_t size)
{
    return ram_alloc_aligned(ret, size, BASE_PAGE_SIZE);
}

// TODO: due to frame_free destroying ram_cap, we always need to destry ram_cap,
// can't give this function a cap..
errval_t ram_free(genpaddr_t addr)
{
    struct ram_alloc_state *ram_alloc_state = get_ram_alloc_state();
    assert(ram_alloc_state->ram_free_func != NULL);
    return ram_alloc_state->ram_free_func(addr);
}

errval_t ram_available(genpaddr_t *available, genpaddr_t *total)
{
    // TODO: Implement protocol to check amount of ram available with memserv
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * \brief Initialize the dispatcher specific state of ram_alloc
 */
void ram_alloc_init(void)
{
    /* Initialize the ram_alloc_state */
    struct ram_alloc_state *ram_alloc_state = get_ram_alloc_state();
    ram_alloc_state->mem_connect_done = false;
    ram_alloc_state->mem_connect_err  = 0;
    thread_mutex_init(&ram_alloc_state->ram_alloc_lock);
    ram_alloc_state->ram_alloc_func   = NULL;
    ram_alloc_state->default_minbase  = 0;
    ram_alloc_state->default_maxlimit = 0;
    ram_alloc_state->base_capnum      = 0;
}

/**
 * \brief Set ram_alloc to the default ram_alloc_remote or to a given function
 *
 * If local_allocator is NULL, it will be initialized to the default
 * remote allocator.
 */
errval_t ram_alloc_set(ram_alloc_func_t local_allocator)
{
    struct ram_alloc_state *ram_alloc_state = get_ram_alloc_state();

    /* Special case */
    if (local_allocator != NULL) {
        ram_alloc_state->ram_alloc_func = local_allocator;
        return SYS_ERR_OK;
    }

    ram_alloc_state->ram_alloc_func = ram_alloc_remote;
    return SYS_ERR_OK;
}

errval_t ram_free_set(ram_free_func_t local_free)
{
    struct ram_alloc_state *ram_alloc_state = get_ram_alloc_state();

    /* Special case */
    if (local_free != NULL) {
        ram_alloc_state->ram_free_func = local_free;
        return SYS_ERR_OK;
    }

    // TODO: Adjust method signature
    ram_alloc_state->ram_free_func = ram_free_remote;

    return SYS_ERR_OK;
}
