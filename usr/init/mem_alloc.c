/**
 * \file
 * \brief Local memory allocator for init till mem_serv is ready to use
 */

#include "mem_alloc.h"
#include <mm/mm.h>
#include <aos/paging.h>

/// MM allocator instance data
struct mm aos_mm;

errval_t aos_ram_alloc_aligned(struct capref *ret, size_t size, size_t alignment)
{
    return mm_alloc_aligned(&aos_mm, size, alignment, ret);
}

errval_t aos_ram_free(genpaddr_t addr)
{
    return mm_free(&aos_mm, addr);
}

/**
 * \brief Setups a local memory allocator for init to use till the memory server
 * is ready to be used. Inspects bootinfo for finding memory region.
 */
errval_t initialize_ram_alloc(struct capref mem_cap, genpaddr_t base, size_t size)
{
    errval_t err;

    // Initialize aos_mm
    err = mm_init(&aos_mm);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "Can't initalize the memory manager.");
    }

    // FIXME: shouldn't need to know so much about the internals of mm
    // Give aos_mm a bit of memory for the initialization
    static char bi_node_buf[sizeof(struct bi_node)*32];
    slab_grow(&aos_mm.bi_node_slab, bi_node_buf, sizeof(bi_node_buf));

    static char mm_node_buf[sizeof(struct mm_node)*64];
    slab_grow(&aos_mm.mm_node_slab, mm_node_buf, sizeof(mm_node_buf));

    static char avl_node_buf[sizeof(struct aos_avl_node)*64];
    slab_grow(&aos_mm.avl_node_slab, avl_node_buf, sizeof(avl_node_buf));

    err = mm_add(&aos_mm, mem_cap, base, size);
    if(err_is_fail(err)) {
        USER_PANIC_ERR(err, "Adding RAM region (%p/%zu) FAILED", base, size);
    }

    DEBUG_PRINTF("Added %"PRIu64" MB of physical memory starting at %p.\n", size / 1024 / 1024, base);

    // Finally, we can initialize the generic RAM allocator to use our local allocator
    err = ram_alloc_set(aos_ram_alloc_aligned);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
    }

    err = ram_free_set(aos_ram_free);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
    }

    return SYS_ERR_OK;
}

