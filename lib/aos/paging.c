/**
 * \file
 * \brief AOS paging helpers.
 */

/*
 * Copyright (c) 2012, 2013, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/paging.h>
#include <aos/except.h>
#include <aos/slab.h>
#include "arch/threads.h"
#include "threads_priv.h"

#include <stdio.h>
#include <string.h>

#define EX_STACK_SIZE (1 << 14)
static char ex_stack_first[EX_STACK_SIZE];

#if 0
#    define DEBUG_PAGING(fmt...) debug_printf(fmt);
#else
#    define DEBUG_PAGING(fmt...) ((void)0)
#endif

#if 0
#    define DEBUG_PAGING_FINE(fmt...) debug_printf(fmt);
#else
#    define DEBUG_PAGING_FINE(fmt...) ((void)0)
#endif

#if 0
#    define DEBUG_EXCEPTION_HANDLER(fmt...) debug_printf(fmt);
#else
#    define DEBUG_EXCEPTION_HANDLER(fmt...) ((void)0)
#endif

static struct paging_state current;

static char paging_node_buf[sizeof(struct paging_node) * 64];
static char paging_avl_node_buf[sizeof(struct aos_avl_node) * 64];

/**
 * \brief Initialize the paging_state struct for the paging
 *        state of the calling process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L0 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr,
                           lvaddr_t max_vaddr, struct capref pdir)
{
    errval_t err;

    st->l0.table = pdir;
    st->l0.parent = NULL;
    st->l0.child = NULL;
    st->l0.level = 0;
    st->l0.slot = 0;

    thread_mutex_init(&st->paging_mutex);
    thread_mutex_init(&st->heap_mutex);

    slab_init(&st->slabs, sizeof(struct paging_node), NULL);
    st->slab_refilling = 0;

    slab_init(&st->avl_slabs, sizeof(struct aos_avl_node), NULL);
    st->avl_slab_refilling = 0;

    err = addr_mgr_init(&st->addr_mgr_state, start_vaddr, max_vaddr);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_ADDR_MGR_INIT);
    }

    return SYS_ERR_OK;
}

/**
 * \brief Initialize the paging_state struct for the paging state
 *        of a child process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L0 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   lvaddr_t max_vaddr, struct capref pdir,
                                   struct slot_allocator *ca)
{
    errval_t err;

    // address space has to start at zero so we can catch null pointers
    assert(start_vaddr == 0);

    err = paging_init_state(st, start_vaddr, max_vaddr, pdir);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_INIT_STATE);
    }

    err = slab_default_refill(&st->slabs);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLAB_REFILL);
    }

    err = slab_default_refill(&st->avl_slabs);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLAB_REFILL);
    }

    // reserve first page to catch null pointers
    err = addr_mgr_alloc_fixed(&st->addr_mgr_state, start_vaddr, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_ADDR_MGR_ALLOC_FIXED);
    }

    return SYS_ERR_OK;
}

static bool paging_addr_is_mapped(struct paging_state *st, lvaddr_t vaddr)
{
    errval_t err;
    bool ret = true;

    uint64_t mask = 0x1FF;
    uint64_t l0_slot = (vaddr >> VMSAv8_64_L0_BITS) & mask;
    uint64_t l1_slot = (vaddr >> VMSAv8_64_L1_BLOCK_BITS) & mask;
    uint64_t l2_slot = (vaddr >> VMSAv8_64_L2_BLOCK_BITS) & mask;
    uint64_t l3_slot = (vaddr >> VMSAv8_64_BASE_PAGE_BITS) & mask;

    thread_mutex_lock(&st->paging_mutex);

    struct paging_node *node_l1;
    err = aos_avl_find(st->l0.child, l0_slot, (void **)&node_l1);
    if (err_is_fail(err)) {
        ret = false;
        goto out;
    }

    struct paging_node *node_l2;
    err = aos_avl_find(node_l1->child, l1_slot, (void **)&node_l2);
    if (err_is_fail(err)) {
        ret = false;
        goto out;
    }

    struct paging_node *node_l3;
    err = aos_avl_find(node_l2->child, l2_slot, (void **)&node_l3);
    if (err_is_fail(err)) {
        ret = false;
        goto out;
    }

    struct paging_node *node_l4;
    err = aos_avl_find(node_l3->child, l3_slot, (void **)&node_l4);
    if (err_is_fail(err)) {
        ret = false;
        goto out;
    }

out:
    thread_mutex_unlock(&st->paging_mutex);
    return ret;
}

static errval_t handle_pagefault(lvaddr_t addr)
{
    DEBUG_PAGING("handle_pagefault begin\n");
    DEBUG_PRINTF("PAGEFAULT at 0x%x\n", addr);
    errval_t err;

    // handle null pointer
    if (addr < BASE_PAGE_SIZE) {
        return LIB_ERR_PAGING_HANDLE_PAGEFAULT_NULL_POINTER;
    }

    struct paging_state *st = get_current_paging_state();

    thread_mutex_lock(&st->heap_mutex);

    // check if address was allocated in address manager
    if (!addr_mgr_is_addr_allocated(&st->addr_mgr_state, (genvaddr_t)addr)) {
        err = LIB_ERR_PAGING_HANDLE_PAGEFAULT_ADDR_NOT_FOUND;
        goto out;
    }

    // check if address was already mapped by another thread
    if (paging_addr_is_mapped(st, addr)) {
        err = SYS_ERR_OK;
        goto out;
    }

    // allocate frame for this address
    struct capref frame;
    size_t allocated_bytes;
    err = frame_alloc(&frame, BASE_PAGE_SIZE, &allocated_bytes);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_FRAME_ALLOC);
        goto out;
    }
    assert(allocated_bytes == BASE_PAGE_SIZE);

    lvaddr_t addr_aligned = ROUND_DOWN(addr, BASE_PAGE_SIZE);
    err = paging_map_fixed_attr(st, addr_aligned, frame, BASE_PAGE_SIZE,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_PAGING_MAP_FIXED_ATTR);
        goto out;
    }

    err = SYS_ERR_OK;
out:
    thread_mutex_unlock(&st->heap_mutex);
    DEBUG_PAGING("handle_pagefault end\n");
    return err;
}

static void exception_handler(enum exception_type type, int subtype, void *addr,
                              arch_registers_state_t *regs)
{
    errval_t err;

    DEBUG_EXCEPTION_HANDLER("Exception type %d subtype %d addr %p\n", type, subtype, addr);

    if (type == EXCEPT_PAGEFAULT) {
        err = handle_pagefault((lvaddr_t)addr);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "Couldn't handle pagefault at addr %p", addr);
        }
    } else {
        USER_PANIC("Couldn't handle exception type %d subtype %d addr %p\n", type,
                   subtype, addr);
    }
    return;
}

/**
 * \brief This function initializes the paging for this domain
 * It is called once before main.
 */
errval_t paging_init(void)
{
    debug_printf("paging_init\n");
    errval_t err;

    struct capref pdir;
    // TODO: How to get existing mapping capabilities??
    pdir.cnode = cnode_page;
    pdir.slot = 0;

    genvaddr_t addr = 1;
    // FIXME: How to make this exact
    genvaddr_t max_addr = 511 * (addr << VMSAv8_64_L0_BITS) - 1;
    // First L0 page table slot is already used, use second slot
    genvaddr_t start_addr = addr << VMSAv8_64_L0_BITS;

    err = paging_init_state(&current, start_addr, max_addr, pdir);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_INIT_STATE);
    }

    set_current_paging_state(&current);

    // give slabs a bit space to get paging up and running
    slab_grow(&current.slabs, paging_node_buf, sizeof(paging_node_buf));
    slab_grow(&current.avl_slabs, paging_avl_node_buf, sizeof(paging_avl_node_buf));

    // setup exception handler
    void *ex_stack_top = ex_stack_first + EX_STACK_SIZE;
    ex_stack_top = ex_stack_top - (lvaddr_t)ex_stack_top % STACK_ALIGNMENT;
    thread_set_exception_handler(exception_handler, NULL, ex_stack_first, ex_stack_top,
                                 NULL, NULL);

    return SYS_ERR_OK;
}

/**
 * \brief Initialize per-thread paging state
 */
void paging_init_onthread(struct thread *t)
{
    errval_t err;

    assert(BASE_PAGE_SIZE % STACK_ALIGNMENT == 0);

    struct capref cap;
    size_t retbytes;
    err = slot_alloc(&cap);
    assert(err_is_ok(err));

    err = frame_alloc(&cap, EX_STACK_SIZE, &retbytes);
    assert(err_is_ok(err));
    assert(retbytes == EX_STACK_SIZE);

    void *ex_stack;
    err = paging_map_frame(get_current_paging_state(), &ex_stack, EX_STACK_SIZE, cap,
                           NULL, NULL);
    assert(err_is_ok(err));

    t->exception_handler = exception_handler;
    t->exception_stack = ex_stack;
    t->exception_stack_top = ex_stack + EX_STACK_SIZE;
}

/**
 * \brief assumes that base has been reserved by/gotten from the addr_mgr
 */
static errval_t paging_region_init_base(struct paging_state *st, struct paging_region *pr,
                                        lvaddr_t base, size_t size, paging_flags_t flags)
{
    pr->base_addr = (lvaddr_t)base;
    pr->current_addr = pr->base_addr;
    pr->region_size = size;
    pr->flags = flags;

    assert(size == ROUND_UP(size, BASE_PAGE_SIZE));

    return SYS_ERR_OK;
}

/**
 * \brief Initialize a paging region in `pr`, such that it  starts
 * from base and contains size bytes.
 */
errval_t paging_region_init_fixed(struct paging_state *st, struct paging_region *pr,
                                  lvaddr_t base, size_t size, paging_flags_t flags)
{
    errval_t err;
    err = addr_mgr_alloc_fixed(&st->addr_mgr_state, base, size);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_ADDR_MGR_ALLOC_FIXED);
    }

    return paging_region_init_base(st, pr, base, size, flags);
}

/**
 * \brief Initialize a paging region in `pr`, such that it contains at least
 * size bytes and is aligned to a multiple of alignment.
 */
errval_t paging_region_init_aligned(struct paging_state *st, struct paging_region *pr,
                                    size_t size, size_t alignment, paging_flags_t flags)
{
    errval_t err;
    genvaddr_t base;
    err = addr_mgr_alloc(&st->addr_mgr_state, &base, size, alignment);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_ADDR_MGR_ALLOC);
    }

    return paging_region_init_base(st, pr, base, size, flags);
}

/**
 * \brief Initialize a paging region in `pr`, such that it contains at least
 * size bytes.
 *
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 */
errval_t paging_region_init(struct paging_state *st, struct paging_region *pr,
                            size_t size, paging_flags_t flags)
{
    return paging_region_init_aligned(st, pr, size, BASE_PAGE_SIZE, flags);
}


/**
 * \brief Allocates physical memory and maps it, so that pr->base_addr up to next_addr_end
 * is backed by memory.
 *
 * The paging_region currently works by only looking at the position of pr->current_addr
 * and using pr->base_addr and pr->region_size to determine which virtual addresses are
 * backed by memory.
 *
 * The code always maintains the invariant that at least the bytes from pr->base_addr to
 * pr->current_addr - 1 are backed by memory. Before increasing pr->current_addr it
 * is checked if the invariant would still hold and if not, BASE_PAGE_SIZE sized pages
 * are mapped until there is enough memory mapped for the current request.
 *
 * Assumptions:
 * - The paging_region.base_addr hase to be BASE_PAGE_SIZE aligned.
 * - paging_region virtual addresses are currently not freed anymore, so no holes exist
 *   in the region
 */
static errval_t paging_region_lazy_alloc(struct paging_state *st,
                                         struct paging_region *pr, lvaddr_t next_addr_end)
{
    size_t allocated = ROUND_UP(pr->current_addr - pr->base_addr, BASE_PAGE_SIZE);
    lvaddr_t allocated_end = pr->base_addr + allocated;
    if (next_addr_end <= allocated_end) {
        return SYS_ERR_OK;  // Already allocated enough RAM for request
    }

    // Allocate more RAM
    errval_t err;
    size_t bytes = ROUND_UP(next_addr_end - allocated_end, BASE_PAGE_SIZE);

    // Limit bytes if boundary of virtual address space is reached
    if (allocated_end + bytes > pr->base_addr + pr->region_size) {
        bytes = (pr->base_addr + pr->region_size) - allocated_end;
    }

    struct capref frame;
    size_t retbytes;
    err = frame_alloc(&frame, bytes, &retbytes);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_REGION_MAP_FAIL);
    }
    if (retbytes < bytes) {
        // Did not get enough memory
        return LIB_ERR_PAGING_REGION_MAP_FAIL;
    }

    err = paging_map_fixed_attr(st, allocated_end, frame, bytes, pr->flags);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_REGION_MAP_FAIL);
    }

    return SYS_ERR_OK;
}

/**
 * \brief return a pointer to a bit of the paging region `pr`.
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 */
errval_t paging_region_map(struct paging_region *pr, size_t req_size, void **retbuf,
                           size_t *ret_size)
{
    lvaddr_t end_addr = pr->base_addr + pr->region_size;
    ssize_t rem = end_addr - pr->current_addr;
    if (rem >= req_size) {
        // ok
        *retbuf = (void *)pr->current_addr;
        *ret_size = req_size;
    } else if (rem > 0) {
        *retbuf = (void *)pr->current_addr;
        *ret_size = rem;
        debug_printf("exhausted paging region, "
                     "expect badness on next allocation\n");
    } else {
        *retbuf = NULL;
        *ret_size = 0;
        return LIB_ERR_VSPACE_MMU_AWARE_NO_SPACE;
    }

    errval_t err = paging_region_lazy_alloc(get_current_paging_state(), pr,
                                            pr->current_addr + *ret_size);
    if (err_is_fail(err)) {
        *retbuf = NULL;
        *ret_size = 0;
        return err_push(err, LIB_ERR_PAGING_REGION_MAP_FAIL);
    }
    pr->current_addr += *ret_size;

    return SYS_ERR_OK;
}

/**
 * \brief free a bit of the paging region `pr`.
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 * NOTE: Implementing this function is optional.
 */
errval_t paging_region_unmap(struct paging_region *pr, lvaddr_t base, size_t bytes)
{
    // XXX: should free up some space in paging region, however need to track
    //      holes for non-trivial case
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * \brief Find a bit of free virtual address space that is large enough to accomodate a
 *        buffer of size 'bytes'.
 *
 * \param st A pointer to the paging state.
 * \param buf This parameter is used to return the free virtual address that was found.
 * \param bytes The number of bytes that need to be free (at the minimum) at the found
 *        virtual address.
 * \param alignment The address needs to be a multiple of 'alignment'.
 * \return Either SYS_ERR_OK if no error occured or an error
 *        indicating what went wrong otherwise.
 */
errval_t paging_alloc(struct paging_state *st, void **buf, size_t bytes, size_t alignment)
{
    genvaddr_t addr;
    errval_t err;

    if (bytes % BASE_PAGE_SIZE || alignment != BASE_PAGE_SIZE) {
        return LIB_ERR_PAGING_ALLOC_FAIL;
    }

    err = addr_mgr_alloc(&st->addr_mgr_state, &addr, bytes, alignment);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_ADDR_MGR_ALLOC);
    }
    *buf = (void *)addr;

    return SYS_ERR_OK;
}

/**
 * \brief Finds a free virtual address and maps a frame at that address
 *
 * \param st A pointer to the paging state.
 * \param buf This will parameter will be used to return the free virtual
 * address at which a new frame as been mapped.
 * \param bytes The number of bytes that need to be free (at the minimum)
 *        at the virtual address found.
 * \param frame A reference to the frame cap that is supposed to be mapped.
 * \param flags The flags that are to be set for the newly mapped region,
 *        see 'paging_flags_t' in paging_types.h .
 * \param arg1 Currently unused argument.
 * \param arg2 Currently unused argument.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_map_frame_attr(struct paging_state *st, void **buf, size_t bytes,
                               struct capref frame, int flags, void *arg1, void *arg2)
{
    errval_t err;

    genvaddr_t addr;
    err = addr_mgr_alloc(&st->addr_mgr_state, &addr, bytes, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_ADDR_MGR_ALLOC);
    }

    err = paging_map_fixed_attr(st, addr, frame, bytes, flags);
    if (err_is_fail(err)) {
        return err;
    }

    *buf = (void *)addr;

    return SYS_ERR_OK;
}

static errval_t paging_map_some(struct paging_node **ret, struct paging_node *our_level,
                                struct paging_node *parent, int level, int slot,
                                struct paging_state *st, struct capref *frame,
                                size_t offset, int flags)
{
    DEBUG_PAGING("map_some begin level: 0x%" PRIx64 " slot: 0x%" PRIx64 "\n",
                 (uint64_t)level, (uint64_t)slot);

    errval_t err = SYS_ERR_OK;

    struct capref lower_pt_cpr;
    struct capref higher_lower_map;

    int alloced = 0;

    struct paging_node *node;
    err = aos_avl_find(our_level->child, slot, (void **)&node);
    if (err_is_fail(err) && err_no(err) == LIB_ERR_AVL_FIND_NOT_FOUND) {
        if (level != 4) {
            enum objtype type = ObjType_VNode_AARCH64_l1;
            switch (level) {
            case (1):
                type = ObjType_VNode_AARCH64_l1;
                break;
            case (2):
                type = ObjType_VNode_AARCH64_l2;
                break;
            case (3):
                type = ObjType_VNode_AARCH64_l3;
                break;
            default:
                return LIB_ERR_PAGING_LEVEL;
            }

            err = slot_alloc(&lower_pt_cpr);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_SLOT_ALLOC);
            }

            struct capref ram;

            err = ram_alloc_aligned(&ram, vnode_objsize(type), vnode_objsize(type));
            if (err_no(err) == LIB_ERR_RAM_ALLOC_WRONG_SIZE
                && type != ObjType_VNode_ARM_l1) {
                // can only get 4kB pages, cannot create ARM_l1, and waste 3kB for
                // ARM_l2
                err = ram_alloc(&ram, BASE_PAGE_SIZE);
            }
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_RAM_ALLOC);
            }

            assert(type_is_vnode(type));
            err = cap_retype(lower_pt_cpr, ram, 0, type, vnode_objsize(type), 1);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_CAP_RETYPE);
            }

            err = cap_destroy(ram);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_CAP_DESTROY);
            }
        } else {
            lower_pt_cpr = *frame;
        }

        err = slot_alloc(&higher_lower_map);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }

        alloced = 1;
    }

    thread_mutex_lock(&st->paging_mutex);

    err = aos_avl_find(our_level->child, slot, (void **)&node);
    if (err_is_fail(err) && err_no(err) == LIB_ERR_AVL_FIND_NOT_FOUND) {
        assert(alloced);

        err = vnode_map(our_level->table, lower_pt_cpr, slot, flags, offset, 1,
                        higher_lower_map);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_VNODE_MAP);
            goto out;
        }

        node = slab_alloc(&st->slabs);
        assert(node != NULL);

        node->mapping = higher_lower_map;
        node->table = lower_pt_cpr;
        node->parent = parent;
        node->child = NULL;

        struct aos_avl_node *avl_node = slab_alloc(&st->avl_slabs);
        assert(avl_node != NULL);

        err = aos_avl_insert(&our_level->child, slot, (void *)node, avl_node);
        assert(err_is_ok(err));

        node->level = level;
        node->slot = slot;
    } else {
        if (alloced) {
            if (level != 4) {
                err = cap_destroy(lower_pt_cpr);
                if (err_is_fail(err)) {
                    err = err_push(err, LIB_ERR_CAP_DESTROY);
                    goto out;
                }
            }

            err = slot_free(higher_lower_map);
            if (err_is_fail(err)) {
                err = err_push(err, LIB_ERR_SLOT_FREE);
                goto out;
            }
        }

        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_AVL_FIND);
            goto out;
        } else if (level == 4) {
            // We do not expect there to be an existing mapping for the frame cap we
            // want to map, so this is an error
            err = LIB_ERR_PAGING_MAPPING_EXISTS;
            goto out;
        }
    }

    *ret = node;

    DEBUG_PAGING("map_some end\n");

out:
    thread_mutex_unlock(&st->paging_mutex);
    return err;
}

static errval_t paging_map_fixed_attr_one(struct paging_state *st, lvaddr_t vaddr,
                                          struct capref frame, size_t bytes,
                                          size_t offset, int flags)
{
    DEBUG_PAGING("paging_map_fixed_attr_one begin\n");
    errval_t err;

    // Only one page at the time
    assert(bytes <= BASE_PAGE_SIZE);

    // First 9 bits
    uint64_t mask = 0x1FF;

    uint64_t l0_slot = (vaddr >> VMSAv8_64_L0_BITS) & mask;
    uint64_t l1_slot = (vaddr >> VMSAv8_64_L1_BLOCK_BITS) & mask;
    uint64_t l2_slot = (vaddr >> VMSAv8_64_L2_BLOCK_BITS) & mask;
    uint64_t l3_slot = (vaddr >> VMSAv8_64_BASE_PAGE_BITS) & mask;


    DEBUG_PAGING_FINE("map l0: %" PRIu64 " l1: %" PRIu64 " l2: %" PRIu64 " l3: "
                      "%" PRIu64 ""
                      " addr: 0x%" PRIx64 "\n",
                      l0_slot, l1_slot, l2_slot, l3_slot, vaddr);

    struct paging_node *node_l1;
    err = paging_map_some(&node_l1, &st->l0, NULL, 1, l0_slot, st, NULL, 0,
                          VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return err;
    }
    assert(node_l1 != NULL);

    struct paging_node *node_l2;
    err = paging_map_some(&node_l2, node_l1, node_l1, 2, l1_slot, st, NULL, 0,
                          VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return err;
    }
    assert(node_l2 != NULL);

    struct paging_node *node_l3;
    err = paging_map_some(&node_l3, node_l2, node_l2, 3, l2_slot, st, NULL, 0,
                          VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return err;
    }
    assert(node_l3 != NULL);

    struct paging_node *node_l4;
    err = paging_map_some(&node_l4, node_l3, node_l3, 4, l3_slot, st, &frame, offset,
                          flags);
    if (err_is_fail(err)) {
        return err;
    }
    assert(node_l4 != NULL);
    assert(node_l4->child == NULL);

    DEBUG_PAGING("paging_map_fixed_attr_one middle\n");

    if (slab_freecount(&st->slabs) < 64 && !st->slab_refilling) {
        st->slab_refilling = 1;
        err = slab_default_refill(&st->slabs);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_SLAB_REFILL);
        }
        st->slab_refilling = 0;
    }

    if (slab_freecount(&st->avl_slabs) < 64 && !st->avl_slab_refilling) {
        st->avl_slab_refilling = 1;
        err = slab_default_refill(&st->avl_slabs);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_SLAB_REFILL);
        }
        st->avl_slab_refilling = 0;
    }

    // TODO: Also refill slot_alloc, as slabs might get refilled through
    // mm_alloc whenallocating more slots
    // Assumption: looking at two_level_alloc, slot_allocator underlying
    // slot_alloc seems already designed to not trigger a recursion
    // Search for two_level_allo, or generally look under lib/aos/slot_alloc

    DEBUG_PAGING("paging_map_fixed_attr_one end\n");

    return SYS_ERR_OK;
}

errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags)
{
    DEBUG_PAGING("paging_map_fixed_attr begin\n");
    DEBUG_PAGING_FINE("paging_map_fixed_attr addr: 0x%" PRIx64 " size: 0x%" PRIx64 "\n",
                      vaddr, bytes);

    errval_t err;

    size_t offset = 0;
    while (bytes >= BASE_PAGE_SIZE) {
        err = paging_map_fixed_attr_one(st, vaddr, frame, BASE_PAGE_SIZE, offset, flags);
        if (err_is_fail(err))
            return err;

        vaddr += BASE_PAGE_SIZE;
        bytes -= BASE_PAGE_SIZE;
        offset += BASE_PAGE_SIZE;
    }

    if (bytes > 0) {
        err = paging_map_fixed_attr_one(st, vaddr, frame, bytes, offset, flags);
        if (err_is_fail(err))
            return err;
    }

    DEBUG_PAGING("paging_map_fixed_attr end\n");

    return SYS_ERR_OK;
}

static errval_t paging_delete_level(struct paging_state *st, struct paging_node *node)
{
    errval_t err;

    thread_mutex_lock(&st->paging_mutex);

    if (node->level != 4) {
        err = cap_destroy(node->table);
        assert(err_is_ok(err));
    }

    // FIXME Sometimes mapping cap is missing so we cannot unmap/destroy
    struct capability ret_cap;
    err = cap_direct_identify(node->mapping, &ret_cap);

    if (err_is_ok(err)) {
        // a mapping exists unmap and destroy it
        struct capref page_table;
        if (node->parent != NULL) {
            page_table = node->parent->table;
        } else {
            page_table = st->l0.table;
        }

        err = vnode_unmap(page_table, node->mapping);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_VNODE_UNMAP);
        }

        err = cap_destroy(node->mapping);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_DESTROY);
        }
    } else if (err_no(err) == SYS_ERR_CAP_NOT_FOUND) {
        // somehow the mapping is missing...
        // we just proceed for now
        DEBUG_PRINTF("paging_delete_level(): mapping cap not found (please fix me)\n");
    } else {
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }

    struct paging_node *parent = node->parent;
    struct aos_avl_node *avl_node;
    err = aos_avl_remove(&node->parent->child, node->slot, (void **)&node, &avl_node);
    assert(err_is_ok(err));
    slab_free(&st->avl_slabs, avl_node);
    slab_free(&st->slabs, node);

    thread_mutex_unlock(&st->paging_mutex);

    if (parent->child == NULL) {
        if (node->level != 0) {
            return paging_delete_level(st, parent);
        } else {
            return SYS_ERR_OK;
        }
    } else {
        return SYS_ERR_OK;
    }
}

static errval_t paging_unmap_one(struct paging_state *st, lvaddr_t vaddr,
                                 struct capref frame, size_t bytes)
{
    assert(bytes <= BASE_PAGE_SIZE);
    errval_t err;

    // First 9 bits
    uint64_t mask = 0x1FF;

    uint64_t l0_slot = (vaddr >> VMSAv8_64_L0_BITS) & mask;
    uint64_t l1_slot = (vaddr >> VMSAv8_64_L1_BLOCK_BITS) & mask;
    uint64_t l2_slot = (vaddr >> VMSAv8_64_L2_BLOCK_BITS) & mask;
    uint64_t l3_slot = (vaddr >> VMSAv8_64_BASE_PAGE_BITS) & mask;
    DEBUG_PAGING_FINE("unmap l0: %" PRIu64 " l1: %" PRIu64 " l2: %" PRIu64 " l3: "
                      "%" PRIu64 " addr: 0x%" PRIx64 "\n",
                      l0_slot, l1_slot, l2_slot, l3_slot);

    struct paging_node *node_l1;
    err = aos_avl_find(st->l0.child, l0_slot, (void **)&node_l1);
    assert(err_is_ok(err));

    struct paging_node *node_l2;
    err = aos_avl_find(node_l1->child, l1_slot, (void **)&node_l2);
    assert(err_is_ok(err));

    struct paging_node *node_l3;
    err = aos_avl_find(node_l2->child, l2_slot, (void **)&node_l3);
    assert(err_is_ok(err));

    struct paging_node *node_l4;
    err = aos_avl_find(node_l3->child, l3_slot, (void **)&node_l4);
    assert(err_is_ok(err));

    return paging_delete_level(st, node_l4);
}

/**
 * \brief unmap a user provided frame, and return the VA of the mapped
 *        frame in `buf`.
 * NOTE: Implementing this function is optional.
 */
errval_t paging_unmap(struct paging_state *st, lvaddr_t vaddr, struct capref frame,
                      size_t bytes)
{
    errval_t err;

    // FIXME: Every unmap should have a corresponding reservation
    err = addr_mgr_free(&st->addr_mgr_state, vaddr, bytes);
    if (err_is_fail(err) && err_no(err) != LIB_ERR_ADDR_MGR_NOT_FOUND) {
        return err_push(err, LIB_ERR_ADDR_MGR_FREE);
    }

    while (bytes >= BASE_PAGE_SIZE) {
        err = paging_unmap_one(st, vaddr, frame, BASE_PAGE_SIZE);
        if (err_is_fail(err))
            return err;

        vaddr += BASE_PAGE_SIZE;
        bytes -= BASE_PAGE_SIZE;
    }

    if (bytes > 0) {
        err = paging_unmap_one(st, vaddr, frame, bytes);
        if (err_is_fail(err))
            return err;
    }

    return SYS_ERR_OK;
}

