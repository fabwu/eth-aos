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
#include "threads_priv.h"

#include <stdio.h>
#include <string.h>

// TODO: switch from slot_alloc to the slot alloc given by paging_init_state

static struct paging_state current;

static char paging_node_buf[sizeof(struct paging_node) * 64];
static char addr_mgr_node_buf[sizeof(struct addr_mgr_node) * 64];

static void addr_mgr_add_node(struct addr_mgr_state *st, struct addr_mgr_node *prev,
                              struct addr_mgr_node *new)
{
    if (prev == NULL) {
        if (st->head != NULL) {
            new->next = st->head;
            st->head->prev = new;
        } else {
            st->tail = new;
            new->next = NULL;
        }
        st->head = new;
        new->prev = NULL;
    } else {
        new->prev = prev;
        if (prev->next != NULL) {
            new->next = prev->next;
            prev->next->prev = new;
        } else {
            new->next = NULL;
            st->tail = new;
        }
        prev->next = new;
    }
}

/**
 * \brief allocs a range of size from the addr mgr at some base addr, returns
 * the base addr
 */
static errval_t addr_mgr_alloc(struct addr_mgr_state *st, genvaddr_t *ret, gensize_t size,
                               gensize_t alignment)
{
#ifdef DEBUG_ADDR_MGR
    debug_printf("addr_mgr_alloc begin\n");
#endif
    // TODO: Handle alignment
    assert(alignment == BASE_PAGE_SIZE);
    if (size % BASE_PAGE_SIZE) {
        return LIB_ERR_ADDR_MGR_ALLOC;
    }
    assert(size % BASE_PAGE_SIZE == 0);
    // Just go at the end of linked list, we have infinite space (Just check we
    // did not run out of infinite space)
    struct addr_mgr_node *prev = NULL;
    genvaddr_t addr;

    // Alloc here, potentially free later on, so that we get our address, we are
    // reentrant
    struct addr_mgr_node *new = (struct addr_mgr_node *)slab_alloc(&st->slabs);
    if (new == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    if (st->tail != NULL) {
        prev = st->tail;
        addr = st->tail->base + st->tail->size;
    } else {
        // addr space starts at zero
        addr = 0;
    }
    assert(addr % BASE_PAGE_SIZE == 0);

    if ((addr + size - 1) <= st->max_addr) {
        addr_mgr_add_node(st, prev, new);

        new->base = addr;
        new->size = size;

        *ret = addr;

        // TODO: Hope we do not run out of slabs in between
        if (slab_freecount(&st->slabs) < 32 && !st->is_slabs_refilling) {
            st->is_slabs_refilling = 1;
            slab_default_refill(&st->slabs);
            st->is_slabs_refilling = 0;
        }

#ifdef DEBUG_ADDR_MGR
        debug_printf("addr_mgr_alloc end\n");
#endif
        return SYS_ERR_OK;
    } else {
        // Didn't get an address, free again
        slab_free(&st->slabs, new);

        return LIB_ERR_ADDR_MGR_FULL;
    }
}

static struct addr_mgr_node *addr_mgr_find_prev(struct addr_mgr_state *st, genvaddr_t base)
{
    struct addr_mgr_node *prev = st->head;
    if (prev != NULL) {
        while (prev->next != NULL && prev->next->base < base) {
            prev = prev->next;
        }
    }
    assert(prev == NULL
           || (prev->base <= base && (prev->next == NULL || base <= prev->next->base)));

    return prev;
}

/**
 * \brief allocs a range from the addr mgr at given base addr
 */
static errval_t addr_mgr_alloc_fixed(struct addr_mgr_state *st, genvaddr_t base,
                                     gensize_t size)
{
    // TODO: Handle alignment
    assert(base % BASE_PAGE_SIZE == 0);
    assert(size % BASE_PAGE_SIZE == 0);
    // Just go at the end of linked list, we have infinite space (Just check we
    // Find first node whose next is inexistent or has a larger or equal base
    // than the desired base
    struct addr_mgr_node *prev = addr_mgr_find_prev(st, base);

    // Make reentrant, only modify linked list when we are sure we can do
    // that without calling external dependencies
    struct addr_mgr_node *new = (struct addr_mgr_node *)slab_alloc(&st->slabs);
    if (new == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    if (prev == NULL
        || ((prev->base + prev->size - 1) < base
            && (prev->next == NULL || (base + size - 1) < prev->next->base))) {
        addr_mgr_add_node(st, prev, new);

        new->base = base;
        new->size = size;

        // TODO: Hope we do not run out of slabs in between
        if (slab_freecount(&st->slabs) < 32 && !st->is_slabs_refilling) {
            st->is_slabs_refilling = 1;
            slab_default_refill(&st->slabs);
            st->is_slabs_refilling = 0;
        }

        return SYS_ERR_OK;
    } else {
        // Didn't find free space, free again
        slab_free(&st->slabs, new);

        return LIB_ERR_ADDR_MGR_FULL;
    }
}

// TODO: Size really needed?
// JP:   No, but we can use the size to double check if everything was done
//       correctly and throw an error otherwise.
static errval_t addr_mgr_free(struct addr_mgr_state *st, genvaddr_t base, gensize_t size)
{
    struct addr_mgr_node *prev = addr_mgr_find_prev(st, base);

    if (prev == NULL) {
        return SYS_ERR_OK;
    } else if (prev->base == base && prev->size == size) {
        // TODO: Hope this is correct...
        if (prev->prev == NULL) {
            st->head = prev->next;
        } else {
            prev->prev->next = prev->next;
        }
        if (prev->next != NULL) {
            prev->next->prev = prev->prev;
        } else {
            st->tail = prev->prev;
        }
        slab_free(&st->slabs, (void *)prev);

        return SYS_ERR_OK;
    } else {
        return LIB_ERR_ADDR_MGR_NOT_FOUND;
    }
}

/**
 * \brief Helper function that allocates a slot and
 *        creates a aarch64 page table capability for a certain level
 */
static errval_t pt_alloc(struct paging_state *st, enum objtype type, struct capref *ret)
{
    errval_t err;
    err = slot_alloc(ret);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        return err;
    }
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        debug_printf("vnode_create failed: %s\n", err_getstring(err));
        return err;
    }
    return SYS_ERR_OK;
}

__attribute__((unused)) static errval_t pt_alloc_l1(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l1, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l2(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l2, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l3(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l3, ret);
}


/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging
 *        state of the calling process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L1 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr,
                           lvaddr_t max_vaddr, struct capref pdir,
                           struct slot_allocator *ca, struct slab_allocator paging_slabs,
                           struct slab_allocator addr_mgr_slabs)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    st->l0_pt = pdir;

    st->addr_mgr_state.head = NULL;
    st->addr_mgr_state.tail = NULL;
    st->addr_mgr_state.is_slabs_refilling = 0;
    // FIXME: Make this exact
    st->addr_mgr_state.max_addr = max_vaddr;

    st->slabs = paging_slabs;
    st->addr_mgr_state.slabs = addr_mgr_slabs;

    errval_t err = addr_mgr_alloc_fixed(&st->addr_mgr_state, 0, start_vaddr);
    if (err_is_fail(err)) {
        return LIB_ERR_ADDR_MGR_ALLOC_FIXED;
    }

    return SYS_ERR_OK;
}

/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging state
 *        of a child process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L1 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   lvaddr_t max_vaddr, struct capref pdir,
                                   struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    struct slab_allocator paging_slabs;
    slab_init(&paging_slabs, sizeof(struct paging_node), NULL);
    slab_default_refill(&paging_slabs);

    struct slab_allocator addr_mgr_slabs;
    slab_init(&addr_mgr_slabs, sizeof(struct addr_mgr_node), NULL);
    slab_default_refill(&addr_mgr_slabs);
    return paging_init_state(st, start_vaddr, max_vaddr, pdir, ca, paging_slabs,
                             addr_mgr_slabs);
}

/**
 * \brief This function initializes the paging for this domain
 * It is called once before main.
 */
errval_t paging_init(void)
{
    debug_printf("paging_init\n");
    // TODO (M2): Call paging_init_state for &current
    // TODO (M4): initialize self-paging handler
    // TIP: use thread_set_exception_handler() to setup a page fault handler
    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.
    // TIP: it might be a good idea to call paging_init_state() from here to
    // avoid code duplication.

    struct slab_allocator paging_slabs;
    slab_init(&paging_slabs, sizeof(struct paging_node), NULL);
    slab_grow(&paging_slabs, paging_node_buf, sizeof(paging_node_buf));

    struct slab_allocator addr_mgr_slabs;
    slab_init(&addr_mgr_slabs, sizeof(struct addr_mgr_node), NULL);
    slab_grow(&addr_mgr_slabs, addr_mgr_node_buf, sizeof(addr_mgr_node_buf));

    struct capref pdir;
    // TODO: How to get existing mapping capabilities??
    pdir.cnode = cnode_page;
    pdir.slot = 0;

    genvaddr_t addr = 1;
    // FIXME: How to make this exact
    genvaddr_t max_addr = 511 * (addr << VMSAv8_64_L0_BITS) - 1;
    // First L0 page table slot is already used, use second slot
    genvaddr_t start_addr = addr << VMSAv8_64_L0_BITS;

    paging_init_state(&current, start_addr, max_addr, pdir, get_default_slot_allocator(),
                      paging_slabs, addr_mgr_slabs);

    set_current_paging_state(&current);
    return SYS_ERR_OK;
}


/**
 * \brief Initialize per-thread paging state
 */
void paging_init_onthread(struct thread *t)
{
    // TODO (M4): setup exception handler for thread `t'.
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
    // TODO: Reserve space at addr_mgr
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
 * TODO(M2): As an OPTIONAL part of M2 implement this function
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
 * TODO(M2): Implement this function.
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
    errval_t err;
    struct capref cap;
    size_t retbytes;
    // TODO: Support alignment
    assert(alignment <= BASE_PAGE_SIZE);
    err = frame_alloc(&cap, bytes, &retbytes);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }
    assert(retbytes == bytes);

    err = paging_map_frame(st, buf, bytes, cap, NULL, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    return SYS_ERR_OK;
}

/**
 * TODO(M2): Implement this function.
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
    // TODO(M2): Implement me
    // - Call paging_alloc to get a free virtual address region of the requested size
    // - Map the user provided frame at the free virtual address
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

errval_t slab_refill_no_pagefault(struct slab_allocator *slabs, struct capref frame,
                                  size_t minbytes)
{
    // Refill the two-level slot allocator without causing a page-fault
    return SYS_ERR_OK;
}

static struct paging_node *find_some(struct paging_node *head, int slot)
{
    while (head != NULL && head->slot != slot) {
        head = head->next;
    }

    return head;
}

static errval_t map_some(struct paging_node **ret, struct paging_node **head,
                         struct paging_node *parent, int level, struct capref pt_cpr,
                         int slot, struct paging_state *st, struct capref *frame,
                         size_t offset, int flags)
{
#ifdef DEBUG_PAGING
    debug_printf("map_some begin\n");
#endif
    errval_t err = 0;
    struct paging_node *node = find_some(*head, slot);
    if (node == NULL) {
        struct capref lower_pt_cpr;
        struct capref higher_lower_map;

        switch (level) {
        case (1):
            err = pt_alloc_l1(st, &lower_pt_cpr);
            break;
        case (2):
            err = pt_alloc_l2(st, &lower_pt_cpr);
            break;
        case (3):
            err = pt_alloc_l3(st, &lower_pt_cpr);
            break;
        case (4):
            lower_pt_cpr = *frame;
            break;
        default:
            return LIB_ERR_PAGING_LEVEL;
        }
        err = slot_alloc(&higher_lower_map);
        if (err_is_fail(err)) {
            return err;
        }

        // Does Read/Write make sense for a page table?
        err = vnode_map(pt_cpr, lower_pt_cpr, slot, flags, offset, 1, higher_lower_map);
        if (err_is_fail(err)) {
            return err;
        }

        // FIXME: This is not necessarily reentrant
        node = slab_alloc(&st->slabs);
        assert(node != NULL);

        node->mapping = higher_lower_map;
        node->table = lower_pt_cpr;
        node->parent = parent;
        node->child = NULL;
        if (*head != NULL) {
            (*head)->previous = node;
            node->next = *head;
        } else {
            node->next = NULL;
        }
        *head = node;
        node->previous = NULL;
        node->level = level;
        node->slot = slot;
    }

    *ret = node;

#ifdef DEBUG_PAGING
    debug_printf("map_some end\n");
#endif

    return SYS_ERR_OK;
}

static errval_t paging_map_fixed_attr_one(struct paging_state *st, lvaddr_t vaddr,
                                          struct capref frame, size_t bytes,
                                          size_t offset, int flags)
{
#ifdef DEBUG_PAGING
    debug_printf("paging_map_fixed_attr_one begin\n");
#endif
    /**
     * \brief map a user provided frame at user provided VA.
     * TODO(M1): Map a frame assuming all mappings will fit into one last level pt
     * TODO(M2): General case
     */

    errval_t err;

    // Only one page at the time
    // TODO: Allow for larger frames
    assert(bytes <= BASE_PAGE_SIZE);

    // First 9 bits
    uint64_t mask = 0x1FF;

    uint64_t l0_slot = (vaddr >> VMSAv8_64_L0_BITS) & mask;
    uint64_t l1_slot = (vaddr >> VMSAv8_64_L1_BLOCK_BITS) & mask;
    uint64_t l2_slot = (vaddr >> VMSAv8_64_L2_BLOCK_BITS) & mask;
    uint64_t l3_slot = (vaddr >> VMSAv8_64_BASE_PAGE_BITS) & mask;
#ifdef DEBUG_PAGING_FINE
    debug_printf("map l0: %" PRIu64 " l1: %" PRIu64 " l2: %" PRIu64 " l3: %" PRIu64 ""
                 " addr: 0x%" PRIx64 "\n",
                 l0_slot, l1_slot, l2_slot, l3_slot, vaddr);
#endif

    struct paging_node *node_l1;
    err = map_some(&node_l1, &st->l0, NULL, 1, st->l0_pt, l0_slot, st, NULL, 0,
                   VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return err;
    }
    assert(node_l1 != NULL);

    struct paging_node *node_l2;
    err = map_some(&node_l2, &node_l1->child, node_l1, 2, node_l1->table, l1_slot, st,
                   NULL, 0, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return err;
    }
    assert(node_l2 != NULL);

    struct paging_node *node_l3;
    err = map_some(&node_l3, &node_l2->child, node_l2, 3, node_l2->table, l2_slot, st,
                   NULL, 0, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return err;
    }
    assert(node_l3 != NULL);

    struct paging_node *node_l4;
    err = map_some(&node_l4, &node_l3->child, node_l3, 4, node_l3->table, l3_slot, st,
                   &frame, offset, flags);
    if (err_is_fail(err)) {
        return err;
    }
    assert(node_l4 != NULL);
    // Virtual address is only allowed to be mapped once!
    assert(node_l3->child == node_l4);
    assert(node_l4->child == NULL);

#ifdef DEBUG_PAGING
    debug_printf("paging_map_fixed_attr_one middle\n");
#endif

    // TODO: Needs to be member, my have multiple state
    static size_t is_refilling = 0;
    // TODO: Hope we do not run out of slabs in between
    if (slab_freecount(&st->slabs) < 32 && !is_refilling) {
        is_refilling = 1;
        slab_default_refill(&st->slabs);
        is_refilling = 0;
    }

    // TODO: Also refill slot_alloc, as slabs might get refilled through
    // mm_alloc whenallocating more slots
    // Assumption: looking at two_level_alloc, slot_allocator underlying
    // slot_alloc seems already designed to not trigger a recursion
    // Search for two_level_allo, or generally look under lib/aos/slot_alloc
#ifdef DEBUG_PAGING
    debug_printf("paging_map_fixed_attr_one end\n");
#endif

    return SYS_ERR_OK;
}

errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags)
{
#ifdef DEBUG_PAGING
    debug_printf("paging_map_fixed_attr begin\n");
#endif
    // TODO: Inefficient, but correct
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

#ifdef DEBUG_PAGING
    debug_printf("paging_map_fixed_attr end\n");
#endif

    return SYS_ERR_OK;
}

static errval_t paging_unmap_one(struct paging_state *st, lvaddr_t vaddr,
                                 struct capref frame, size_t bytes)
{
    assert(bytes <= BASE_PAGE_SIZE);
    test();

    // First 9 bits
    uint64_t mask = 0x1FF;

    uint64_t l0_slot = (vaddr >> VMSAv8_64_L0_BITS) & mask;
    uint64_t l1_slot = (vaddr >> VMSAv8_64_L1_BLOCK_BITS) & mask;
    uint64_t l2_slot = (vaddr >> VMSAv8_64_L2_BLOCK_BITS) & mask;
    uint64_t l3_slot = (vaddr >> VMSAv8_64_BASE_PAGE_BITS) & mask;
#ifdef DEBUG_PAGING_FINE
    debug_printf("unmap l0: %" PRIu64 " l1: %" PRIu64 " l2: %" PRIu64 " l3: "
                 "%" PRIu64 " addr: 0x%" PRIx64 "\n",
                 l0_slot, l1_slot, l2_slot, l3_slot);
#endif

    struct paging_node *node_l1 = find_some(st->l0, l0_slot);
    assert(node_l1 != NULL);

    struct paging_node *node_l2 = find_some(node_l1->child, l1_slot);
    assert(node_l2 != NULL);

    struct paging_node *node_l3 = find_some(node_l2->child, l2_slot);
    assert(node_l3 != NULL);

    struct paging_node *node_l4 = find_some(node_l3->child, l3_slot);
    assert(node_l4 != NULL);

    // TODO: Refactor
    // Delete mapping
    cap_destroy(node_l4->mapping);
    // Was the only child of L3
    if (node_l4->previous == NULL && node_l4->next == NULL) {
        // Delete L3 mapping
        cap_destroy(node_l3->mapping);
        // Delete L3 pt
        cap_destroy(node_l3->table);

        // Was the only child of L2
        if (node_l3->previous == NULL && node_l3->next == NULL) {
            // Delete L2 mapping
            cap_destroy(node_l2->mapping);
            // Delete L2 pt
            cap_destroy(node_l2->table);

            if (node_l2->previous == NULL && node_l2->next == NULL) {
                // Delete L1 mapping
                cap_destroy(node_l1->mapping);
                // Delete L1 table
                cap_destroy(node_l1->table);

                // Won't ever delete L0, or we are toast

                slab_free(&st->slabs, node_l1);

                st->l0->child = NULL;
            } else {
                if (node_l2->previous != NULL) {
                    if (node_l2->next != NULL) {
                        node_l2->next->previous = node_l2->previous;
                    }
                    node_l2->previous->next = node_l2->next;
                } else {
                    node_l1->child = node_l2->next;
                    if (node_l2->next != NULL) {
                        node_l2->next->previous = NULL;
                    }
                }
            }
            slab_free(&st->slabs, node_l2);
        } else {
            if (node_l3->previous != NULL) {
                if (node_l3->next != NULL) {
                    node_l3->next->previous = node_l3->previous;
                }
                node_l3->previous->next = node_l3->next;
            } else {
                node_l2->child = node_l3->next;
                if (node_l3->next != NULL) {
                    node_l3->next->previous = NULL;
                }
            }
        }

        slab_free(&st->slabs, node_l3);
    } else {
        if (node_l4->previous != NULL) {
            if (node_l4->next != NULL) {
                node_l4->next->previous = node_l4->previous;
            }
            node_l4->previous->next = node_l4->next;
        } else {
            node_l3->child = node_l4->next;
            if (node_l4->next != NULL) {
                node_l4->next->previous = NULL;
            }
        }
    }

    slab_free(&st->slabs, node_l4);

    return SYS_ERR_OK;
}

/**
 * \brief unmap a user provided frame, and return the VA of the mapped
 *        frame in `buf`.
 * NOTE: Implementing this function is optional.
 */
// errval_t paging_unmap(struct paging_state *st, const void *region)
// {
errval_t paging_unmap(struct paging_state *st, lvaddr_t vaddr, struct capref frame,
                      size_t bytes)
{
    // TODO: Inefficient, but correct
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

static errval_t paging_cap_copy(struct cnoderef l2_cnode_ref, size_t *slot,
                                size_t num_slots, struct capref src)
{
    errval_t err;
    if (*slot < num_slots) {
        struct capref cap;
        cap.cnode = l2_cnode_ref;
        cap.slot = *slot;
        err = cap_copy(cap, src);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_COPY);
        }
        ++*slot;

        return SYS_ERR_OK;
    } else {
        return LIB_ERR_PAGING_COPY_CAPABILITIES_TOO_MANY;
    }
}

/**
 * \brief copies capabilites into given cnode
 */
errval_t paging_copy_capabilities(struct paging_state *st, struct cnoderef l2_cnode_ref,
                                  size_t start_slot, size_t num_slots)
{
    if (st->l0 != NULL) {
        errval_t err;
        struct paging_node *l1_pt = st->l0->child;
        while (l1_pt != NULL) {
            struct paging_node *l2_pt = l1_pt->child;
            while (l2_pt != NULL) {
                struct paging_node *l3_pt = l2_pt->child;
                while (l3_pt != NULL) {
                    err = paging_cap_copy(l2_cnode_ref, &start_slot, num_slots,
                                          l3_pt->table);
                    if (err_is_fail(err)) {
                        return err;
                    }
                    l3_pt = l3_pt->next;
                }
                err = paging_cap_copy(l2_cnode_ref, &start_slot, num_slots, l2_pt->table);
                if (err_is_fail(err)) {
                    return err;
                }
                l2_pt = l2_pt->next;
            }
            err = paging_cap_copy(l2_cnode_ref, &start_slot, num_slots, l1_pt->table);
            if (err_is_fail(err)) {
                return err;
            }
            l1_pt = l1_pt->next;
        }
    }

    return SYS_ERR_OK;
}
