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

static struct paging_state current;

static char paging_node_buf[sizeof(struct paging_node) * 64];

/**
 * \brief Helper function that allocates a slot and
 *        creates a aarch64 page table capability for a certain level
 */
static errval_t pt_alloc(struct paging_state * st, enum objtype type, 
                         struct capref *ret) 
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

__attribute__((unused)) static errval_t pt_alloc_l1(struct paging_state * st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l1, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l2(struct paging_state * st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l2, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l3(struct paging_state * st, struct capref *ret) 
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
                           struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    return LIB_ERR_NOT_IMPLEMENTED;
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
                           struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    return SYS_ERR_OK;
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
    slab_init(&current.slabs, sizeof(struct paging_node), NULL);
    // Paging_node_buf should be zero initialized?
    slab_grow(&current.slabs, paging_node_buf, sizeof(paging_node_buf));

    // TODO: How to get existing mapping capabilities??
    current.l0_pt.cnode = cnode_page;
    current.l0_pt.slot = 0;

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
 * \brief Initialize a paging region in `pr`, such that it  starts
 * from base and contains size bytes.
 */
errval_t paging_region_init_fixed(struct paging_state *st, struct paging_region *pr,
                                  lvaddr_t base, size_t size, paging_flags_t flags)
{
    pr->base_addr = (lvaddr_t)base;
    pr->current_addr = pr->base_addr;
    pr->region_size = size;
    pr->flags = flags;

    //TODO(M2): Add the region to a datastructure and ensure paging_alloc
    //will return non-overlapping regions.
    return SYS_ERR_OK;
}

/**
 * \brief Initialize a paging region in `pr`, such that it contains at least
 * size bytes and is aligned to a multiple of alignment.
 */
errval_t paging_region_init_aligned(struct paging_state *st, struct paging_region *pr,
                                    size_t size, size_t alignment, paging_flags_t flags)
{
    void *base;
    errval_t err = paging_alloc(st, &base, size, alignment);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_region_init: paging_alloc failed\n");
        return err_push(err, LIB_ERR_VSPACE_MMU_AWARE_INIT);
    }

    return paging_region_init_fixed(st, pr, (lvaddr_t)base, size, flags);
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
 * \brief return a pointer to a bit of the paging region `pr`.
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 */
errval_t paging_region_map(struct paging_region *pr, size_t req_size, void **retbuf,
                           size_t *ret_size)
{
    lvaddr_t end_addr = pr->base_addr + pr->region_size;
    ssize_t rem = end_addr - pr->current_addr;
    if (rem > req_size) {
        // ok
        *retbuf = (void *)pr->current_addr;
        *ret_size = req_size;
        pr->current_addr += req_size;
    } else if (rem > 0) {
        *retbuf = (void *)pr->current_addr;
        *ret_size = rem;
        pr->current_addr += rem;
        debug_printf("exhausted paging region, "
                     "expect badness on next allocation\n");
    } else {
        return LIB_ERR_VSPACE_MMU_AWARE_NO_SPACE;
    }
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
    /**
     * TODO(M2): Implement this function
     * \brief Find a bit of free virtual address space that is large enough to
     *        accomodate a buffer of size `bytes`.
     */
    *buf = NULL;
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
    assert(bytes <= BASE_PAGE_SIZE);
    static uint64_t counter = 0;
    // Set first bit of l0 index
    uint64_t addr = 1;
    addr = addr << VMSAv8_64_L0_BITS;
    addr = addr + (counter << VMSAv8_64_BASE_PAGE_BITS);
    debug_printf("real l3_slot: %"PRIu64"\n", counter);
    err = paging_map_fixed_attr(st, addr, frame, bytes, flags);
    *buf = (void *) addr;
    ++counter;
    return err;

}

errval_t slab_refill_no_pagefault(struct slab_allocator *slabs, struct capref frame,
                                  size_t minbytes)
{
    // Refill the two-level slot allocator without causing a page-fault
    return SYS_ERR_OK;
}

static struct paging_node *find_some(struct paging_node *head, int slot) {
    while (head != NULL && head->slot != slot) {
        head = head->next;
    }

    return head;
}

static struct paging_node *map_some(struct paging_node **head,
        struct paging_node *parent, int level, struct capref pt_cpr,
        int slot, struct paging_state *st, struct capref *frame) {
    errval_t err = 0;
    struct paging_node *node = find_some(*head, slot);
    if (node == NULL) {
        struct capref lower_pt_cpr;
        struct capref higher_lower_map;

        switch(level) {
            case(1):
                err = pt_alloc_l1(st, &lower_pt_cpr);
                break;
            case(2):
                err = pt_alloc_l2(st, &lower_pt_cpr);
                break;
            case(3):
                err = pt_alloc_l3(st, &lower_pt_cpr);
                break;
            case(4):
                lower_pt_cpr = *frame;
                break;
            default:
                return NULL;
        }
        assert(err_is_ok(err));
        err = slot_alloc(&higher_lower_map);
        assert(err_is_ok(err));
        // Does Read/Write make sense for a page table?
        err = vnode_map(pt_cpr, lower_pt_cpr, slot, VREGION_FLAGS_READ_WRITE,
                0, 1, higher_lower_map);
        assert(err_is_ok(err));

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

    return node;
}

errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags)
{
    /**
     * \brief map a user provided frame at user provided VA.
     * TODO(M1): Map a frame assuming all mappings will fit into one last level pt
     * TODO(M2): General case
     */

    // Only one page at the time
    // TODO: Allow for larger frames
    assert(bytes <= BASE_PAGE_SIZE);

    // First 9 bits
    uint64_t mask = 0xEF;

    uint64_t l0_slot = (vaddr >> VMSAv8_64_L0_BITS) & mask;

    struct paging_node *node_l1 = map_some(&st->l0, NULL, 1, st->l0_pt, l0_slot,
                                            st, NULL);
    assert(node_l1 != NULL);
    assert(st->l0 == node_l1);

    uint64_t l1_slot = (vaddr >> VMSAv8_64_L1_BLOCK_BITS) & mask;
    struct paging_node *node_l2 = map_some(&node_l1->child, node_l1, 2,
                                            node_l1->table, l1_slot, st, NULL);
    assert(node_l2 != NULL);
    assert(node_l1->child == node_l2);

    uint64_t l2_slot = (vaddr >> VMSAv8_64_L2_BLOCK_BITS) & mask;
    struct paging_node *node_l3 = map_some(&node_l2->child, node_l2, 3,
                                            node_l2->table, l2_slot, st, NULL);
    assert(node_l3 != NULL);
    assert(node_l2->child == node_l3);

    uint64_t l3_slot = (vaddr >> VMSAv8_64_BASE_PAGE_BITS) & mask;
    debug_printf("l3_slot: %"PRIu64"\n", l3_slot);
    struct paging_node *node_l4 = map_some(&node_l3->child, node_l3, 4,
                                            node_l3->table, l3_slot, st, &frame);
    assert(node_l4 != NULL);
    assert(node_l3->child == node_l4);
    assert(node_l4->child == NULL);

    static size_t is_refilling = 0;
    // TODO: Hope we do not run out of slabs in between
    if (slab_freecount(&st->slabs) - is_refilling == 32) {
        is_refilling = 1;
        slab_default_refill(&st->slabs);
        is_refilling = 0;
    }

    // TODO: Also refill slot_alloc, as slabs might get refilled through
    // mm_alloc whenallocating more slots
    // Assumption: looking at two_level_alloc, slot_allocator underlying
    // slot_alloc seems already designed to not trigger a recursion
    // Search for two_level_allo, or generally look under lib/aos/slot_alloc

    return SYS_ERR_OK;
}


/**
 * \brief unmap a user provided frame, and return the VA of the mapped
 *        frame in `buf`.
 * NOTE: Implementing this function is optional.
 */
// errval_t paging_unmap(struct paging_state *st, const void *region)
// {
errval_t paging_unmap(struct paging_state *st, lvaddr_t vaddr, struct capref
        frame, size_t bytes) {
    assert(bytes <= BASE_PAGE_SIZE);

    // First 9 bits
    uint64_t mask = 0xEF;

    uint64_t l0_slot = (vaddr >> VMSAv8_64_L0_BITS) & mask;
    struct paging_node *node_l1 = find_some(st->l0, l0_slot);
    assert(node_l1 != NULL);

    uint64_t l1_slot = (vaddr >> VMSAv8_64_L1_BLOCK_BITS) & mask;
    struct paging_node *node_l2 = find_some(node_l1->child, l1_slot);
    assert(node_l2 != NULL);

    uint64_t l2_slot = (vaddr >> VMSAv8_64_L2_BLOCK_BITS) & mask;
    struct paging_node *node_l3 = find_some(node_l2->child, l2_slot);
    assert(node_l3 != NULL);

    uint64_t l3_slot = (vaddr >> VMSAv8_64_BASE_PAGE_BITS) & mask;
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
            } else {
                if (node_l2->previous != NULL) {
                    if (node_l2->next != NULL) {
                        node_l2->next->previous = node_l2->previous;
                    }
                    node_l2->previous->next = node_l2->next;
                } else {
                    node_l1->child = node_l2->next;
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
        }
    }

    slab_free(&st->slabs, node_l4);

    return SYS_ERR_OK;
}
