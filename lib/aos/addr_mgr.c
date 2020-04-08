/**
 * \file
 * \brief Address manager to track allocated vaddresses
 */

#include <aos/aos.h>
#include <aos/addr_mgr.h>

#if 0
#    define DEBUG_ADDR_MGR(fmt...) debug_printf(fmt);
#else
#    define DEBUG_ADDR_MGR(fmt...) ((void)0)
#endif

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
errval_t addr_mgr_alloc(struct addr_mgr_state *st, genvaddr_t *ret, gensize_t size,
                               gensize_t alignment)
{
    DEBUG_ADDR_MGR("addr_mgr_alloc begin\n");

    // TODO: Handle alignment
    assert(alignment == BASE_PAGE_SIZE);
    assert(size > 0);
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

        DEBUG_ADDR_MGR("addr_mgr_alloc end\n");

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
 * \brief returns the allocated node for a given address or NULL if no region
 * was allocated for this address.
 */
static struct addr_mgr_node *addr_mgr_find_node_for_addr(struct addr_mgr_state *st, genvaddr_t addr) {
    struct addr_mgr_node *cur_node = st->head;
    while(cur_node != NULL) {
        genvaddr_t region_start = cur_node->base;
        genvaddr_t region_end = region_start + cur_node->size;

        // assume start and end are page aligned
        assert(region_start % BASE_PAGE_SIZE == 0);
        assert(region_end % BASE_PAGE_SIZE == 0);

        if(addr >= region_start && addr <= region_end) {
            return cur_node;
        }

        cur_node = cur_node->next;
    }

    // couldn't find node for addr
    return NULL;
}

bool addr_mgr_is_addr_allocated(struct addr_mgr_state *st, genvaddr_t addr) {
    return addr_mgr_find_node_for_addr(st, addr) != NULL;
}

/**
 * \brief allocs a range from the addr mgr at given base addr
 */
errval_t addr_mgr_alloc_fixed(struct addr_mgr_state *st, genvaddr_t base,
                                     gensize_t size)
{
    // TODO: Handle alignment
    assert(base % BASE_PAGE_SIZE == 0);
    assert(size % BASE_PAGE_SIZE == 0);
    assert(size > 0);
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

errval_t addr_mgr_free(struct addr_mgr_state *st, genvaddr_t base, gensize_t size)
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

