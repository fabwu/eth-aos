/**
 * \file
 * \brief Address manager to track allocated vaddresses
 */

#include <aos/aos.h>
#include <aos/addr_mgr.h>

#if 1
#    define DEBUG_ADDR_MGR(fmt...) debug_printf(fmt);
#else
#    define DEBUG_ADDR_MGR(fmt...) ((void)0)
#endif

/**
 * Add new adr_mgr_node to the free avl, potentially adding to existing avl node by adding
 * onselfes to the list of free nodes with same size
 */
static errval_t addr_mgr_add_to_free(struct addr_mgr_state *st, struct addr_mgr_node *node)
{
    errval_t err;
    struct aos_avl_node *new_avl;
    struct addr_mgr_node *exist_node;

    node->type = AddrNodeType_Free;

    err = aos_avl_find(st->size_free, node->size, (void **)&exist_node);

    node->free_prev = NULL;
    if (err_is_fail(err) && err_no(err) == LIB_ERR_AVL_FIND_NOT_FOUND) {
        new_avl = (struct aos_avl_node *)slab_alloc(&st->avl_slabs);
        assert(new_avl != NULL);

        err = aos_avl_insert(&st->size_free, node->size, (void *)node, new_avl);
        assert(err_is_ok(err));

        node->free_next = NULL;
    } else if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_AVL_FIND);
    } else {
        new_avl = exist_node->free_size_avl;

        exist_node->free_prev = node;
        node->free_next = exist_node;

        err = aos_avl_change_value(node, new_avl);
        assert(err_is_ok(err));
    }

    node->free_size_avl = new_avl;

    assert(node->free_size_avl != NULL);

    // add node into free tree indexed by address
    struct aos_avl_node *new_address_avl;
    new_address_avl = (struct aos_avl_node *)slab_alloc(&st->avl_slabs);
    assert(new_address_avl != NULL);

    err = aos_avl_insert(&st->address_free, node->base, (void *)node, new_address_avl);
    assert(err_is_ok(err));

    node->free_address_avl = new_address_avl;

    return SYS_ERR_OK;
}

errval_t addr_mgr_init(struct addr_mgr_state *st, lvaddr_t start_addr, lvaddr_t max_addr,
                       struct slab_allocator addr_mgr_slabs,
                       struct slab_allocator avl_slabs)
{
    errval_t err;
    // TODO Init slabs in this function and refill them immediately (give buffer
    // when we call it the first time to bootstrap paging)
    st->addr_mgr_slabs = addr_mgr_slabs;
    st->addr_mgr_slabs_refilling = 0;

    st->avl_slabs = avl_slabs;
    st->avl_slabs_refilling = 0;

    st->start_addr = start_addr;
    st->max_addr = max_addr;

    // Add region which goes from start_addr to max_addr to free list
    struct addr_mgr_node *new = (struct addr_mgr_node *)slab_alloc(&st->addr_mgr_slabs);
    if (new == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    new->base = start_addr;
    new->size = max_addr - start_addr;

    err = addr_mgr_add_to_free(st, new);
    aos_avl_traverse(st->address_free, 0);

    return SYS_ERR_OK;
}

static errval_t addr_mgr_alloc_internal(struct addr_mgr_state *st, genvaddr_t base, gensize_t size,
                               struct addr_mgr_node *node)
{
    errval_t err;
    assert(node->free_size_avl != NULL);
    assert(node->free_address_avl != NULL);

    // Always take first from this size free list
    if (node->free_next == NULL) {
        // Need to remove avl_node from free, as the only one with this size which is free
        err = aos_avl_remove_fast(&st->size_free, node->free_size_avl);
        assert(err_is_ok(err));

        slab_free(&st->avl_slabs, node->free_size_avl);
    } else {
        // Only remove us from this size free list
        err = aos_avl_change_value(node->free_next, node->free_size_avl);
        assert(err_is_ok(err));

        node->free_next->free_prev = NULL;
    }

    // remove node from free tree indexed by address
    err = aos_avl_remove_fast(&st->address_free, node->free_address_avl);
    assert(err_is_ok(err));
    slab_free(&st->avl_slabs, node->free_address_avl);

    // Node is not in any avl at the moment, also not of a free list
    node->free_size_avl = NULL;
    node->free_address_avl = NULL;
    node->free_next = NULL;
    node->free_prev = NULL;

    // Split off node on the left, ensuring that base == node->base afterwards
    if (base != node->base) {
        struct addr_mgr_node *new_addr_mgr_left = (struct addr_mgr_node *)slab_alloc(
            &st->addr_mgr_slabs);
        new_addr_mgr_left->base = node->base;
        new_addr_mgr_left->size = base - node->base;
        node->base += new_addr_mgr_left->size;
        node->size -= new_addr_mgr_left->size;

        new_addr_mgr_left->prev = node->prev;
        node->prev = new_addr_mgr_left;
        if (new_addr_mgr_left->prev != NULL) {
            new_addr_mgr_left->prev->next = new_addr_mgr_left;
        } else {
            st->all = new_addr_mgr_left;
        }

        new_addr_mgr_left->next = node;

        // Add what is left of node back to the free list
        err = addr_mgr_add_to_free(st, new_addr_mgr_left);
        assert(err_is_ok(err));
    }

    assert(base == node->base);

    struct addr_mgr_node *new_addr = NULL;
    if (node->size > size) {
        // Split free node to get required size
        new_addr = (struct addr_mgr_node *)slab_alloc(&st->addr_mgr_slabs);
        assert(new_addr != NULL);

        new_addr->base = node->base;
        node->base += size;
        node->size -= size;
        new_addr->size = size;

        new_addr->free_size_avl = NULL;
        new_addr->free_next = NULL;
        new_addr->free_prev = NULL;

        new_addr->prev = node->prev;
        node->prev = new_addr;
        if (new_addr->prev != NULL) {
            new_addr->prev->next = new_addr;
        } else {
            st->all = new_addr;
        }

        new_addr->next = node;

        // Add what is left of node back to the free list
        err = addr_mgr_add_to_free(st, node);
        assert(err_is_ok(err));
    } else {
        // Free node has exactly the required size so we jsut us it
        new_addr = node;
    }

    new_addr->type = AddrNodeType_Allocated;

    struct aos_avl_node *new_allocated_avl = (struct aos_avl_node *)slab_alloc(
        &st->avl_slabs);
    assert(new_allocated_avl != NULL);
    err = aos_avl_insert(&st->allocated, new_addr->base, (void *)new_addr,
                         new_allocated_avl);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_AVL_INSERT);
    }

    DEBUG_ADDR_MGR("addr_mgr_alloc() add node to allocated with key: 0x%" PRIx64
                   " and size 0x%" PRIx64 "\n",
                   new_addr->base, new_addr->size);

    new_addr->allocated_address_avl = new_allocated_avl;

    if (slab_freecount(&st->addr_mgr_slabs) < 32 && !st->addr_mgr_slabs_refilling) {
        st->addr_mgr_slabs_refilling = 1;
        slab_default_refill(&st->addr_mgr_slabs);
        st->addr_mgr_slabs_refilling = 0;
    }

    if (slab_freecount(&st->avl_slabs) < 32 && !st->avl_slabs_refilling) {
        st->avl_slabs_refilling = 1;
        slab_default_refill(&st->avl_slabs);
        st->avl_slabs_refilling = 0;
    }

    DEBUG_ADDR_MGR("addr_mgr_alloc end\n");

    return SYS_ERR_OK;
}

/**
 * \brief allocs a range of size from the addr mgr at some base addr, returns
 * the base addr
 */
errval_t addr_mgr_alloc(struct addr_mgr_state *st, genvaddr_t *ret, gensize_t wanted_size,
                        gensize_t alignment)
{
    DEBUG_ADDR_MGR("addr_mgr_alloc begin\n");
    errval_t err;

    // TODO: handle alignment
    assert(alignment <= BASE_PAGE_SIZE);

    size_t size = BASE_PAGE_SIZE;
    while (size < wanted_size) {
        size += BASE_PAGE_SIZE;
    }

    // Find suitable node in free tree
    struct addr_mgr_node *node;
    err = aos_avl_find_ge(st->size_free, size, (void **)&node);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_AVL_FIND_GE);
    }

    assert(node->size >= size);
    DEBUG_ADDR_MGR("addr_mgr_alloc found node size: 0x%" PRIx64 "\n", node->size);

    // Always get the leftmost chunk, e.g. from base upward until base + size - 1
    genvaddr_t base = node->base;
    err = addr_mgr_alloc_internal(st, base, size, node);

    *ret = base;

    DEBUG_ADDR_MGR("addr_mgr_alloc begin\n");

    return err;
}

/**
 * \brief returns the allocated node for a given address or NULL if no region
 * was allocated for this address.
 */
static struct addr_mgr_node *addr_mgr_find_node_for_addr(struct addr_mgr_state *st,
                                                         genvaddr_t addr)
{
    errval_t err;
    lvaddr_t base_addr = ROUND_DOWN(addr, BASE_PAGE_SIZE);

    struct addr_mgr_node *node;

    err = aos_avl_find(st->allocated, base_addr, (void **)&node);
    if (err_is_ok(err)) {
        return node;
    } else if (err_no(err) == LIB_ERR_AVL_FIND_NOT_FOUND) {
        return NULL;
    }

    // TODO Better error handling
    DEBUG_ERR(err, "Err in avl find");
    return NULL;
}

bool addr_mgr_is_addr_allocated(struct addr_mgr_state *st, genvaddr_t addr)
{
    return addr_mgr_find_node_for_addr(st, addr) != NULL;
}

/**
 * \brief allocs a range from the addr mgr at given base addr
 */
errval_t addr_mgr_alloc_fixed(struct addr_mgr_state *st, genvaddr_t base, gensize_t size)
{
    DEBUG_ADDR_MGR("addr_mgr_alloc_fixed() called with base %p and size %d\n", base, size);

    // TODO: Handle alignment
    assert(base % BASE_PAGE_SIZE == 0);
    assert(size % BASE_PAGE_SIZE == 0);
    assert(size > 0);

    errval_t err;

    // find node which closest to base but has smaller or equal address
    struct addr_mgr_node *free_node;
    err = aos_avl_find_le(st->address_free, base, (void **)&free_node);
    if (err_is_fail(err) && err_no(err) == LIB_ERR_AVL_FIND_LE_NOT_FOUND) {
        return LIB_ERR_ADDR_MGR_FULL;
    } else if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_AVL_FIND_LE);
    }

    assert(free_node->base <= base);

    if (base + size >= free_node->base + free_node->size) {
        return LIB_ERR_ADDR_MGR_FULL;
    }

    return addr_mgr_alloc_internal(st, base, size, free_node);
}

static errval_t addr_mgr_remove_from_free(struct addr_mgr_state *st,
                                          struct addr_mgr_node *node)
{
    DEBUG_ADDR_MGR("addr_mgr_remove_from_free begin\n");
    DEBUG_ADDR_MGR("addr_mgr_remove_from_free node addr: 0x%" PRIx64 "\n", node->base);

    assert(node->free_size_avl != NULL);
    assert(node->free_address_avl != NULL);
    assert(st->size_free != NULL);
    assert(st->address_free != NULL);

    errval_t err;
    if (node->free_prev == NULL && node->free_next == NULL) {
        DEBUG_ADDR_MGR("addr_mgr_remove_from_free before crash\n");
        // Remove avl from free, we the only ones with this size
        err = aos_avl_remove_fast(&st->size_free, node->free_size_avl);
        assert(err_is_ok(err));

        slab_free(&st->avl_slabs, node->free_size_avl);
    } else {
        if (node->free_prev == NULL) {
            aos_avl_change_value(node->free_next, node->free_size_avl);

            node->free_next->free_prev = NULL;
        } else {
            node->free_prev->free_next = node->free_next;
            if (node->free_next != NULL) {
                node->free_next->free_prev = node->free_prev;
            }
        }
    }

    err = aos_avl_remove_fast(&st->address_free, node->free_address_avl);
    assert(err_is_ok(err));

    slab_free(&st->avl_slabs, node->free_address_avl);

    node->free_size_avl = NULL;
    node->free_address_avl = NULL;
    node->free_next = NULL;
    node->free_prev = NULL;

    DEBUG_ADDR_MGR("addr_mgr_remove_from_free end\n");

    return SYS_ERR_OK;
}

errval_t addr_mgr_free(struct addr_mgr_state *st, genvaddr_t base, gensize_t size)
{
    DEBUG_ADDR_MGR("addr_mgr_free begin\n");
    DEBUG_ADDR_MGR("addr_mgr_free addr to free: 0x%" PRIx64 "\n", base);

    errval_t err;

    struct addr_mgr_node *old_node;
    err = aos_avl_find(st->allocated, base, (void **)&old_node);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_AVL_FIND);
    }

    assert(old_node->base == base);

    // delete from allocated
    err = aos_avl_remove_fast(&st->allocated, old_node->allocated_address_avl);
    assert(err_is_ok(err));

    slab_free(&st->avl_slabs, old_node->allocated_address_avl);

    old_node->allocated_address_avl = NULL;

    assert(old_node->prev == NULL || old_node->prev->base < old_node->base);
    assert(old_node->next == NULL || old_node->next->base > old_node->base);

    // check if can fuse with neighbours
    struct addr_mgr_node *left_neigh = old_node->prev;
    if (left_neigh != NULL && left_neigh->type == AddrNodeType_Free) {
        assert(left_neigh->free_size_avl != NULL);
        assert(left_neigh->free_address_avl != NULL);
        err = addr_mgr_remove_from_free(st, left_neigh);
        assert(err_is_ok(err));

        // all list should be ordered ascending
        assert(left_neigh->base < old_node->base);

        old_node->base = left_neigh->base;
        old_node->size += left_neigh->size;

        old_node->prev = left_neigh->prev;
        if (left_neigh->prev == NULL) {
            st->all = old_node;
        } else {
            old_node->prev->next = old_node;
        }

        slab_free(&st->addr_mgr_slabs, left_neigh);
    }

    struct addr_mgr_node *right_neigh = old_node->next;
    if (right_neigh != NULL && right_neigh->type == AddrNodeType_Free) {
        assert(right_neigh->free_size_avl != NULL);
        assert(right_neigh->free_address_avl != NULL);
        err = addr_mgr_remove_from_free(st, right_neigh);
        assert(err_is_ok(err));

        // all list should be ordered ascending
        assert(old_node->base < right_neigh->base);

        old_node->size += right_neigh->size;

        old_node->next = right_neigh->next;
        if (right_neigh->next != NULL) {
            old_node->next->prev = old_node;
        }

        slab_free(&st->addr_mgr_slabs, right_neigh);
    }

    assert(old_node->prev == NULL || old_node->prev->base < old_node->base);
    assert(old_node->next == NULL || old_node->next->base > old_node->base);

    err = addr_mgr_add_to_free(st, old_node);
    assert(err_is_ok(err));

    DEBUG_ADDR_MGR("addr_mgr_free end\n");

    return SYS_ERR_OK;
}

