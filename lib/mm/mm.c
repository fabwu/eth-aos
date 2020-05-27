/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>

#if 0
#    define DEBUG_MM(fmt...) debug_printf(fmt);
#else
#    define DEBUG_MM(fmt...) ((void)0)
#endif

errval_t mm_init(struct mm *mm)
{
    slab_init(&mm->bi_node_slab, sizeof(struct bi_node), NULL);
    slab_init(&mm->mm_node_slab, sizeof(struct mm_node), NULL);
    slab_init(&mm->avl_node_slab, sizeof(struct aos_avl_node), NULL);

    mm->bi = NULL;

    mm->all = NULL;
    mm->free = NULL;
    mm->allocated = NULL;

    mm->stats_bytes_max = 0;
    mm->stats_bytes_available = 0;

    mm->mm_node_slab_refilling = 0;
    mm->avl_node_slab_refilling = 0;

    thread_mutex_init(&mm->alloc_mutex);

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    assert(!"NYI");
}

/**
 * Add new mm_node to free avl, potentially adding to existing avl node by adding
 * onselfes to the list of free nodes with same size
 */
static errval_t mm_add_to_free(struct mm *mm, struct mm_node *node)
{
    errval_t err;
    struct aos_avl_node *new_avl;
    struct mm_node *exist_mm;

    node->type = NodeType_Free;

    err = aos_avl_find(mm->free, node->size, (void **)&exist_mm);

    node->free_prev = NULL;
    if (err_is_fail(err) && err_no(err) == LIB_ERR_AVL_FIND_NOT_FOUND) {
        new_avl = (struct aos_avl_node *)slab_alloc(&mm->avl_node_slab);
        assert(new_avl != NULL);

        err = aos_avl_insert(&mm->free, node->size, (void *)node, new_avl);
        assert(err_is_ok(err));

        node->free_next = NULL;
    } else if (err_is_fail(err)) {
        return LIB_ERR_AVL_FIND;
    } else {
        new_avl = exist_mm->avl;

        exist_mm->free_prev = node;
        node->free_next = exist_mm;

        err = aos_avl_change_value(node, new_avl);
        assert(err_is_ok(err));
    }

    node->avl = new_avl;

    assert(node->avl != NULL);

    return SYS_ERR_OK;
}

errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size)
{
    DEBUG_MM("mm_add begin\n");
    DEBUG_MM("mm_add with size 0x%" PRIx64 "\n", size);
    DEBUG_MM("mm_add with base 0x%" PRIx64 "\n", base);

    // TODO: Cleanup on error
    errval_t err;

    // TODO: Handle alignment
    assert(base % BASE_PAGE_SIZE == 0);

    // Create bi node, off of which all capabilities are created from
    struct bi_node *new_bi = (struct bi_node *)slab_alloc(&mm->bi_node_slab);
    assert(new_bi != NULL);

    new_bi->cap = cap;
    new_bi->base = base;
    new_bi->size = size;

    if (mm->bi != NULL) {
        new_bi->next = mm->bi;
        mm->bi->prev = new_bi;
    } else {
        new_bi->next = NULL;
    }

    new_bi->prev = NULL;
    mm->bi = new_bi;

    // Create a mm_node, which refers to new_bi, and online when allocated capability is created
    struct mm_node *new_mm = (struct mm_node *)slab_alloc(&mm->mm_node_slab);
    assert(new_mm != NULL);

    new_mm->base = base;
    new_mm->size = size;
    new_mm->origin = new_bi;

    // Add to linked list of all mm_nodes in ascending order, to support fusing free nodes
    // Assumption: bi has caps ordered in ascending order, so this should be faste
    struct mm_node *all = mm->all;
    while (all != NULL && base < all->base && all->next != NULL) {
        all = all->next;
    }
    if (all == NULL) {
        mm->all = new_mm;
        new_mm->next = NULL;
        new_mm->prev = NULL;
    } else if (base < all->base) {
        new_mm->prev = all->prev;
        new_mm->next = all;
        if (all->prev != NULL) {
            all->prev->next = new_mm;
        } else {
            mm->all = new_mm;
        }
        all->prev = new_mm;
    } else {
        all->next = new_mm;
        new_mm->prev = all;
        new_mm->next = NULL;
    }

    err = mm_add_to_free(mm, new_mm);
    assert(err_is_ok(err));

    assert(new_mm->avl != NULL);

    mm->stats_bytes_max += size;
    mm->stats_bytes_available += size;

    DEBUG_MM("mm_add end\n");

    return SYS_ERR_OK;
}


errval_t mm_alloc_aligned(struct mm *mm, size_t wanted_size, size_t alignment,
                          struct capref *retcap)
{
    DEBUG_MM("mm_alloc_aligned begin\n");
    errval_t err;

    // TODO: handle alignment
    assert(alignment <= BASE_PAGE_SIZE);

    size_t size = ROUND_UP(wanted_size, BASE_PAGE_SIZE);

    struct capref cap;
    // TODO: Improve cleanup
    // Alloc capability
    err = slot_alloc(&cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    thread_mutex_lock(&mm->alloc_mutex);

    struct mm_node *node;
    err = aos_avl_find_ge(mm->free, size, (void **)&node);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_AVL_FIND_GE);
        goto out;
    }

    assert(node->size >= size);
    DEBUG_MM("mm_alloc_aligned found node size: 0x%" PRIx64 "\n", node->size);

    assert(node->avl != NULL);

    // Always take first from this size free list
    if (node->free_next == NULL) {
        // Need to remove avl_node from free, as the only one with this size which is free
        err = aos_avl_remove_fast(&mm->free, node->avl);
        assert(err_is_ok(err));

        slab_free(&mm->avl_node_slab, node->avl);
    } else {
        // Only remove us from this size free list
        err = aos_avl_change_value(node->free_next, node->avl);
        assert(err_is_ok(err));

        node->free_next->free_prev = NULL;
    }

    // Node is not in any avl at the moment, also not of a free list
    node->avl = NULL;
    node->free_next = NULL;
    node->free_prev = NULL;

    struct mm_node *new_mm = NULL;
    if (node->size > size) {
        new_mm = (struct mm_node *)slab_alloc(&mm->mm_node_slab);
        assert(new_mm != NULL);

        // TODO: unify mm_node initialization
        new_mm->base = node->base;
        node->base += size;
        node->size -= size;
        new_mm->size = size;
        new_mm->origin = node->origin;

        new_mm->avl = NULL;
        new_mm->free_next = NULL;
        new_mm->free_prev = NULL;

        new_mm->prev = node->prev;
        node->prev = new_mm;
        if (new_mm->prev != NULL) {
            new_mm->prev->next = new_mm;
        } else {
            mm->all = new_mm;
        }

        new_mm->next = node;

        // Add what is left of node back to the free list
        err = mm_add_to_free(mm, node);
        assert(err_is_ok(err));
    } else {
        new_mm = node;
    }

    new_mm->type = NodeType_Allocated;

    err = cap_retype(cap, new_mm->origin->cap, new_mm->base - new_mm->origin->base,
                     ObjType_RAM, size, 1);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_CAP_RETYPE);
        goto out;
    }

    struct aos_avl_node *new_avl = (struct aos_avl_node *)slab_alloc(&mm->avl_node_slab);
    assert(new_avl != NULL);
    err = aos_avl_insert(&mm->allocated, new_mm->base, (void *)new_mm, new_avl);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_AVL_INSERT);
        goto out;
    }

out:
    thread_mutex_unlock(&mm->alloc_mutex);
    if (err_is_fail(err)) {
        return err;
    }

    DEBUG_MM("mm_alloc_aligned add node to allocated with key: 0x%" PRIx64 "\n",
             new_mm->base);

    new_mm->avl = new_avl;

    mm->stats_bytes_available -= size;

    *retcap = cap;

    // Only need to refill mm_node_slab, as bi_node_slab will never be need after
    // startup
    // Hope 31 is enough to keep it going until refilled
    if (slab_freecount(&mm->mm_node_slab) < 32 && !mm->mm_node_slab_refilling) {
        mm->mm_node_slab_refilling = 1;
        slab_default_refill(&mm->mm_node_slab);
        mm->mm_node_slab_refilling = 0;
    }

    // Hope 31 is enough to keep it going until refilled
    if (slab_freecount(&mm->avl_node_slab) < 32 && !mm->avl_node_slab_refilling) {
        mm->avl_node_slab_refilling = 1;
        slab_default_refill(&mm->avl_node_slab);
        mm->avl_node_slab_refilling = 0;
    }

    DEBUG_MM("mm_alloc_aligned end\n");

    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

static errval_t mm_remove_from_free(struct mm *mm, struct mm_node *node)
{
    DEBUG_MM("mm_remove_from_free begin\n");
    DEBUG_MM("mm_remove_from_free node addr: 0x%" PRIx64 "\n", node->base);

    assert(node->avl != NULL);
    assert(mm->free != NULL);

    errval_t err;
    if (node->free_prev == NULL && node->free_next == NULL) {
        DEBUG_MM("mm_remove_from_free before crash\n");
        // Remove avl from free, we the only ones with this size
        err = aos_avl_remove_fast(&mm->free, node->avl);
        assert(err_is_ok(err));

        slab_free(&mm->avl_node_slab, node->avl);
    } else {
        if (node->free_prev == NULL) {
            aos_avl_change_value(node->free_next, node->avl);

            node->free_next->free_prev = NULL;
        } else {
            node->free_prev->free_next = node->free_next;
            if (node->free_next != NULL) {
                node->free_next->free_prev = node->free_prev;
            }
        }
    }

    node->avl = NULL;
    node->free_next = NULL;
    node->free_prev = NULL;

    DEBUG_MM("mm_remove_from_free end\n");

    return SYS_ERR_OK;
}

// Assumes cap has already been destroyed!
errval_t mm_free(struct mm *mm, genpaddr_t addr)
{
    DEBUG_MM("mm_free begin\n");
    DEBUG_MM("mm_free addr to free: 0x%" PRIx64 "\n", addr);

    errval_t err;

    // FIXME: add debug cap_retype/cap_destroy, to check if really is free

    thread_mutex_lock(&mm->alloc_mutex);

    struct mm_node *old_node;
    err = aos_avl_find(mm->allocated, addr, (void **)&old_node);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_AVL_FIND);
        goto out;
    }

    assert(old_node->base == addr);

    mm->stats_bytes_available += old_node->size;

    // delete from allocated
    err = aos_avl_remove_fast(&mm->allocated, old_node->avl);
    assert(err_is_ok(err));

    slab_free(&mm->avl_node_slab, old_node->avl);

    old_node->avl = NULL;

    assert(old_node->prev == NULL || old_node->prev->base < old_node->base);
    assert(old_node->next == NULL || old_node->next->base > old_node->base);

    // check if can fuse with neighbours
    struct mm_node *left_neigh = old_node->prev;
    if (left_neigh != NULL && old_node->origin == left_neigh->origin
        && left_neigh->type == NodeType_Free) {
        assert(left_neigh->avl != NULL);

        DEBUG_MM("mm_free before crash\n");
        err = mm_remove_from_free(mm, left_neigh);
        assert(err_is_ok(err));
        DEBUG_MM("mm_free after crash\n");

        // all list should be ordered ascending
        assert(left_neigh->base < old_node->base);

        old_node->base = left_neigh->base;
        old_node->size += left_neigh->size;

        old_node->prev = left_neigh->prev;
        if (left_neigh->prev == NULL) {
            mm->all = old_node;
        } else {
            old_node->prev->next = old_node;
        }

        slab_free(&mm->mm_node_slab, left_neigh);
    }

    struct mm_node *right_neigh = old_node->next;
    if (right_neigh != NULL && old_node->origin == right_neigh->origin
        && right_neigh->type == NodeType_Free) {
        assert(right_neigh->avl != NULL);
        err = mm_remove_from_free(mm, right_neigh);
        assert(err_is_ok(err));

        // all list should be ordered ascending
        assert(old_node->base < right_neigh->base);

        old_node->size += right_neigh->size;

        old_node->next = right_neigh->next;
        if (right_neigh->next != NULL) {
            old_node->next->prev = old_node;
        }

        slab_free(&mm->mm_node_slab, right_neigh);
    }

    assert(old_node->prev == NULL || old_node->prev->base < old_node->base);
    assert(old_node->next == NULL || old_node->next->base > old_node->base);

    err = mm_add_to_free(mm, old_node);
    assert(err_is_ok(err));

    err = SYS_ERR_OK;

    DEBUG_MM("mm_free end\n");

out:
    thread_mutex_unlock(&mm->alloc_mutex);
    return err;
}
