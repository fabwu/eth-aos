/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>



errval_t mm_init(struct mm *mm)
{
    slab_init(&mm->capnode_slab, sizeof(struct capnode), NULL);
    slab_init(&mm->mmnode_slab, sizeof(struct mmnode), NULL);

    mm->capnode_head = NULL;
    mm->mmnode_head = NULL;

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    assert(!"NYI");
}

errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size)
{
    struct capnode *new = (struct capnode *)slab_alloc(&mm->capnode_slab);
    assert(new != NULL);

    new->cap.cap = cap;
    new->cap.base = base;
    new->cap.size = size;
    new->base = base;
    new->size = size;

    if (mm->capnode_head != NULL) {
        new->next = mm->capnode_head;
        mm->capnode_head->prev = new;
    } else {
        new->next = NULL;
    }

    new->prev = NULL;
    mm->capnode_head = new;
    
    return SYS_ERR_OK;
}


errval_t mm_alloc_aligned(struct mm *mm, size_t wanted_size, size_t alignment, struct capref *retcap)
{
    // TODO: handle alignment
    assert(alignment <= BASE_PAGE_SIZE);

    size_t size = BASE_PAGE_SIZE;
    while (size < wanted_size) {
        size += (1 << 12);
    }

    errval_t err;
    struct mmnode *curr = mm->mmnode_head;
    while (curr != NULL) {
        if (curr->type == NodeType_Free && curr->size >= size)
            break;

        curr = curr->next;
    }

    // Split from one of the capnodes
    if (curr == NULL) {
        struct capnode *curr_cap = mm->capnode_head;
        while (curr_cap != NULL) {
            if (curr_cap->size >= size)
                break;

            curr_cap = curr_cap->next;
        }
        
        if (curr_cap == NULL) {
            return LIB_ERR_RAM_ALLOC;
        }

        struct mmnode *new = (struct mmnode *)slab_alloc(&mm->mmnode_slab);
        if (new == NULL) {
            return LIB_ERR_SLAB_ALLOC_FAIL;
        }

        new->type = NodeType_Allocated;
        // Track where I'm from
        new->capnode = curr_cap;

        // Split off at the start
        new->base = curr_cap->base;
        new->size = size;

        if (mm->mmnode_head == NULL) {
            new->next = NULL;
        } else {
            new->next = mm->mmnode_head;
            mm->mmnode_head->prev = new;
        }
        mm->mmnode_head = new;
        new->prev = NULL;

        // Reduce size
        curr_cap->base += size;
        curr_cap->size -= size;

        curr = new;
    }

    curr->type = NodeType_Allocated;

    struct capref cap;

    // Alloc capability
    err = slot_alloc(&cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    assert(curr->base % BASE_PAGE_SIZE == 0);

    // Assumption: offset is offset into object pointed to by capability,
    // size is size of the part of the object pointed to by capability from
    // the offset onward, that should be propagated
    // offset needs to account for already split rams
    err = cap_retype(cap, curr->capnode->cap.cap,
            curr->base - curr->capnode->cap.base, ObjType_RAM, size, 1);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    *retcap = cap;

    // FIXME: HACK
    // Only need to refill mmnode_slab, as capnode_slab will never be need after
    // startup
    static int is_refilling_slab = 0;
    // Hope 31 is enough to keep it going until refilled
    if (slab_freecount(&mm->mmnode_slab) < 32 &&  !is_refilling_slab) {
        is_refilling_slab = 1;
        slab_default_refill(&mm->mmnode_slab);
        is_refilling_slab = 0;
    }

    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}


// Assumes cap has already been destroyed!
errval_t mm_free(struct mm *mm, genpaddr_t addr)
{
    // TODO: Can I delete/recreate capref, so that we can ensure caller does not
    // inadvertently use capability?
    struct mmnode *curr = mm->mmnode_head;
    while (curr != NULL) {
        // TODO: Maybe check via cap if really allowed to free, can't spoof me
        // into freeing stuff he doesn't own?
        if (curr->type == NodeType_Allocated && curr->base == addr)
            break;

        curr = curr->next;
    }

    // TODO: Give back nice error message
    assert(curr != NULL);

    // TODO: Maybe fuse back together if left or right is free and came from the
    // same original block
    curr->type = NodeType_Free;

    return SYS_ERR_OK;
}
