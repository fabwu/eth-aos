/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>



errval_t mm_init(struct mm *mm, enum objtype objtype,
                     slab_refill_func_t slab_refill_func,
                     slot_alloc_t slot_alloc_func,
                     slot_refill_t slot_refill_func,
                     void *slot_alloc_inst)
{
    // In need to allocate struct mmnode, therefore I need slabs of size
    // sizeof(struct mmnode)
    slab_init(&mm->slabs, sizeof(struct mmnode), slab_refill_func);

    mm->objtype = objtype;
    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    assert(!"NYI");
}

errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size)
{
    // Slabs are sizeof(struct mmnode), cast is resonable
    // TODO: handle slab allocator empty
    struct mmnode *new = (struct mmnode *)slab_alloc(&mm->slabs);

    new->type = NodeType_Free;
    new->cap.cap = cap;
    new->cap.base = base;
    new->cap.size = size;
    new->base = base;
    new->size = size;

    if (mm->head != NULL) {
        new->next = mm->head;
        mm->head->prev = new;
    } else {
        new->next = NULL;
    }

    new->prev = NULL;
    mm->head = new;
    
    return SYS_ERR_OK;
}


errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap)
{
    errval_t err;
    struct mmnode *curr = mm->head;
    while (curr != NULL) {
        if (curr->type == NodeType_Free && curr->size >= size)
            break;

        curr = curr->next;
    }

    if (curr == NULL) {
        return LIB_ERR_RAM_ALLOC;
    }

    // TODO: handle alignment
    assert(curr->base % alignment == 0);

    if (size == curr->size) {
        curr->type = NodeType_Allocated;
        *retcap = curr->cap.cap;

        return SYS_ERR_OK;
    } else {
        // TODO: handle slab allocator empty
        struct mmnode *new = (struct mmnode *)slab_alloc(&mm->slabs);
        assert(new != NULL);

        new->type = NodeType_Allocated;

        // Alloc capability
        // TODO: handle slot allocator empty
        err = mm->slot_alloc(mm->slot_alloc_inst, 1, &new->cap.cap);
        assert(err_is_ok(err));

        // Split off at the start
        new->cap.base = curr->base;
        new->base = curr->base;
        new->size = size;

        // Reduce size
        curr->base += size;
        curr->size -= size;

        assert(curr->size > 0);

        // Maybe we shouldn't do that, as we might need this to fuse when
        // freeing?
        // curr->cap.base = curr->base;
        // curr->cap.size = curr->size;

        if (curr->prev == NULL) {
            mm->head = new;
            new->prev = NULL;
        } else {
            curr->prev->next = new;
            new->prev = curr->prev;
        }

        curr->prev = new;
        new->next = curr;

        // Assumption: offset is offset into object pointed to by capability,
        // size is size of the part of the object pointed to by capability from
        // the offset onward, that should be propagated
        // offset needs to account for already split rams
        err = cap_retype(new->cap.cap, curr->cap.cap,
                // TODO: Is this correct?
                curr->base - curr->cap.base, ObjType_RAM, size, 1);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_RAM_ALLOC);
        }

        *retcap = new->cap.cap;

        return SYS_ERR_OK;
    }
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}


errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size)
{
    // TODO: Can I delete/recreate capref, so that we can ensure caller does not
    // inadvertently use capability?
    struct mmnode *curr = mm->head;
    while (curr != NULL) {
        // TODO: Maybe check via cap if really allowed to free, can't spoof me
        // into freeing stuff he doesn't own?
        if (curr->type == NodeType_Allocated && curr->base == base)
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
