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
    } 

    mm->head = new;
    
    return SYS_ERR_OK;
}


errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}


errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size)
{
    return LIB_ERR_NOT_IMPLEMENTED;

}
