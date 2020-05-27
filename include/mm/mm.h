/**
 * \file
 * \brief Memory manager header
 */

/*
 * Copyright (c) 2008, 2011, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef AOS_MM_H
#define AOS_MM_H

#include <sys/cdefs.h>
#include <errors/errno.h>
#include <aos/types.h>
#include <aos/capabilities.h>
#include <aos/slab.h>
#include <aos/avl.h>

__BEGIN_DECLS

enum nodetype {
    NodeType_Free,      ///< This region exists and is free
    NodeType_Allocated  ///< This region exists and is allocated
};

struct bi_node {
    struct bi_node *prev;
    struct bi_node *next;
    struct capref cap;
    genpaddr_t base;
    gensize_t size;
};

struct mm_node {
    // all double linked list
    struct mm_node *prev;
    struct mm_node *next;

    struct bi_node *origin;

    struct aos_avl_node *avl;
    
    // free with same size double linked list
    struct mm_node *free_prev;
    struct mm_node *free_next;

    genpaddr_t base;
    gensize_t size;

    enum nodetype type;
};

/**
 * \brief Memory manager instance data
 *
 * This should be opaque from the perspective of the client, but to allow
 * them to allocate its memory, we declare it in the public header.
 */
struct mm {
    struct slab_allocator bi_node_slab;
    struct slab_allocator mm_node_slab;
    struct slab_allocator avl_node_slab;

    struct bi_node *bi;

    struct mm_node *all;
    struct aos_avl_node *free;
    struct aos_avl_node *allocated;

    /* statistics */
    gensize_t stats_bytes_max;
    gensize_t stats_bytes_available;

    char mm_node_slab_refilling;
    char avl_node_slab_refilling;

    struct thread_mutex alloc_mutex;
};

errval_t mm_init(struct mm *mm);
errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size);
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment,
                              struct capref *retcap);
errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap);
errval_t mm_free(struct mm *mm, genpaddr_t addr);
void mm_dump_mmnodes(struct mm *mm);
void mm_destroy(struct mm *mm);

__END_DECLS

#endif /* AOS_MM_H */
