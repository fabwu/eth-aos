/**
 * \file
 * \brief Address manager to track allocated vaddresses
 */

#ifndef AOS_ADDR_MGR
#define AOS_ADDR_MGR

#include <aos/avl.h>

enum addr_mgr_nodetype {
    AddrNodeType_Free,      ///< This region exists and is free
    AddrNodeType_Allocated  ///< This region exists and is allocated
};

struct addr_mgr_node {
    genvaddr_t base;
    gensize_t size;

    struct addr_mgr_node *next;
    struct addr_mgr_node *prev;

    struct aos_avl_node *free_size_avl; // this is the avl node in the free tree indexed by size
    struct aos_avl_node *free_address_avl; // this is the avl node in the free tree indexed by address
    struct aos_avl_node *allocated_address_avl; // this is the avl node in the allocated tree indexed by address

    struct addr_mgr_node *free_prev;
    struct addr_mgr_node *free_next;

    //TODO we can remove this and use the avl nodes to determine if node is
    //free
    enum addr_mgr_nodetype type;
};

struct addr_mgr_state {
    struct slab_allocator addr_mgr_slabs;
    struct slab_allocator avl_slabs;
    int addr_mgr_slabs_refilling;
    int avl_slabs_refilling;

    struct addr_mgr_node *all;
    struct aos_avl_node *size_free; // avl tree with free nodes indexed by size (each size has a linked list with
                                    // addr nodes from this size)
    struct aos_avl_node *address_free; // avl_tree with free nodes indexed by address
    struct aos_avl_node *allocated; // avl tree with allocated nodes indexed by address 

    lvaddr_t start_addr;
    lvaddr_t max_addr;
};

errval_t addr_mgr_init(struct addr_mgr_state *st, lvaddr_t start_addr, lvaddr_t max_addr,
        struct slab_allocator addr_mgr_slabs, struct slab_allocator avl_slabs);

errval_t addr_mgr_alloc(struct addr_mgr_state *st, genvaddr_t *ret, gensize_t size,
                               gensize_t alignment);

errval_t addr_mgr_alloc_fixed(struct addr_mgr_state *st, genvaddr_t base,
                                     gensize_t size);

bool addr_mgr_is_addr_allocated(struct addr_mgr_state *st, genvaddr_t addr);

errval_t addr_mgr_free(struct addr_mgr_state *st, genvaddr_t base, gensize_t size);

#endif
