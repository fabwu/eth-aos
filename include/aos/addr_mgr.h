/**
 * \file
 * \brief Address manager to track allocated vaddresses
 */

#ifndef AOS_ADDR_MGR
#define AOS_ADDR_MGR

struct addr_mgr_node {
    genvaddr_t base;
    gensize_t size;
    struct addr_mgr_node* prev;
    struct addr_mgr_node* next;
};

struct addr_mgr_state {
    struct slab_allocator slabs;
    int is_slabs_refilling;
    struct addr_mgr_node *head;
    struct addr_mgr_node *tail;
    genvaddr_t max_addr;
};

errval_t addr_mgr_init(struct addr_mgr_state *st, lvaddr_t max_addr,
        struct slab_allocator slabs);

errval_t addr_mgr_alloc(struct addr_mgr_state *st, genvaddr_t *ret, gensize_t size,
                               gensize_t alignment);

errval_t addr_mgr_alloc_fixed(struct addr_mgr_state *st, genvaddr_t base,
                                     gensize_t size);

bool addr_mgr_is_addr_allocated(struct addr_mgr_state *st, genvaddr_t addr);

errval_t addr_mgr_free(struct addr_mgr_state *st, genvaddr_t base, gensize_t size);

#endif
