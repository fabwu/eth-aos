#ifndef AOS_AVL
#define AOS_AVL

// Implementation of an avl tree without internal memory management and opaque pointer
// A lot taken from https://en.wikipedia.org/wiki/AVL_tree

struct aos_avl_node {
    struct aos_avl_node *parent;
    struct aos_avl_node *left;
    struct aos_avl_node *right;

    uint64_t key;
    void *value;

    signed char bal;
};

/**
 * \brief insert key with value into tree root, node must be provided
 */
errval_t aos_avl_insert(struct aos_avl_node **root, uint64_t key, void *value,
                        struct aos_avl_node *node);

/**
 * \brief removes key from tree root, returns value saved under key, node is struct not
 * anymore used in tree root afterwards
 */
errval_t aos_avl_remove(struct aos_avl_node **root, uint64_t key, void **value,
                        struct aos_avl_node **node);

/**
 * \brief removes node from tree root, node is not used in tree afterwards
 */
errval_t aos_avl_remove_fast(struct aos_avl_node **root, struct aos_avl_node *node);

/**
 * \brieft finds value for key in tree root
 */
errval_t aos_avl_find(struct aos_avl_node *root, uint64_t key, void **value);

/**
 * \brieft finds value for key, such that found key is greater or equal, in tree root
 */
errval_t aos_avl_find_ge(struct aos_avl_node *root, uint64_t key, void **value);

/**
 * \brief change value of a node
 */
errval_t aos_avl_change_value(void *value, struct aos_avl_node *node);

/**
 * \brieft print tree
 */
errval_t aos_avl_traverse(struct aos_avl_node *root, int level);

#endif
