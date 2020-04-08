#include <aos/aos.h>
#include <aos/avl.h>

#if 0
#    define DEBUG_AVL(fmt...) debug_printf(fmt);
#else
#    define DEBUG_AVL(fmt...) ((void)0)
#endif

static errval_t aos_avl_find_parent(struct aos_avl_node *root, uint64_t key,
                                    struct aos_avl_node **parent)
{
    // FIXME: need to support this case
    assert(root != NULL);

    while (root != NULL) {
        *parent = root;
        if ((*parent)->key == key) {
            break;
        } else if ((*parent)->key < key) {
            root = (*parent)->right;
        } else {
            root = (*parent)->left;
        }
    }

    return SYS_ERR_OK;
}

errval_t aos_avl_find_ge(struct aos_avl_node *root, uint64_t key, void **value)
{
    *value = NULL;

    while (root != NULL) {
        if (root->key == key) {
            *value = root->value;
            break;
        } else if (root->key < key) {
            root = root->right;
        } else {
            assert(root->value != NULL);
            *value = root->value;
            root = root->left;
        }
    }

    if (*value == NULL) {
        return LIB_ERR_AVL_FIND_GE_NOT_FOUND;
    }

    return SYS_ERR_OK;
}

errval_t aos_avl_find_le(struct aos_avl_node *root, uint64_t key, void **value)
{
    *value = NULL;

    while (root != NULL) {
        if (root->key == key) {
            *value = root->value;
            break;
        } else if (root->key > key) {
            root = root->left;
        } else {
            assert(root->value != NULL);
            *value = root->value;
            root = root->right;
        }
    }

    if (*value == NULL) {
        return LIB_ERR_AVL_FIND_LE_NOT_FOUND;
    }

    return SYS_ERR_OK;
}

static struct aos_avl_node *aos_avl_rotate_left(struct aos_avl_node *parent,
                                                struct aos_avl_node *child)
{
    parent->right = child->left;
    if (parent->right != NULL)
        parent->right->parent = parent;

    child->left = parent;
    parent->parent = child;
    if (child->bal == 0) {
        parent->bal = 1;
        child->bal = -1;
    } else {
        parent->bal = 0;
        child->bal = 0;
    }

    return child;
}

static struct aos_avl_node *aos_avl_rotate_rightleft(struct aos_avl_node *parent,
                                                     struct aos_avl_node *child)
{
    struct aos_avl_node *child_child;
    child_child = child->left;
    child->left = child_child->right;
    if (child->left != NULL) {
        child->left->parent = child;
    }

    child_child->right = child;
    child->parent = child_child;

    parent->right = child_child->left;
    if (parent->right != NULL) {
        parent->right->parent = parent;
    }

    child_child->left = parent;
    parent->parent = child_child;

    if (child_child->bal > 0) {
        parent->bal = -1;
        child->bal = 0;
    } else {
        if (child_child->bal == 0) {
            parent->bal = 0;
            child->bal = 0;
        } else {
            parent->bal = 0;
            child->bal = 1;
        }
    }

    child_child->bal = 0;

    return child_child;
}

static struct aos_avl_node *aos_avl_rotate_right(struct aos_avl_node *parent,
                                                 struct aos_avl_node *child)
{
    parent->left = child->right;
    if (parent->left != NULL)
        parent->left->parent = parent;

    child->right = parent;
    parent->parent = child;
    if (child->bal == 0) {
        parent->bal = -1;
        child->bal = 1;
    } else {
        parent->bal = 0;
        child->bal = 0;
    }

    return child;
}

static struct aos_avl_node *aos_avl_rotate_leftright(struct aos_avl_node *parent,
                                                     struct aos_avl_node *child)
{
    struct aos_avl_node *child_child;
    child_child = child->right;
    child->right = child_child->left;
    if (child->right != NULL) {
        child->right->parent = child;
    }

    child_child->left = child;
    child->parent = child_child;

    parent->left = child_child->right;
    if (parent->left != NULL) {
        parent->left->parent = parent;
    }

    child_child->right = parent;
    parent->parent = child_child;

    if (child_child->bal < 0) {
        parent->bal = 1;
        child->bal = 0;
    } else {
        if (child_child->bal == 0) {
            parent->bal = 0;
            child->bal = 0;
        } else {
            parent->bal = 0;
            child->bal = -1;
        }
    }

    child_child->bal = 0;

    return child_child;
}


errval_t aos_avl_insert(struct aos_avl_node **root, uint64_t key, void *value,
                        struct aos_avl_node *node)
{
    errval_t err;

    assert(node != NULL);

    node->value = value;
    node->key = key;
    node->left = NULL;
    node->right = NULL;
    node->bal = 0;

    if (*root == NULL) {
        node->parent = NULL;

        *root = node;

        return SYS_ERR_OK;
    } else {
        struct aos_avl_node *parent;
        err = aos_avl_find_parent(*root, key, &parent);
        assert(err_is_ok(err));

        // TODO: handle this?
        if (parent->key == key) {
            return LIB_ERR_AVL_INSERT;
        }

        node->parent = parent;

        if (key < parent->key) {
            assert(parent->left == NULL);
            parent->left = node;
        } else {
            assert(parent->right == NULL);
            parent->right = node;
        }


        struct aos_avl_node *child = node;
        struct aos_avl_node *parent_parent;
        struct aos_avl_node *new_parent;
        for (; parent != NULL; parent = child->parent) {
            if (parent->right == child) {
                if (parent->bal > 0) {
                    parent_parent = parent->parent;
                    if (child->bal < 0) {
                        // Double rotate
                        new_parent = aos_avl_rotate_rightleft(parent, child);
                    } else {
                        // Single rotate
                        new_parent = aos_avl_rotate_left(parent, child);
                    }
                } else {
                    if (parent->bal < 0) {
                        parent->bal = 0;
                        break;
                    }

                    parent->bal = 1;
                    child = parent;
                    continue;
                }
            } else {
                if (parent->bal < 0) {
                    parent_parent = parent->parent;
                    if (child->bal > 0) {
                        new_parent = aos_avl_rotate_leftright(parent, child);
                    } else {
                        new_parent = aos_avl_rotate_right(parent, child);
                    }
                } else {
                    if (parent->bal > 0) {
                        parent->bal = 0;
                        break;
                    }

                    parent->bal = -1;
                    child = parent;
                    continue;
                }
            }

            new_parent->parent = parent_parent;
            if (parent_parent != NULL) {
                if (parent == parent_parent->left) {
                    parent_parent->left = new_parent;
                } else {
                    parent_parent->right = new_parent;
                }
            } else {
                *root = new_parent;
            }
            break;
        }

        return SYS_ERR_OK;
    }
}

errval_t aos_avl_remove(struct aos_avl_node **root, uint64_t key, void **value,
                        struct aos_avl_node **node)
{
    errval_t err;
    assert(*root != NULL);

    struct aos_avl_node *parent;
    err = aos_avl_find_parent(*root, key, &parent);
    assert(err_is_ok(err));

    assert(parent->key == key);

    *value = parent->value;

    *node = parent;

    return aos_avl_remove_fast(root, parent);
}

errval_t aos_avl_remove_fast(struct aos_avl_node **root, struct aos_avl_node *node)
{
    DEBUG_AVL("aos_avl_remove_fast begin\n");
    assert(*root != NULL);
    assert(node != NULL);
    DEBUG_AVL("aos_avl_remove_fast removing: 0x%" PRIx64 "\n", node->key);

    if (node->right != NULL && node->right != NULL) {
        // Descend, replace
        struct aos_avl_node *min = node->right;
        while (min->left != NULL) {
            min = min->left;
        }

        // Swap, so that for external observers pointers to nodes don't suddenly change
        // key/value
        struct aos_avl_node tmp = *min;
        min->left = node->left;
        if (min->left != NULL) {
            min->left->parent = min;
        }
        if (min != node->right) {
            min->right = node->right;
            if (min->right != NULL) {
                min->right->parent = min;
            }
        }
        min->bal = node->bal;
        min->parent = node->parent;

        if (node->parent != NULL) {
            if (node->parent->left == node) {
                node->parent->left = min;
            } else {
                node->parent->right = min;
            }
        } else {
            *root = min;
        }

        if (min != node->right) {
            node->parent = tmp.parent;
        } else {
            node->parent = min;
        }

        node->left = tmp.left;
        if (node->left != NULL) {
            tmp.left->parent = node;
        }
        node->right = tmp.right;
        if (node->right != NULL) {
            tmp.right->parent = node;
        }

        if (node->parent->left == min) {
            node->parent->left = node;
        } else {
            node->parent->right = node;
        }

        assert(min->parent != min);
        assert(node->parent != node);
    }

    struct aos_avl_node *child = node;
    struct aos_avl_node *parent = child->parent;
    struct aos_avl_node *parent_parent;
    char tmp_bal;
    for (; parent != NULL; parent = parent_parent) {
        parent_parent = parent->parent;

        assert(parent->left == child || parent->right == child);

        if (parent->left == child) {
            if (parent->bal > 0) {
                assert(parent->right != NULL);
                tmp_bal = parent->right->bal;
                if (parent->right->bal < 0) {
                    child = aos_avl_rotate_rightleft(parent, parent->right);
                } else {
                    child = aos_avl_rotate_left(parent, parent->right);
                }
            } else {
                if (parent->bal == 0) {
                    parent->bal = 1;
                    break;
                } else {
                    parent->bal = 0;
                    child = parent;
                    continue;
                }
            }
        } else {
            assert(parent->right != NULL);
            if (parent->bal < 0) {
                assert(parent->left != NULL);
                tmp_bal = parent->left->bal;
                if (parent->left->bal > 0) {
                    child = aos_avl_rotate_leftright(parent, parent->left);
                } else {
                    child = aos_avl_rotate_right(parent, parent->left);
                }
            } else {
                if (parent->bal == 0) {
                    parent->bal = -1;
                    break;
                } else {
                    parent->bal = 0;
                    child = parent;
                    continue;
                }
            }
        }

        child->parent = parent_parent;
        if (parent_parent != NULL) {
            if (parent == parent_parent->left) {
                parent_parent->left = child;
            } else {
                parent_parent->right = child;
            }
            if (tmp_bal == 0)
                break;
        } else {
            *root = child;
        }
    }

    // No more then two children
    struct aos_avl_node *new_child = NULL;
    if (node->right != NULL) {
        new_child = node->right;
    } else if (node->left != NULL) {
        new_child = node->left;
    }
    if (new_child != NULL) {
        new_child->parent = node->parent;
    }

    if (node->parent == NULL) {
        *root = new_child;
        return SYS_ERR_OK;
    } else {
        if (node->parent->right == node) {
            node->parent->right = new_child;
        } else {
            node->parent->left = new_child;
        }
    }

    DEBUG_AVL("aos_avl_remove_fast end\n");

    return SYS_ERR_OK;
}

errval_t aos_avl_find(struct aos_avl_node *root, uint64_t key, void **value)
{
    errval_t err;
    // Empty tree
    if (root == NULL) {
        return LIB_ERR_AVL_FIND_NOT_FOUND;
    }

    struct aos_avl_node *parent;
    err = aos_avl_find_parent(root, key, &parent);
    assert(err_is_ok(err));

    if (parent == NULL || parent->key != key) {
        return LIB_ERR_AVL_FIND_NOT_FOUND;
    }

    *value = parent->value;

    return SYS_ERR_OK;
}

size_t aos_avl_size(struct aos_avl_node *root)
{
    size_t i = 1;
    if (root->left != NULL) {
        i += aos_avl_size(root->left);
    }
    if (root->right != NULL) {
        i += aos_avl_size(root->right);
    }

    return i;
}

errval_t aos_avl_traverse(struct aos_avl_node *root, int level)
{
    if (root->parent != NULL) {
        debug_printf("key: 0x%" PRIx64 ", balance: %hhd, level: %d, parent: 0x%" PRIx64
                     "\n",
                     root->key, root->bal, level, root->parent->key);
    } else {
        debug_printf("key: 0x%" PRIx64 ", balance: %hhd, level: %d, parent: -\n",
                     root->key, root->bal, level);
    }
    if (root->left != NULL) {
        aos_avl_traverse(root->left, level + 1);
    }
    if (root->right != NULL) {
        aos_avl_traverse(root->right, level + 1);
    }

    return SYS_ERR_OK;
}

errval_t aos_avl_change_value(void *value, struct aos_avl_node *node)
{
    node->value = value;

    return SYS_ERR_OK;
}
