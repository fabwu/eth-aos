#include "spawn.h"
#include "rpc.h"

struct spawn_node *head;

static errval_t prepare_spawn(struct spawn_node **ret_node) {
    errval_t err;

    struct spawn_node *node = (struct spawn_node *)malloc(sizeof(struct spawn_node));
    if (node == NULL) {
        return INIT_ERR_PREPARE_SPAWN;
    }

    err = rpc_create_child_channel_to_init(&node->client_chan);
    if (err_is_fail(err)) {
        return err_push(err, INIT_ERR_PREPARE_SPAWN);
    }
    node->si.init_client_ep = node->client_chan.local_cap;

    err = rpc_create_child_channel_to_init(&node->server_chan);
    if (err_is_fail(err)) {
        return err_push(err, INIT_ERR_PREPARE_SPAWN);
    }
    node->si.init_server_ep = node->server_chan.local_cap;

    *ret_node = node;

    return SYS_ERR_OK;
}

static errval_t finish_spawn(struct spawn_node *node, domainid_t *pid)
{
    // add spawn info to linked list
    node->next = head;
    head = node;

    node->client_chan.did = node->pid;
    node->server_chan.did = node->pid;

    if(pid != NULL) {
        *pid = node->pid;
    }

    return SYS_ERR_OK;
}

errval_t init_spawn_by_name(char *name, domainid_t *pid)
{
    errval_t err;

    struct spawn_node *node;
    err = prepare_spawn(&node);
    if(err_is_fail(err)) {
         goto err;
    }

    err = spawn_load_by_name(name, &node->si, &node->pid);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_SPAWN);
        goto err;
    }

    err = finish_spawn(node, pid);
    if(err_is_fail(err)) {
        goto err;
    }

    return SYS_ERR_OK;

err:
    free(node);
    return err;
}

errval_t init_spawn_by_argv(int argc, char *argv[], domainid_t *pid)
{
    errval_t err;

    struct spawn_node *node;
    err = prepare_spawn(&node);
    if(err_is_fail(err)) {
         goto err;
    }

    err = spawn_load_by_argv(argc, argv, &node->si, &node->pid);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_SPAWN);
        goto err;
    }

    err = finish_spawn(node, pid);
    if(err_is_fail(err)) {
        goto err;
    }

    return SYS_ERR_OK;

err:
    free(node);
    return err;
}

void init_spawn_get_lmp_chan(domainid_t pid, struct lmp_chan **chan) {
    struct spawn_node *current = head;

    while(current != NULL) {
        if(current->pid == pid) {
            *chan = &current->client_chan;
            return;
        }
        current = current->next;
    }

    *chan = NULL;
    return;
}
