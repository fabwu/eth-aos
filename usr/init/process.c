#include "process.h"
#include "rpc.h"

static struct process_state state;

static bool process_find_node(domainid_t pid, struct process_node **node,
                      struct process_node **parent)
{
    *parent = NULL;
    *node = state.head;
    while (*node != NULL && (*node)->pid != pid) {
        *parent = *node;
        *node = (*node)->next;
    }

    return *node != NULL && (*node)->pid == pid;
}

void process_init(void)
{
    slab_init(&state.slabs, sizeof(struct process_node), slab_default_refill);
    state.head = NULL;
    state.node_count = 0;
}

errval_t process_add(domainid_t pid, coreid_t core_id, char *name)
{
    struct process_node *node = (struct process_node *)slab_alloc(&state.slabs);
    if (node == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    node->pid = pid;
    node->core_id = core_id;
    strncpy(node->name, name, DISP_NAME_LEN);

    node->next = state.head;
    state.head = node;
    state.node_count += 1;

    return SYS_ERR_OK;
}

errval_t process_spawn_rpc(struct lmp_chan *chan) {
    errval_t err = SYS_ERR_OK;
    struct spawninfo *si = NULL;

    // FIXME: Pass core id
    char *cmdline;
    err = lmp_protocol_recv_string(chan, AOS_RPC_PROCESS_SPAWN_CMD, &cmdline);
    if (err_is_fail(err)) {
        return err;
    }

    int argc;
    char *buf;
    char **argv = make_argv(cmdline, &argc, &buf);
    free(cmdline);
    if (argc < 1 || argv == NULL) {
        err = AOS_ERR_RPC_SPAWN_PROCESS;
        goto out;
    }

    grading_rpc_handler_process_spawn(argv[0], disp_get_core_id()); // FIXME core id

    si = (struct spawninfo *)malloc(sizeof(struct spawninfo));
    if (si == NULL) {
        err = INIT_ERR_PREPARE_SPAWN;
        goto out;
    }

    dispatcher_node_ref node_ref;
    err = rpc_create_child_channel_to_init(&si->initep, &node_ref);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_PREPARE_SPAWN);
        goto out;
    }

    domainid_t pid;
    err = spawn_load_by_name_argv(argv[0], argc, argv, si, &pid);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_SPAWN);
        goto out;
    }

    rpc_dispatcher_node_set_pid(node_ref, pid);

    // FIXME: Add core_id here
    err = process_add(pid, 0, argv[0]);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_SPAWN);
        goto out;
    }

out:
    if (si != NULL) {
        free(si);
    }
    if (argv != NULL) {
        free_argv(argv, buf);
    }

    if (err_is_fail(err)) {
        errval_t inner_err = lmp_protocol_send2(chan, AOS_RPC_PROCESS_SPAWN, 0, false);
        if (err_is_fail(inner_err)) {
            DEBUG_ERR(inner_err, "Could not report failed process spawn");
        }
    } else {
        err = lmp_protocol_send2(chan, AOS_RPC_PROCESS_SPAWN, pid, true);
        if (err_is_fail(err)) {
            err = err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
        }
    }

    return err;
}

errval_t process_exit(domainid_t pid)
{
    struct process_node *node, *parent;
    if (!process_find_node(pid, &node, &parent)) {
        DEBUG_PRINTF("Trying to remove unkown process with pid: 0x%x\n", pid);
        return INIT_ERR_PROCESS_NOT_FOUND;
    }

    if (parent != NULL) {
        parent->next = node->next;
    }
    if (node == state.head) {
        state.head = node->next;
    }
    state.node_count -= 1;
    slab_free(&state.slabs, node);
    return SYS_ERR_OK;
}

errval_t process_get_all_pids_rpc(struct lmp_chan *chan)
{
    grading_rpc_handler_process_get_all_pids();

    // To prevent problems with beeing reentrant pids are copied to an array before being sent
    domainid_t *pids = malloc(state.node_count * sizeof(domainid_t));
    if (pids == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    struct process_node *node = state.head;
    for (size_t i = 0; node != NULL; ++i) {
        pids[i] = node->pid;
        node = node->next;
    }

    errval_t err = lmp_protocol_send_bytes(chan, AOS_RPC_PROCESS_GET_ALL_PIDS,
                                           state.node_count * sizeof(domainid_t),
                                           (uint8_t *)pids);

    free(pids);

    return err;
}

errval_t process_get_name_rpc(struct lmp_chan *chan, domainid_t pid)
{
    grading_rpc_handler_process_get_name(pid);

    struct process_node *node, *parent;
    if (!process_find_node(pid, &node, &parent)) {
        DEBUG_PRINTF("Trying to access unkown process with pid: 0x%x\n", pid);
        return INIT_ERR_PROCESS_NOT_FOUND;
    }

    return lmp_protocol_send_string(chan, AOS_RPC_PROCESS_GET_NAME, node->name);
}