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

void process_handle_lmp_request(uintptr_t message_type, struct lmp_recv_msg *msg,
                                struct dispatcher_node *node)
{
    errval_t err;
    if (disp_get_core_id() == INIT_PROCESS_PIN_TO_CORE) {
        struct aos_chan chan = make_aos_chan_lmp(&node->chan);

        switch (message_type) {
        case AOS_RPC_PROCESS_SPAWN:
            err = process_spawn_rpc(&chan, (coreid_t)msg->words[1]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to spawn process in rpc_spawn_process()");
            }
            break;
        case AOS_RPC_PROCESS_GET_ALL_PIDS:
            err = process_get_all_pids_rpc(&chan);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed in rpc_get_all_pids()");
            }
            break;
        case AOS_RPC_PROCESS_GET_NAME:
            err = process_get_name_rpc(&chan, (domainid_t)msg->words[1]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed in rpc_process_get_name()");
            }
            break;
        case AOS_RPC_PROCESS_EXIT:
            err = process_exit(node->pid);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed in rpc_process_exit()");
            }
            break;
        default:
            debug_printf("Unknown request: %" PRIu64 "\n", message_type);
        }
    } else {
        struct aos_chan chan;
        switch (message_type) {
        case AOS_RPC_PROCESS_SPAWN:
            debug_printf("We don't support spawning on core 0 from core 1\n",
                         message_type);
            break;
        case AOS_RPC_PROCESS_GET_ALL_PIDS:
        case AOS_RPC_PROCESS_GET_NAME:
        case AOS_RPC_PROCESS_EXIT:
            chan = make_aos_chan_ump(node->pid, 0);
            aos_protocol_send(&chan, message_type, NULL_CAP, msg->words[1], msg->words[2], msg->words[3]);
            break;
        }
    }
}

static errval_t process_spawn_remote(struct aos_chan *chan, size_t msg_length) {
    errval_t err = SYS_ERR_OK;
    struct spawninfo *si = NULL;
    domainid_t pid;

    char *cmdline;
    err = aos_protocol_recv_string(chan, AOS_RPC_PROCESS_SPAWN_REMOTE_CMD, &cmdline);
    if (err_is_fail(err)) {
        return err;
    }

    int argc;
    char *buf;
    char **argv = make_argv(cmdline, &argc, &buf);
    if (argc < 1 || argv == NULL) {
        err = AOS_ERR_RPC_SPAWN_PROCESS;
        goto out;
    }

    grading_rpc_handler_process_spawn(argv[0], disp_get_core_id());

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

    err = spawn_load_by_name_argv(argv[0], argc, argv, si, &pid);
    if (err_is_fail(err)) {
        err = err_push(err, INIT_ERR_SPAWN);
        goto out;
    }

    rpc_dispatcher_node_set_pid(node_ref, pid);
out:
    if (si != NULL) {
        free(si);
    }
    if (argv != NULL) {
        free_argv(argv, buf);
    }
    if (cmdline != NULL) {
        free(cmdline);
    }

    if (err_is_fail(err)) {
        errval_t inner_err = aos_protocol_send2(chan, AOS_RPC_PROCESS_SPAWN_REMOTE, 0, false);
        if (err_is_fail(inner_err)) {
            DEBUG_ERR(inner_err, "Could not report failed process spawn");
        }
    } else {
        err = aos_protocol_send2(chan, AOS_RPC_PROCESS_SPAWN_REMOTE, pid, true);
        if (err_is_fail(err)) {
            err = err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
        }
    }

    return err;
}


void process_handle_ump_request(uintptr_t message_type, uint8_t *buf)
{
    errval_t err;

    domainid_t remote_pid = (domainid_t)(((uint64_t *)buf)[0] >> 32);
    domainid_t local_pid = (domainid_t)((uint64_t *)buf)[0];

    struct aos_chan chan;
    if (disp_get_core_id() == INIT_PROCESS_PIN_TO_CORE) {
        chan = make_aos_chan_ump(local_pid, remote_pid);

        switch (message_type) {
        case AOS_RPC_PROCESS_SPAWN:
            err = process_spawn_rpc(&chan, ((uint64_t *)buf)[2]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to spawn process in rpc_spawn_process()");
            }
            break;
        case AOS_RPC_PROCESS_GET_ALL_PIDS:
            err = process_get_all_pids_rpc(&chan);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed in rpc_get_all_pids()");
            }
            break;
        case AOS_RPC_PROCESS_GET_NAME:
            err = process_get_name_rpc(&chan, ((uint64_t *)buf)[2]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed in rpc_process_get_name()");
            }
            break;
        case AOS_RPC_PROCESS_EXIT:
            err = process_exit(remote_pid);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed in rpc_process_exit()");
            }
            break;
        case AOS_RPC_PROCESS_SPAWN_REMOTE:
            DEBUG_PRINTF("Remote spawning on core 0 is not implemented\n");
            break;
        default:
            debug_printf("Unknown request: %" PRIu64 "\n", message_type);
        }
    } else {
        if (message_type == AOS_RPC_PROCESS_SPAWN_REMOTE) {
            DEBUG_PRINTF("Request for spawn on core 1\n");
            chan = make_aos_chan_ump(local_pid, remote_pid);
            process_spawn_remote(&chan, (size_t)((uint64_t *)buf)[2]);
            return;
        }
        // Could also be response!
        DEBUG_PRINTF("remote: %d local %d\n", remote_pid, local_pid);
        if (message_type == AOS_RPC_PROCESS_SPAWN) {
            // TODO
        } else {
            // Got UMP request on core 1, but those should only be sent to core 0
            DEBUG_PRINTF("UMP request for process could not be handled by core %d\n", disp_get_core_id());
        }
    }
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

errval_t process_spawn_rpc(struct aos_chan *chan, coreid_t core_id)
{
    errval_t err = SYS_ERR_OK;
    struct spawninfo *si = NULL;
    domainid_t pid;

    char *cmdline;
    err = aos_protocol_recv_string(chan, AOS_RPC_PROCESS_SPAWN_CMD, &cmdline);
    if (err_is_fail(err)) {
        return err;
    }

    int argc;
    char *buf;
    char **argv = make_argv(cmdline, &argc, &buf);
    if (argc < 1 || argv == NULL) {
        err = AOS_ERR_RPC_SPAWN_PROCESS;
        goto out;
    }

    grading_rpc_handler_process_spawn(argv[0], core_id);

    if (core_id == disp_get_core_id()) {
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

        err = spawn_load_by_name_argv(argv[0], argc, argv, si, &pid);
        if (err_is_fail(err)) {
            err = err_push(err, INIT_ERR_SPAWN);
            goto out;
        }

        rpc_dispatcher_node_set_pid(node_ref, pid);
    } else {
        size_t cmd_len = strlen(cmdline) + 1;

        DEBUG_PRINTF("Passing command '%s' to core %u in URPC frame...\n", cmdline,
                     core_id);

        struct aos_chan remote_chan = make_aos_chan_ump(0, 0);
        err = aos_protocol_send1(&remote_chan, AOS_RPC_PROCESS_SPAWN_REMOTE, cmd_len);
        if (err_is_fail(err)) {
            return err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
        }

        // Send commandline that should be used to spawn process
        err = aos_protocol_send_string(&remote_chan, AOS_RPC_PROCESS_SPAWN_REMOTE_CMD, cmdline);
        if (err_is_fail(err)) {
            return err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
        }

        // Get pid and success information
        uintptr_t ret_pid = 0;
        uintptr_t ret_success = 0;
        err = aos_protocol_recv2(&remote_chan, AOS_RPC_PROCESS_SPAWN_REMOTE, &ret_pid, &ret_success);
        if (err_is_fail(err)) {
            return err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
        } else if (!ret_success) {
            return AOS_ERR_RPC_SPAWN_PROCESS;
        }

        // Not passing newpid directly because of mismatching types
        pid = ret_pid;

        DEBUG_PRINTF("Received ump reply from core %u: Spawned pid %d\n", core_id, pid);
    }

    err = process_add(pid, core_id, argv[0]);
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
    if (cmdline != NULL) {
        free(cmdline);
    }

    if (err_is_fail(err)) {
        errval_t inner_err = aos_protocol_send2(chan, AOS_RPC_PROCESS_SPAWN, 0, false);
        if (err_is_fail(inner_err)) {
            DEBUG_ERR(inner_err, "Could not report failed process spawn");
        }
    } else {
        err = aos_protocol_send2(chan, AOS_RPC_PROCESS_SPAWN, pid, true);
        if (err_is_fail(err)) {
            err = err_push(err, AOS_ERR_RPC_SPAWN_PROCESS);
        }
    }

    return err;
}

errval_t process_exit(domainid_t pid)
{
    DEBUG_PRINTF("Removing process %d from process management\n", pid);
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

errval_t process_get_all_pids_rpc(struct aos_chan *chan)
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

    errval_t err = aos_protocol_send_bytes(chan, AOS_RPC_PROCESS_GET_ALL_PIDS,
                                           state.node_count * sizeof(domainid_t),
                                           (uint8_t *)pids);

    free(pids);

    return err;
}

errval_t process_get_name_rpc(struct aos_chan *chan, domainid_t pid)
{
    errval_t err;
    grading_rpc_handler_process_get_name(pid);

    struct process_node *node, *parent;
    if (!process_find_node(pid, &node, &parent)) {
        DEBUG_PRINTF("Trying to access unkown process with pid: 0x%x\n", pid);
        return aos_protocol_send1(chan, AOS_RPC_PROCESS_GET_NAME, false);
    } else {
        err = aos_protocol_send1(chan, AOS_RPC_PROCESS_GET_NAME, true);
        if (err_is_fail(err)) {
            return err;
        }

        return aos_protocol_send_string(chan, AOS_RPC_PROCESS_GET_NAME_STR, node->name);
    }
}
