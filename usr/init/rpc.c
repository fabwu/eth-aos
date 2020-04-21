/**
 * \file
 * \brief init rpc
 */

#include "rpc.h"
#include "process.h"
#include <aos/lmp_protocol.h>
#include <machine/atomic.h>

#if 0
#    define DEBUG_RPC_SETUP(fmt...) debug_printf(fmt);
#else
#    define DEBUG_RPC_SETUP(fmt...) ((void)0)
#endif

/**
 * Receives a number.
 */
static errval_t rpc_print_number(uintptr_t number)
{
    // has to be called for grading see chapter 5.10
    grading_rpc_handle_number(number);

    return SYS_ERR_OK;
}

/**
 * Receives a string.
 */
static errval_t rpc_print_string(struct lmp_chan *chan, struct lmp_recv_msg *lookahead)
{
    char *string;
    errval_t err = lmp_protocol_recv_string_cap_la(chan, AOS_RPC_SEND_STRING, NULL,
                                                   &string, lookahead);
    if (err_is_fail(err)) {
        return err;
    }

    // has to be called for grading see chapter 5.10
    grading_rpc_handler_string(string);

    free(string);
    return SYS_ERR_OK;
}

/**
 * Allocates ram, sends capability to child.
 */
static errval_t rpc_send_ram(struct lmp_chan *chan, size_t size, size_t alignment)
{
    errval_t err;

    // has to be called for grading see chapter 5.10
    grading_rpc_handler_ram_cap(size, alignment);

    struct capref ram_cap;
    err = slot_alloc(&ram_cap);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_SLOT_ALLOC);
        goto out;
    }

    err = ram_alloc_aligned(&ram_cap, size, alignment);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_RAM_ALLOC_ALIGNED);
        goto out;
    }

out:
    if (err_is_ok(err)) {
        lmp_protocol_send_cap3(chan, AOS_RPC_GET_RAM_CAP, ram_cap, size, alignment, true);

        // we have to destroy cap here otw. child cannot free ram later
        err = cap_destroy(ram_cap);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_DESTROY);
        }

        return SYS_ERR_OK;
    } else {
        lmp_protocol_send_cap3(chan, AOS_RPC_GET_RAM_CAP, NULL_CAP, 0, alignment, false);
        return err;
    }
}

/**
 * Frees ram at given physical address.
 */
// FIXME: Add mechanism so processes can only free their only ram, why we can't get the
// capability here is because of fram_free
static errval_t rpc_free_ram(struct lmp_chan *chan, genpaddr_t addr)
{
    errval_t err;

    err = ram_free(addr);
    if (err_is_ok(err)) {
        lmp_protocol_send2(chan, AOS_RPC_FREE_RAM_CAP, addr, true);
        return SYS_ERR_OK;
    } else {
        lmp_protocol_send2(chan, AOS_RPC_FREE_RAM_CAP, 0, false);
        return err_push(err, LIB_ERR_RAM_FREE);
    }
}

/**
 * Receives a char from the serial line.
 */
static errval_t rpc_serial_getchar(void)
{
    // just call the grading function
    //
    // we didn't go for the extra challenge
    grading_rpc_handler_serial_getchar();

    return SYS_ERR_OK;
}

/**
 * Puts a char on the serial line.
 */
// FIXME: Add line buffer, so the output of different processes does not get mixed and
// sys_print() only gets called once per line.
static errval_t rpc_serial_putchar(uintptr_t arg1)
{
    char c = (char)arg1;

    // XXX Here we would call serial_put_char or similar
    char str[2];
    str[0] = c;
    str[1] = '\0';

    sys_print(str, 2);

    grading_rpc_handler_serial_putchar(c);

    return SYS_ERR_OK;
}

struct urpc_data *urpc_frame_core1;

/**
 * Spawns process.
 */
__attribute__((unused)) static errval_t rpc_spawn_process(struct lmp_chan *chan) {
    errval_t err = SYS_ERR_OK;
    struct spawninfo *si = NULL;
    domainid_t pid;

    char *cmdline = NULL;
    err = lmp_protocol_recv_string(chan, AOS_RPC_PROCESS_SPAWN_CMD, &cmdline);
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

    uintptr_t coreid_recv;
    err = lmp_protocol_recv1(chan, AOS_RPC_PROCESS_SPAWN_CORE, &coreid_recv);
    if (err_is_fail(err)) {
        err = AOS_ERR_RPC_SPAWN_PROCESS;
        goto out;
    }
    coreid_t coreid = (coreid_t)coreid_recv;

    grading_rpc_handler_process_spawn(argv[0], coreid);

    if (coreid == 0) {
        si = (struct spawninfo *)malloc(sizeof(struct spawninfo));
        if (si == NULL) {
            err = INIT_ERR_PREPARE_SPAWN;
            goto out;
        }

        err = rpc_create_child_channel_to_init(&si->initep, NULL);
        if (err_is_fail(err)) {
            err = err_push(err, INIT_ERR_PREPARE_SPAWN);
            goto out;
        }

        err = spawn_load_by_name_argv(argv[0], argc, argv, si, &pid);
        if (err_is_fail(err)) {
            err = err_push(err, INIT_ERR_SPAWN);
            goto out;
        }
    } else {
        assert(coreid == 1);
        struct urpc_data *urpc = urpc_frame_core1;

        size_t cmd_len = strlen(cmdline);
        if (cmd_len > URPC_MAX_MSG_LEN - 1) {
            err = INIT_ERR_SPAWN_CMD_TOO_LONG;
            goto out;
        }

        DEBUG_PRINTF("passing command '%s' to core %u in URPC frame...\n", cmdline, coreid);
        memcpy((void *)urpc->msg, cmdline, cmd_len);
        urpc->msg[cmd_len] = '\0';
        // ensure msg is written before flag is written
        dmb(sy);
        urpc->flag = 1;

        // wait for response
        DEBUG_PRINTF("waiting for reply from core %u...\n", coreid);
        while (urpc->flag);

        // ensure flag is read before ret is read
        dmb(sy);
        err = urpc->err;
        DEBUG_PRINTF("received reply %u from core %u in URPC frame\n", err, coreid);
        if (err_is_fail(err)) {
            return err_push(err, INIT_ERR_SPAWN_URPC);
            goto out;
        }

        // TODO get PID
        pid = 1;
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

/**
 * Handles messages from different child channels
 */
static void rpc_handler_recv_closure(void *arg)
{
    errval_t err;
    struct dispatcher_node *node = (struct dispatcher_node *)arg;
    struct lmp_chan *chan = &node->chan;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(chan, &msg, &cap);

    DEBUG_RPC_SETUP("rpc_handler_recv_closure called!\n");

    if (err_is_ok(err)) {
        if (!capref_is_null(cap)) {
            lmp_chan_alloc_recv_slot(chan);
        }
        uintptr_t message_type = msg.words[0];
        switch (message_type) {
        case AOS_RPC_SEND_NUMBER:
            rpc_print_number(msg.words[1]);
            break;
        case AOS_RPC_SEND_STRING:
            rpc_print_string(chan, &msg);
            break;
        case AOS_RPC_GET_RAM_CAP:
            err = rpc_send_ram(chan, msg.words[1], msg.words[2]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "rpc_send_ram failed");
            }
            break;
        case AOS_RPC_FREE_RAM_CAP:
            err = rpc_free_ram(chan, msg.words[1]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "rpc_free_ram failed");
            }
            break;
        case AOS_RPC_SERIAL_GETCHAR:
            err = rpc_serial_getchar();
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "rpc_serial_getchar failed");
            }
            break;
         case AOS_RPC_SERIAL_PUTCHAR:
            err = rpc_serial_putchar(msg.words[1]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "rpc_serial_putchar failed");
            }
            break;
        case AOS_RPC_PROCESS_SPAWN:
            err = process_spawn_rpc(chan);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to spawn process in rpc_spawn_process()");
            }
            break;
        case AOS_RPC_PROCESS_GET_ALL_PIDS:
            err = process_get_all_pids_rpc(chan);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed in rpc_get_all_pids()");
            }
            break;
        case AOS_RPC_PROCESS_GET_NAME:
            err = process_get_name_rpc(chan, (domainid_t)msg.words[1]);
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
            debug_printf("Unknown request: %" PRIu64 "\n", msg.words[0]);
        }

        // Want to receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(rpc_handler_recv_closure, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

        DEBUG_RPC_SETUP("rpc_handler_recv_closure success!\n");

        return;
    } else if (lmp_err_is_transient(err)) {
        // Want to receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(rpc_handler_recv_closure, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

        DEBUG_RPC_SETUP("rpc_handler_recv_closure retry!\n");

        return;
    }

fail:
    DEBUG_ERR(err, "rpc_handler_recv_closure failed hard");
}

/**
 * Receives a child endpoint cap, saves it in the channel and notify the child
 * that channel is ready.
 */
static void rpc_setup_recv_closure(void *arg)
{
    errval_t err;

    struct dispatcher_node *node = (struct dispatcher_node *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(&node->chan, &msg, &cap);

    DEBUG_RPC_SETUP("rpc_setup_recv_closure called!\n");

    // Got message
    if (err_is_ok(err)) {
        // Check if setup message
        assert(msg.words[0] == AOS_RPC_SETUP);

        node->chan.remote_cap = cap;
        node->state = DISPATCHER_CONNECTED;

        err = lmp_chan_alloc_recv_slot(&node->chan);
        if (err_is_fail(err)) {
            goto fail;
        }

        DEBUG_RPC_SETUP("rpc_setup_recv_closure success!\n");

        err = lmp_protocol_send0(&node->chan, AOS_RPC_SETUP);
        if (err_is_fail(err)) {
            goto fail;
        }

        // Channel to child is setup, switch to child handler
        err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                     MKCLOSURE(rpc_handler_recv_closure, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

        return;
    } else if (lmp_err_is_transient(err)) {
        DEBUG_RPC_SETUP("rpc_setup_recv_closure retry!\n");

        // Want to receive further messages
        err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                     MKCLOSURE(rpc_setup_recv_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

fail:
    // FIXME: Handle error case better
    DEBUG_ERR(err, "rpc_setup_recv_closure failed hard!\n");
}

/**
 * Creates a unique channel to a child (to be spawned)
 */
errval_t rpc_create_child_channel_to_init(struct capref *ret_init_ep_cap, dispatcher_node_ref *node_ref)
{
    errval_t err = SYS_ERR_OK;

    assert(ret_init_ep_cap != NULL);
    struct lmp_state *st = get_current_lmp_state();
    assert(st != NULL);

    struct dispatcher_node *node = slab_alloc(&st->slabs);
    if (node == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    node->state = DISPATCHER_DISCONNECTED;
    lmp_chan_init(&node->chan);

    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &node->chan.local_cap, &node->chan.endpoint);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_ENDPOINT_CREATE);
        goto out;
    }

    // Preallocate first receive slot
    // lmp_protocol will preallocate new slots when the current slot is used up
    err = lmp_chan_alloc_recv_slot(&node->chan);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_CHAN_ALLOC_RECV_SLOT);
        goto out;
    }

    // Needs to be non-blocking, so lmp_protocol is not used here
    err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                 MKCLOSURE(rpc_setup_recv_closure, node));
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
        goto out;
    }

    // Add node to dispatcher list
    // Done as late as possible so there's no unfinished node in the list
    node->next = st->head;
    st->head = node;

    assert(!capref_is_null(node->chan.local_cap));
    *ret_init_ep_cap = node->chan.local_cap;
    if (node_ref != NULL) {
        *node_ref = (dispatcher_node_ref)node;
    }

out:
    if (err_is_fail(err)) {
        if (!capref_is_null(node->chan.endpoint->recv_slot)) {
            cap_destroy(node->chan.endpoint->recv_slot);
        }
        lmp_chan_destroy(&node->chan);
        slab_free(&st->slabs, node);
    }
    return err;
}

void rpc_dispatcher_node_set_pid(dispatcher_node_ref node_ref, domainid_t pid)
{
    struct dispatcher_node *node = (struct dispatcher_node *)node_ref;
    node->pid = pid;
}

errval_t rpc_initialize_lmp(struct lmp_state *st)
{
    errval_t err;
    st->head = NULL;
    slab_init(&st->slabs, sizeof(struct dispatcher_node), slab_default_refill);
    err = slab_default_refill(&st->slabs);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLAB_REFILL);
    }

    // init doesn't get a cap_selfep
    err = cap_retype(cap_selfep, cap_dispatcher, 0, ObjType_EndPointLMP, 0, 1);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    set_current_lmp_state(st);

    return SYS_ERR_OK;
}

