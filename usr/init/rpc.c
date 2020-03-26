/**
 * \file
 * \brief init rpc
 */

#include "rpc.h"

#define DEBUG_RPC_SETUP 0

static void rpc_handler_send_closure(void *arg)
{
    errval_t err;
    struct lmp_msg_holder *holder = (struct lmp_msg_holder *)arg;
    // Bump child that this channel is now ready
    err = lmp_chan_send4(holder->chan, LMP_SEND_FLAGS_DEFAULT, holder->cap,
                         holder->words[0], holder->words[1], holder->words[2],
                         holder->words[3]);

#if DEBUG_RPC_SETUP
    debug_printf("rpc_handler_send_closure called!\n");
#endif

    if (err_is_ok(err)) {
#if DEBUG_RPC_SETUP
        debug_printf("rpc_handler_send_closure success!\n");
#endif
        free(holder);

        return;
    } else if (lmp_err_is_transient(err)) {
#if DEBUG_RPC_SETUP
        debug_printf("rpc_handler_send_closure retry!\n");
#endif
        // Want to receive further messages
        err = lmp_chan_register_send(holder->chan, get_default_waitset(),
                                     MKCLOSURE(rpc_handler_send_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

    DEBUG_ERR(err, "rpc_handler_send_closure failed hard!\n");
}

/**
 * Receives a number
 * msg.words[0] == AOS_RPC_MSG_SEND_NUMBER
 * msg.words[1] == number
 * msg.words[2] == not used
 * msg.words[3] == not used
 */
static errval_t rpc_print_number(uintptr_t number)
{
    // has to be called for grading see chapter 5.10
    grading_rpc_handle_number(number);

    return SYS_ERR_OK;
}

/**
 * Receives a string
 * msg.words[0] == AOS_RPC_MSG_SEND_STRING
 * msg.words[1] == buffer 1
 * msg.words[2] == buffer 2
 * msg.words[3] == buffer 3
 */
static errval_t rpc_print_string(uintptr_t *buf)
{
    char string[AOS_RPC_BUFFER_SIZE];

    memcpy(string, buf, AOS_RPC_BUFFER_SIZE);

    // has to be called for grading see chapter 5.10
    grading_rpc_handler_string(string);

    return SYS_ERR_OK;
}

/**
 * Allocates ram, sends capability to child
 * msg.words[0] == AOS_RPC_MSG_GET_RAM_CAP
 * msg.words[1] == size
 * msg.words[2] == alignment
 * msg.words[3] == success
 */
static errval_t rpc_send_ram(struct lmp_chan *chan, size_t size, size_t alignment)
{
    errval_t err = SYS_ERR_OK;

    // has to be called for grading see chapter 5.10
    grading_rpc_handler_ram_cap(size, alignment);

    struct lmp_msg_holder *holder = (struct lmp_msg_holder *)malloc(
        sizeof(struct lmp_msg_holder));
    if (holder == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    holder->cap = NULL_CAP;
    holder->words[0] = 1;
    holder->words[1] = size;
    holder->words[2] = alignment;
    holder->words[3] = 0;
    holder->chan = chan;

    struct capref ram_cap;
    err = slot_alloc(&ram_cap);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = ram_alloc_aligned(&ram_cap, size, alignment);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_RAM_ALLOC_ALIGNED);
    } else {
        holder->cap = ram_cap;
        holder->words[3] = 1;
    }

    rpc_handler_send_closure(holder);

    return err;
}

/**
 * Allocates ram, sends capability to child
 * msg.words[0] == AOS_RPC_MSG_GET_RAM_CAP
 * msg.words[1] == size
 * msg.words[2] == alignment
 * msg.words[3] == success
 */
// FIXME: Add mechanism so processes can only free their only ram, why we can't get the
// capability here is because of fram_free
static errval_t rpc_free_ram(struct lmp_chan *chan, genpaddr_t addr)
{
    errval_t err = SYS_ERR_OK;

    struct lmp_msg_holder *holder = (struct lmp_msg_holder *)malloc(
        sizeof(struct lmp_msg_holder));
    if (holder == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    holder->cap = NULL_CAP;
    holder->words[0] = 1;
    holder->words[1] = addr;
    holder->words[2] = 0;
    holder->chan = chan;

    err = ram_free(addr);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_RAM_FREE);
    } else {
        holder->words[2] = 1;
    }

    rpc_handler_send_closure(holder);

    return err;
}

/**
 * Receives a char from the serial line
 * msg.words[0] == AOS_RPC_MSG_SERIAL_PUTCHAR
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
 * Puts a char on the serial line
 * msg.words[0] == AOS_RPC_MSG_SERIAL_PUTCHAR
 * msg.words[1] == character
 */
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

/**
 * Spawns process
 * msg.words[0] == AOS_RPC_MSG_PROCESS_SPAWN
 * msg.words[1] == pid
 * msg.words[2] == success
 */
// TODO: Transfer string
static void rpc_spawn_process(struct lmp_chan *chan, char *name) {}

/**
 * Handles messages from different child channels
 */
static void rpc_handler_recv_closure(void *arg)
{
    errval_t err;
    struct lmp_chan *chan = (struct lmp_chan *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(chan, &msg, &cap);
#if DEBUG_RPC_SETUP
    debug_printf("rpc_handler_recv_closure called!\n");
#endif

    if (err_is_ok(err)) {
        // cap.cnode == NULL_CNODE
        if (cap.cnode.croot == 0 && cap.cnode.cnode == 0) {
            lmp_chan_alloc_recv_slot(chan);
        }
        uintptr_t message_type = msg.words[0];
        switch (message_type) {
        case AOS_RPC_MSG_SEND_NUMBER:
            rpc_print_number(msg.words[1]);
            break;
        case AOS_RPC_MSG_SEND_STRING:
            rpc_print_string(msg.words + 1);
            break;
        case AOS_RPC_MSG_GET_RAM_CAP:
            err = rpc_send_ram(chan, msg.words[1], msg.words[2]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "rpc_send_ram failed");
            }
            break;
        case AOS_RPC_MSG_FREE_RAM_CAP:
            err = rpc_free_ram(chan, msg.words[1]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "rpc_free_ram failed");
            }
            break;
        case AOS_RPC_MSG_SERIAL_GETCHAR:
            err = rpc_serial_getchar();
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "rpc_serial_getchar failed");
            }
            break;
         case AOS_RPC_MSG_SERIAL_PUTCHAR:
            err = rpc_serial_putchar(msg.words[1]);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "rpc_serial_putchar failed");
            }
            break;
         case AOS_RPC_MSG_PROCESS_SPAWN:
            // TODO: Handle string
            rpc_spawn_process(chan, "hello");
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

#if DEBUG_RPC_SETUP
        debug_printf("rpc_handler_recv_closure success!\n");
#endif
        return;
    } else if (lmp_err_is_transient(err)) {
        // Want to receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(rpc_handler_recv_closure, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

#if DEBUG_RPC_SETUP
        debug_printf("rpc_handler_recv_closure retry!\n");
#endif
        return;
    }

fail:
    DEBUG_ERR(err, "rpc_handler_recv_closure failed hard");
}

/**
 * Notify child that channel is ready
 */
static void rpc_setup_send_closure(void *arg)
{
    errval_t err;
    struct dispatcher_node *node = (struct dispatcher_node *)arg;
    // Bump child that this channel is now ready
    err = lmp_ep_send1(node->chan.remote_cap, LMP_SEND_FLAGS_DEFAULT, NULL_CAP, 0);

#if DEBUG_RPC_SETUP
    debug_printf("rpc_setup_send_closure called!\n");
#endif

    if (err_is_ok(err)) {
#if DEBUG_RPC_SETUP
        debug_printf("rpc_setup_send_closure success!\n");
#endif

        // Channel to child is setup, switch to child handler
        err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                     MKCLOSURE(rpc_handler_recv_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    } else if (lmp_err_is_transient(err)) {
#if DEBUG_RPC_SETUP
        debug_printf("rpc_setup_send_closure retry!\n");
#endif
        // Want to receive further messages
        err = lmp_chan_register_send(&node->chan, get_default_waitset(),
                                     MKCLOSURE(rpc_setup_send_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

    DEBUG_ERR(err, "rpc_setup_send_closure failed hard!\n");
}

/**
 * Receives a child endpoint cap, saves it in the channel and notify the child
 * that channel is ready
 */
static void rpc_setup_recv_closure(void *arg)
{
    errval_t err;

    struct dispatcher_node *node = (struct dispatcher_node *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(&node->chan, &msg, &cap);

#if DEBUG_RPC_SETUP
    debug_printf("rpc_setup_recv_closure called!\n");
#endif

    // Got message
    if (err_is_ok(err)) {
        // Check if setup message
        assert(msg.words[0] == 0);  // FIXME: Replace 0 with constant

        node->chan.remote_cap = cap;
        node->state = DISPATCHER_CONNECTED;

        err = lmp_chan_alloc_recv_slot(&node->chan);
        if (err_is_fail(err)) {
            goto fail;
        }

#if DEBUG_RPC_SETUP
        // FIXME: shouldn't this loop in usr/init/main.c not also just execute a send close?
        debug_printf("rpc_setup_recv_closure success!\n");
#endif

        rpc_setup_send_closure(arg);

        return;
    } else if (lmp_err_is_transient(err)) {
#if DEBUG_RPC_SETUP
        debug_printf("rpc_setup_recv_closure retry!\n");
#endif
        // Want to receive further messages
        err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                     MKCLOSURE(rpc_setup_recv_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

fail:
    DEBUG_ERR(err, "rpc_setup_recv_closure failed hard!\n");
}

/**
 * Creates a unique channel to a child (to be spawned)
 */
errval_t rpc_create_child_channel_to_init(struct capref *ret_init_ep_cap)
{
    // FIXME: cleanup upon err
    errval_t err;
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
        return err_push(err, LIB_ERR_ENDPOINT_CREATE);
    }

    // FIXME: Shouldn't be necessary
    err = lmp_chan_alloc_recv_slot(&node->chan);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_ALLOC_RECV_SLOT);
    }

    err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                 MKCLOSURE(rpc_setup_recv_closure, node));
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
    }

    // Add node to dispatcher list
    // Done as late as possible so there's no unfinished node in the list
    node->next = st->head;
    st->head = node;

    assert(!capref_is_null(node->chan.local_cap));
    *ret_init_ep_cap = node->chan.local_cap;

    return SYS_ERR_OK;
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

