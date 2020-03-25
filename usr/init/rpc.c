/**
 * \file
 * \brief init rpc
 */

#include "rpc.h"

#define DEBUG_RPC_SETUP 1

/**
 * Handles messages from different child channels
 */
static void init_message_handler(void *arg)
{
    errval_t err;
    struct dispatcher_node *node = (struct dispatcher_node *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(&node->chan, &msg, &cap);
    debug_printf("aos_rpc_recv_regular_closure called!\n");

    if (err_is_ok(err)) {
        // TODO: implement protocol here
        DEBUG_PRINTF("msg_buflen %zu\n", msg.buf.msglen);
        DEBUG_PRINTF("msg.words[0] = %d\n", msg.words[0]);
        DEBUG_PRINTF("msg.words[1] = %d\n", msg.words[1]);

        if (msg.words[0] == 2) {
            // send ram back
            err = lmp_chan_send2(&node->chan, LMP_SEND_FLAGS_DEFAULT, NULL_CAP,
                                 msg.words[0], msg.words[1]);
        }

        err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                     MKCLOSURE(init_message_handler, node));
        if (err_is_fail(err)) {
            goto fail;
        }

        debug_printf("aos_rpc_recv_regular_closure success!\n");
        return;
    } else if (lmp_err_is_transient(err)) {
        debug_printf("aos_rpc_recv_regular_closure retry!\n");
        // Want to receive further messages
        err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                     MKCLOSURE(init_message_handler, node));
        if (err_is_ok(err)) {
            return;
        }
    }

fail:
    DEBUG_ERR(err, "recv_real_closure failed hard");
}

/**
 * Notify child that channel is ready
 */
static void setup_send_closure(void *arg)
{
    errval_t err;
    struct lmp_chan *chan = (struct lmp_chan *)arg;
    // Bump child that this channel is now ready
    err = lmp_ep_send(chan->remote_cap, LMP_FLAG_SYNC, NULL_CAP, 1, 1, 0, 0, 0);

#if DEBUG_RPC_SETUP
    debug_printf("setup_send_closure called!\n");
#endif

    if (err_is_ok(err)) {
#if DEBUG_RPC_SETUP
        debug_printf("setup_send_closure success!\n");
#endif

        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(init_message_handler, arg));
        if (err_is_ok(err)) {
            return;
        }
    } else if (lmp_err_is_transient(err)) {
#if DEBUG_RPC_SETUP
        debug_printf("setup_send_closure retry!\n");
#endif
        // Want to receive further messages
        err = lmp_chan_register_send(chan, get_default_waitset(),
                                     MKCLOSURE(setup_send_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

    DEBUG_ERR(err, "setup_send_closure failed hard!\n");
}

/**
 * Receives a child endpoint cap, saves it in the channel and notify the child
 * that channel is ready
 */
static void setup_recv_closure(void *arg)
{
    errval_t err;

    struct lmp_chan *chan = (struct lmp_chan *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    err = lmp_chan_recv(chan, &msg, &cap);

#if DEBUG_RPC_SETUP
    debug_printf("setup_recv_closure called!\n");
#endif

    // Got message
    if (err_is_ok(err)) {
        chan->remote_cap = cap;

        err = lmp_chan_alloc_recv_slot(chan);
        if (err_is_fail(err)) {
            goto fail;
        }

#if DEBUG_RPC_SETUP
        // FIXME: shouldn't this loop in usr/init/main.c not also just execute a send close?
        debug_printf("setup_recv_closure success!\n");
#endif

        setup_send_closure(arg);

        return;
    } else if (lmp_err_is_transient(err)) {
#if DEBUG_RPC_SETUP
        debug_printf("setup_recv_closure retry!\n");
#endif
        // Want to receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(setup_recv_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

fail:
    DEBUG_ERR(err, "setup_recv_closure failed hard!\n");
}

/**
 * Creates a unique channel to a child (to be spawned)
 */
errval_t create_child_channel_to_init(struct capref *ret_init_ep_cap)
{
    // FIXME: cleanup upon err
    errval_t err;
    struct lmp_state *st = get_current_lmp_state();
    assert(st != NULL);

    struct dispatcher_node *node = slab_alloc(&st->slabs);
    if (node == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    node->next = st->head;
    st->head = node;

    node->state = DISPATCHER_DISCONNECTED;

    struct capref init_ep_cap;
    struct lmp_endpoint *init_ep;
    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &init_ep_cap, &init_ep);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_ENDPOINT_CREATE);
    }

    lmp_chan_init(&node->chan);

    node->chan.local_cap = init_ep_cap;
    node->chan.endpoint = init_ep;

    // FIXME: Shouldn't be necessary
    err = lmp_chan_alloc_recv_slot(&node->chan);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_ALLOC_RECV_SLOT);
    }

    err = lmp_chan_register_recv(&node->chan, get_default_waitset(),
                                 MKCLOSURE(setup_recv_closure, &node->chan));
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
    }

    *ret_init_ep_cap = init_ep_cap;

    return SYS_ERR_OK;
}

errval_t initialize_lmp(struct lmp_state *st)
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

