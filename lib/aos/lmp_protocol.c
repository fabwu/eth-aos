/**
 * \file
 * \brief LMP Protocol for AOS
 */

#include <aos/aos.h>
#include <aos/lmp_protocol.h>

struct lmp_msg_state {
    struct lmp_chan *chan;
    uint8_t message_type;
    struct capref cap;
    uintptr_t data[3];
    bool done;
    bool failed;
};

static struct lmp_msg_state make_lmp_msg_state(struct lmp_chan *chan, uint8_t message_type,
                                               struct capref cap, uintptr_t arg1,
                                               uintptr_t arg2, uintptr_t arg3)
{
    struct lmp_msg_state state;
    state.chan = chan;
    state.message_type = message_type;
    state.data[0] = arg1;
    state.data[1] = arg2;
    state.data[2] = arg3;
    state.done = false;
    state.failed = false;
    return state;
}

/**
 * \brief Dispatch on the default waitset until the given boolean is set.
 */
static errval_t lmp_protocol_wait_for(bool *ready_bit)
{
    struct waitset *default_ws = get_default_waitset();
    while (!(*ready_bit)) {
        errval_t err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_EVENT_DISPATCH);
        }
    }

    return SYS_ERR_OK;
}

/**
 * \brief Send lmp message using the given lmp_msg_state.
 */
static void lmp_protocol_send_closure(void *arg)
{
    errval_t err;

    struct lmp_msg_state *state = (struct lmp_msg_state *)arg;
    err = lmp_chan_send4(state->chan, LMP_SEND_FLAGS_DEFAULT, state->cap, state->message_type,
                         state->data[0], state->data[1], state->data[2]);

    if (err_is_ok(err)) {
        state->done = true;
        return;
    } else if (lmp_err_is_transient(err)) {
        err = lmp_chan_register_send(state->chan, get_default_waitset(),
                                     MKCLOSURE(lmp_protocol_send_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

    state->done = true;
    state->failed = true;
    DEBUG_ERR(err, "send_closure failed hard");
}

/**
 * \brief Receive lmp message with given message type using the given lmp_msg_state.
 */
static void lmp_protocol_recv_closure(void *arg)
{
    errval_t err;

    struct lmp_msg_state *st = (struct lmp_msg_state *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(st->chan, &msg, &st->cap);

    if (err_is_ok(err)) {
        // Check message type
        assert(msg.words[0] == st->message_type);
        if (msg.words[0] != st->message_type) {
            st->failed = true;
        }

        if (!capref_is_null(st->cap)) {
            // Allocate slot for next receive
            err = lmp_chan_alloc_recv_slot(st->chan);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Couldn't allocate slot for ret_cap");
            }
        }

        st->data[0] = msg.words[1];
        st->data[1] = msg.words[2];
        st->data[2] = msg.words[3];
        st->done = true;
        return;
    } else if (lmp_err_is_transient(err)) {
        err = lmp_chan_register_recv(st->chan, get_default_waitset(),
                                     MKCLOSURE(lmp_protocol_recv_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

    st->done = true;
    st->failed = true;
    DEBUG_ERR(err, "recv_closure failed hard");
}

/**
 * \brief Send given lmp message over given lmp channel.
 */
errval_t lmp_protocol_send(struct lmp_chan *chan, uint8_t message_type, struct capref cap,
                           uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    struct lmp_msg_state state = make_lmp_msg_state(chan, message_type, cap, arg1, arg2,
                                                    arg3);

    lmp_protocol_send_closure(&state);
    errval_t err = lmp_protocol_wait_for(&state.done);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_LMP_SEND_FAILURE);
    } else if (state.failed) {
        return AOS_ERR_LMP_SEND_FAILURE;
    }

    return SYS_ERR_OK;
}

/**
 * \brief Receive lmp message of the given message type using given lmp channel.
 */
errval_t lmp_protocol_recv(struct lmp_chan *chan, uint8_t message_type,
                           struct capref *ret_cap, uintptr_t *ret_arg1,
                           uintptr_t *ret_arg2, uintptr_t *ret_arg3)
{
    errval_t err;

    struct lmp_msg_state state;
    state.chan = chan;
    state.message_type = message_type;
    state.failed = false;
    state.done = false;

    err = lmp_chan_register_recv(state.chan, get_default_waitset(),
                                 MKCLOSURE(lmp_protocol_send_closure, &state));
    if(err_is_fail(err)) {
        return err_push(err, AOS_ERR_LMP_RECV_FAILURE);
    }
    err = lmp_protocol_wait_for(&state.done);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_LMP_RECV_FAILURE);
    } else if (state.failed) {
        return AOS_ERR_LMP_RECV_FAILURE;
    }

    if (ret_cap != NULL) {
        *ret_cap = state.cap;
    }
    if (ret_arg1 != NULL) {
        *ret_arg1 = state.data[0];
    }
    if (ret_arg2 != NULL) {
        *ret_arg2 = state.data[1];
    }
    if (ret_arg3 != NULL) {
        *ret_arg3 = state.data[2];
    }

    return SYS_ERR_OK;
}

errval_t lmp_protocol_send_bytes_cap(struct lmp_chan *chan, uint8_t message_type,
                                     struct capref cap, size_t size, int8_t *bytes)
{
}

errval_t lmp_protocol_recv_bytes_cap(struct lmp_chan *chan, uint8_t message_type,
                                     struct capref *ret_cap, size_t *ret_size,
                                     int8_t **ret_bytes)
{
}

errval_t lmp_protocol_send_string_cap(struct lmp_chan *chan, uint8_t message_type,
                                      struct capref cap, char *string)
{
}
errval_t lmp_protocol_recv_string_cap(struct lmp_chan *chan, uint8_t message_type,
                                      struct capref *ret_cap, char *string)
{
}
