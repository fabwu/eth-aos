/**
 * \file
 * \brief LMP Protocol for AOS
 */

#include <aos/aos.h>
#include <aos/lmp_protocol.h>
#include <aos/aos_protocol.h>

#define LMP_PROTOCOL_DATA_LENGTH 3
#define LMP_PROTOCOL_DATA_ENTRY_SIZE sizeof(uintptr_t)
#define LMP_PROTOCOL_DATA_BYTES (LMP_PROTOCOL_DATA_LENGTH * LMP_PROTOCOL_DATA_ENTRY_SIZE)

struct lmp_msg_state {
    struct lmp_chan *chan;
    uint16_t message_type;
    struct capref cap;
    uintptr_t data[3];
    bool done;
    bool failed;
};

static bool do_ump_dispatch = false;

void lmp_protocol_set_ump_dispatch(bool value)
{
    do_ump_dispatch = value;
}

static struct lmp_msg_state make_lmp_msg_state(struct lmp_chan *chan,
                                               uint16_t message_type, struct capref cap,
                                               uintptr_t arg1, uintptr_t arg2,
                                               uintptr_t arg3)
{
    struct lmp_msg_state state;
    state.chan = chan;
    state.message_type = message_type;
    state.cap = cap;
    state.data[0] = arg1;
    state.data[1] = arg2;
    state.data[2] = arg3;
    return state;
}

/**
 * \brief Dispatch on the default waitset until the given boolean is set.
 */
static errval_t lmp_protocol_wait_for(bool *ready_bit)
{
    errval_t err;
    struct waitset *default_ws = get_default_waitset();
    if (!do_ump_dispatch) {
        while (!(*ready_bit)) {
            err = event_dispatch(default_ws);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_EVENT_DISPATCH);
            }
        }
    } else {
        aos_protocol_wait_for(ready_bit);
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
    err = lmp_chan_send4(state->chan, LMP_SEND_FLAGS_DEFAULT, state->cap,
                         state->message_type, state->data[0], state->data[1],
                         state->data[2]);

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

static errval_t lmp_protocol_send_state(struct lmp_msg_state *state)
{
    state->done = false;
    state->failed = false;

    lmp_protocol_send_closure(state);
    errval_t err = lmp_protocol_wait_for(&state->done);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_LMP_SEND_FAILURE);
    } else if (state->failed) {
        return AOS_ERR_LMP_SEND_FAILURE;
    }

    return SYS_ERR_OK;
}

/**
 * \brief Receive lmp message with given message type using the given lmp_msg_state.
 */
static void lmp_protocol_recv_closure(void *arg)
{
    errval_t err;

    struct lmp_msg_state *state = (struct lmp_msg_state *)arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(state->chan, &msg, &state->cap);

    if (err_is_ok(err)) {
        // Check message type
        assert(msg.words[0] == state->message_type);
        if (msg.words[0] != state->message_type) {
            state->failed = true;
        }

        if (!capref_is_null(state->cap)) {
            // Allocate slot for next receive
            err = lmp_chan_alloc_recv_slot(state->chan);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Couldn't allocate slot for ret_cap");
            }
        }

        state->data[0] = msg.words[1];
        state->data[1] = msg.words[2];
        state->data[2] = msg.words[3];
        state->done = true;
        return;
    } else if (lmp_err_is_transient(err)) {
        err = lmp_chan_register_recv(state->chan, get_default_waitset(),
                                     MKCLOSURE(lmp_protocol_recv_closure, arg));
        if (err_is_ok(err)) {
            return;
        }
    }

    state->done = true;
    state->failed = true;
    DEBUG_ERR(err, "recv_closure failed hard");
}

static errval_t lmp_protocol_recv_state(struct lmp_msg_state *state)
{
    errval_t err;

    state->done = false;
    state->failed = false;

    err = lmp_chan_register_recv(state->chan, get_default_waitset(),
                                 MKCLOSURE(lmp_protocol_recv_closure, state));
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_LMP_RECV_FAILURE);
    }

    err = lmp_protocol_wait_for(&state->done);
    if (err_is_fail(err)) {
        return err_push(err, AOS_ERR_LMP_RECV_FAILURE);
    } else if (state->failed) {
        return AOS_ERR_LMP_RECV_FAILURE;
    }

    return SYS_ERR_OK;
}

/**
 * \brief Send given lmp message over given lmp channel.
 */
errval_t lmp_protocol_send(struct lmp_chan *chan, uint16_t message_type, struct capref cap,
                           uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    assert((message_type & 0xff00) && (message_type & 0xff));
    struct lmp_msg_state state = make_lmp_msg_state(chan, message_type, cap, arg1, arg2,
                                                    arg3);
    return lmp_protocol_send_state(&state);
}

/**
 * \brief Receive lmp message of the given message type using given lmp channel.
 */
errval_t lmp_protocol_recv(struct lmp_chan *chan, uint16_t message_type,
                           struct capref *ret_cap, uintptr_t *ret_arg1,
                           uintptr_t *ret_arg2, uintptr_t *ret_arg3)
{
    assert((message_type & 0xff00) && (message_type & 0xff));
    struct lmp_msg_state state;
    state.chan = chan;
    state.message_type = message_type;

    errval_t err = lmp_protocol_recv_state(&state);
    if (err_is_fail(err)) {
        return err;
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

/**
 * \brief Send given bytes over given lmp channel.
 *
 * The first message contains the amount of bytes and the first 2*8 bytes. All later
 * messages contain <= 3*8 bytes until all bytes have been sent. The last message contains
 * the remaining bytes followed by 0 entries.
 */
errval_t lmp_protocol_send_bytes_cap(struct lmp_chan *chan, uint16_t message_type,
                                     struct capref cap, size_t size, const uint8_t *bytes)
{
    errval_t err;

    assert((message_type & 0xff00) && (message_type & 0xff));
    struct lmp_msg_state state = make_lmp_msg_state(chan, message_type, cap, size, 0, 0);

    memcpy(&state.data[1], bytes, MIN(size, 2 * LMP_PROTOCOL_DATA_ENTRY_SIZE));
    size_t offset = 2 * LMP_PROTOCOL_DATA_ENTRY_SIZE;

    err = lmp_protocol_send_state(&state);
    if (err_is_fail(err)) {
        return err;
    }

    state.cap = NULL_CAP;
    while (offset < size) {
        size_t send_size = LMP_PROTOCOL_DATA_BYTES;
        if (size - offset < LMP_PROTOCOL_DATA_BYTES) {
            send_size = size - offset;
            memset(state.data + send_size, 0, LMP_PROTOCOL_DATA_BYTES - send_size);
        }
        memcpy(&state.data, bytes + offset, send_size);
        offset += send_size;

        err = lmp_protocol_send_state(&state);
        if (err_is_fail(err)) {
            return err;
        }
    }

    return SYS_ERR_OK;
}

/**
 * \brief Receive bytes over the given lmp channel.
 *
 * It designed to receive messages sent by lmp_protocol_send_bytes_cap() and follows the
 * protocol described there. The returned array is allocated using malloc and has to be
 * freed by the client after it is no longer used.
 */
errval_t lmp_protocol_recv_bytes_cap_la(struct lmp_chan *chan, uint16_t message_type,
                                        struct capref *ret_cap, size_t *ret_size,
                                        uint8_t **ret_bytes,
                                        struct lmp_recv_msg *lookahead)
{
    errval_t err;

    assert((message_type & 0xff00) && (message_type & 0xff));
    assert(ret_bytes != NULL);
    struct lmp_msg_state state;
    state.chan = chan;
    state.message_type = message_type;

    if (lookahead != NULL) {
        // Use lookahead message instead of receiving a new message
        assert(message_type == lookahead->words[0]);
        state.data[0] = lookahead->words[1];
        state.data[1] = lookahead->words[2];
        state.data[2] = lookahead->words[3];
    } else {
        err = lmp_protocol_recv_state(&state);
        if (err_is_fail(err)) {
            return err;
        }
    }

    if (ret_cap != NULL) {
        *ret_cap = state.cap;
    }

    size_t size = state.data[0];
    if (ret_size != NULL) {
        *ret_size = size;
    }

    *ret_bytes = (uint8_t *)malloc(size);
    if (ret_bytes == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    memcpy(*ret_bytes, &state.data[1], MIN(size, 2 * LMP_PROTOCOL_DATA_ENTRY_SIZE));
    size_t offset = 2 * LMP_PROTOCOL_DATA_ENTRY_SIZE;

    while (offset < size) {
        err = lmp_protocol_recv_state(&state);
        if (err_is_fail(err)) {
            free(*ret_bytes);
            return err;
        }

        size_t recv_size = MIN(size - offset, LMP_PROTOCOL_DATA_BYTES);
        memcpy(*ret_bytes + offset, state.data, recv_size);
        offset += recv_size;
    }

    return SYS_ERR_OK;
}

/**
 * \brief Sends the given \0 terminated string over the given lmp channel.
 */
errval_t lmp_protocol_send_string_cap(struct lmp_chan *chan, uint16_t message_type,
                                      struct capref cap, const char *string)
{
    size_t size = strlen(string) + 1;
    return lmp_protocol_send_bytes_cap(chan, message_type, cap, size,
                                       (const uint8_t *)string);
}

/**
 * \brief Receives the given \0 terminated string from the given lmp channel.
 *
 * The returned string is allocated using malloc and has to be freed by the client after
 * it is no longer used.
 */
errval_t lmp_protocol_recv_string_cap_la(struct lmp_chan *chan, uint16_t message_type,
                                         struct capref *ret_cap, char **ret_string,
                                         struct lmp_recv_msg *lookahead)
{
    return lmp_protocol_recv_bytes_cap_la(chan, message_type, ret_cap, NULL,
                                          (uint8_t **)ret_string, lookahead);
}
