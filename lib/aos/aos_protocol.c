#include <aos/aos_protocol.h>

#if 1
#    define DEBUG_AOS_PROTOCOL(fmt...) debug_printf(fmt);
#else
#    define DEBUG_AOS_PROTOCOL(fmt...) ((void)0)
#endif

#define AOS_UMP_MSG_SIZE 63
#define AOS_UMP_PAYLOAD_SIZE AOS_UMP_MSG_SIZE - 16

struct callback {
    void (*handler)(void *arg, uint8_t *buf);
    void *arg;
};

#define MKCALLBACK(h,a)  (struct callback){ /*handler*/ (h), /*arg*/ (a) }
#define NOP_CALLBACK     MKCALLBACK(NULL, NULL)

struct ump_event_node {
    struct callback closure;
    struct ump_event_node *next;
    domainid_t target_pid;
};

struct ump_msg_state {
    uint8_t *buf;
    bool done;
};

static struct ump_event_node *head = NULL;
static struct aos_ump *ump = NULL;

void aos_protocol_set_ump(struct aos_ump *value)
{
    ump = value;
}

static void aos_protocol_dispatch_ump(uint8_t *buf)
{
    domainid_t pid = ((uint64_t *)buf)[0];
    struct ump_event_node *parent = NULL;
    struct ump_event_node *current = head;
    while (current != NULL && current->target_pid != pid) {
        parent = current;
        current = current->next;
    }

    if (current == NULL) {
        DEBUG_AOS_PROTOCOL("ERROR: Could not handle ump message for pid %d\n", pid);
        return;
    }

    assert(pid == current->target_pid);
    // Remove from list
    if (parent != NULL) {
        parent->next = current->next;
    }
    if (head == current) {
        head = current->next;
    }

    // Call callback
    if (current->closure.handler != NULL) {
        current->closure.handler(current->closure.arg, buf);
    }
    free(current);
}

/**
 * \brief Dispatch on the default waitset and ump until the given boolean is set for
 * forever if NULL is given.
 */
errval_t aos_protocol_wait_for(bool *ready_bit)
{
    errval_t err;
    struct waitset *default_ws = get_default_waitset();
    while (ready_bit == NULL || !(*ready_bit)) {
        if (ump != NULL && aos_ump_can_dequeue(ump)) {
            uint8_t *buf = (uint8_t *)malloc(AOS_UMP_MSG_SIZE);
            if (buf == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }

            err = aos_ump_dequeue(ump, buf, AOS_UMP_MSG_SIZE);
            if (err_is_fail(err)) {
                return err;
            }
            aos_protocol_dispatch_ump(buf);
        } else {
            err = event_dispatch_non_block(default_ws);
            if (err_is_fail(err) && err != LIB_ERR_NO_EVENT) {
                return err;
            }
            thread_yield();
        }
    }

    return SYS_ERR_OK;
}

static void aos_protocol_callback(void *arg, uint8_t *buf)
{
    struct ump_msg_state *state = (struct ump_msg_state *)arg;
    state->buf = buf;
    state->done = true;
}

static errval_t aos_protocol_recv_state(domainid_t pid, struct ump_msg_state *state)
{
    state->done = false;
    struct ump_event_node *node = (struct ump_event_node *)malloc(
        sizeof(struct ump_event_node));
    if (node == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    node->target_pid = pid;
    node->closure = MKCALLBACK(aos_protocol_callback, state);

    // Add to list
    node->next = head->next;
    head = node;

    return aos_protocol_wait_for(&state->done);
}

errval_t aos_protocol_send(struct aos_chan *chan, uint16_t message_type, struct capref cap,
                           uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    assert((message_type & 0xff00) && (message_type & 0xff));
    if (chan->is_lmp) {
        return lmp_protocol_send(chan->lmp, message_type, cap, arg1, arg2, arg3);
    }
    assert(capref_is_null(cap));

    uint64_t buf[5];
    buf[0] = chan->remote_pid;
    buf[1] = message_type;
    buf[2] = arg1;
    buf[3] = arg2;
    buf[4] = arg3;
    aos_ump_enqueue(ump, (void *)buf, sizeof(uint64_t) * 5);

    return SYS_ERR_OK;
}

errval_t aos_protocol_recv(struct aos_chan *chan, uint16_t message_type,
                           struct capref *ret_cap, uintptr_t *ret_arg1,
                           uintptr_t *ret_arg2, uintptr_t *ret_arg3)
{
    assert((message_type & 0xff00) && (message_type & 0xff));
    if (chan->is_lmp) {
        return lmp_protocol_recv(chan->lmp, message_type, ret_cap, ret_arg1, ret_arg2,
                                 ret_arg3);
    }
    assert(ret_cap == NULL);

    errval_t err;
    struct ump_msg_state state;
    err = aos_protocol_recv_state(chan->remote_pid, &state);
    if (err_is_fail(err)) {
        return err;
    }

    uint64_t *buf = (uint64_t *)state.buf;
    assert(buf != NULL);
    assert(buf[1] == message_type);

    if (ret_arg1 != NULL) {
        *ret_arg1 = buf[2];
    }

    if (ret_arg2 != NULL) {
        *ret_arg2 = buf[3];
    }

    if (ret_arg3 != NULL) {
        *ret_arg3 = buf[4];
    }

    free(state.buf);
    return SYS_ERR_OK;
}

errval_t aos_protocol_send_bytes_cap(struct aos_chan *chan, uint16_t message_type,
                                     struct capref cap, size_t size, const uint8_t *bytes)
{
    assert((message_type & 0xff00) && (message_type & 0xff));
    if (chan->is_lmp) {
        return lmp_protocol_send_bytes_cap(chan->lmp, message_type, cap, size, bytes);
    }
    assert(capref_is_null(cap));

    uint64_t buf[AOS_UMP_MSG_SIZE];
    buf[0] = chan->remote_pid;
    buf[1] = message_type;
    buf[2] = size;
    uint8_t *byte_buf = (uint8_t *)&buf[3];

    size_t first_payload = MIN(size, AOS_UMP_PAYLOAD_SIZE - 8);
    memcpy(byte_buf, bytes, first_payload);
    memset(byte_buf + first_payload, 0, AOS_UMP_MSG_SIZE - first_payload);
    aos_ump_enqueue(ump, (void *)buf, AOS_UMP_MSG_SIZE);
    byte_buf = (uint8_t *)&buf[2];

    for (size_t offset = first_payload; offset < size; offset += AOS_UMP_PAYLOAD_SIZE) {
        memcpy(byte_buf, bytes + offset, MIN(size - offset, AOS_UMP_PAYLOAD_SIZE));
        aos_ump_enqueue(ump, (void *)buf, AOS_UMP_MSG_SIZE);
    }

    return SYS_ERR_OK;
}

errval_t aos_protocol_recv_bytes_cap(struct aos_chan *chan, uint16_t message_type,
                                     struct capref *ret_cap, size_t *ret_size,
                                     uint8_t **ret_bytes)
{
    assert((message_type & 0xff00) && (message_type & 0xff));
    assert(ret_bytes != NULL);
    if (chan->is_lmp) {
        return lmp_protocol_recv_bytes_cap(chan->lmp, message_type, ret_cap, ret_size,
                                           ret_bytes);
    }
    assert(ret_cap == NULL);

    errval_t err;
    struct ump_msg_state state;
    err = aos_protocol_recv_state(chan->remote_pid, &state);
    if (err_is_fail(err)) {
        return err;
    }

    uint64_t *buf = (uint64_t *)state.buf;
    assert(buf != NULL);
    assert(buf[1] == message_type);

    size_t size = buf[2];
    if (ret_size != NULL) {
        *ret_size = size;
    }

    *ret_bytes = (uint8_t *)malloc(size);
    if (*ret_bytes == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    size_t first_payload = MIN(size, AOS_UMP_PAYLOAD_SIZE - 8);
    memcpy(*ret_bytes, &buf[3], first_payload);
    free(state.buf);

    for (size_t offset = first_payload; offset < size; offset += AOS_UMP_PAYLOAD_SIZE) {
        err = aos_protocol_recv_state(chan->remote_pid, &state);
        if (err_is_fail(err)) {
            return err;
        }

        buf = (uint64_t *)state.buf;
        assert(buf != NULL);
        assert(buf[1] == message_type);

        memcpy(*ret_bytes + offset, &buf[2], MIN(size - offset, AOS_UMP_PAYLOAD_SIZE));
        
        free(state.buf);
    }

    return SYS_ERR_OK;
}

errval_t aos_protocol_send_string_cap(struct aos_chan *chan, uint16_t message_type,
                                      struct capref cap, const char *string)
{
    assert((message_type & 0xff00) && (message_type & 0xff));
    if (chan->is_lmp) {
        return lmp_protocol_send_string_cap(chan->lmp, message_type, cap, string);
    }
    assert(capref_is_null(cap));

    size_t size = strlen(string) + 1;
    return aos_protocol_send_bytes_cap(chan, message_type, cap, size,
                                       (const uint8_t *)string);
}

errval_t aos_protocol_recv_string_cap(struct aos_chan *chan, uint16_t message_type,
                                      struct capref *ret_cap, char **ret_string)
{
    assert((message_type & 0xff00) && (message_type & 0xff));
    if (chan->is_lmp) {
        return lmp_protocol_recv_string_cap(chan->lmp, message_type, ret_cap, ret_string);
    }
    assert(ret_cap == NULL);

    return aos_protocol_recv_bytes_cap(chan, message_type, ret_cap, NULL,
                                       (uint8_t **)ret_string);
}
