/**
 * \file nameservice.h
 * \brief
 */
#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/waitset.h>
#include <aos/nameserver.h>
#include <aos/aos_rpc.h>

#include <hashtable/hashtable.h>

#if 1
#    define DEBUG_NS(fmt...) debug_printf(fmt);
#else
#    define DEBUG_NS(fmt...) ((void)0)
#endif

struct srv_entry {
    const char *name;
    nameservice_receive_handler_t *recv_handler;
    void *st;
};

struct nameservice_chan {
    struct aos_rpc rpc;
    char *name;
};

struct hashtable *ht;

static void nameservice_handler(void *arg)
{
    assert(arg == NULL);

    errval_t err;

    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    err = lmp_chan_recv(get_init_server_chan(), &msg, NULL);

    if (err_is_ok(err)) {
        DEBUG_PRINTF("Received msg with header %p\n", msg.words[0]);
        return;
    } else if (lmp_err_is_transient(err)) {
        // Receive further messages
        err = lmp_chan_register_recv(get_init_server_chan(), get_default_waitset(),
                                     MKCLOSURE(nameservice_handler, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

        return;
    }

fail:
    DEBUG_ERR(err, "nameservice_handler failed hard");
}

errval_t nameservice_init(void)
{
    errval_t err;

    ht = create_hashtable();

    err = lmp_chan_register_recv(get_init_server_chan(), get_default_waitset(),
                                 MKCLOSURE(nameservice_handler, NULL));
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
    }

    return SYS_ERR_OK;
}

/**
 * @brief sends a message back to the client who sent us a message
 *
 * @param chan opaque handle of the channel
 * @oaram message pointer to the message
 * @param bytes size of the message in bytes
 * @param response the response message
 * @param response_byts the size of the response
 *
 * @return error value
 */
errval_t nameservice_rpc(nameservice_chan_t chan, void *message, size_t bytes,
                         void **response, size_t *response_bytes, struct capref tx_cap,
                         struct capref rx_cap)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief registers our selves as 'name'
 *
 * @param name  our name
 * @param recv_handler the message handler for messages received over this service
 * @param st  state passed to the receive handler
 *
 * @return SYS_ERR_OK
 */
errval_t nameservice_register(const char *name,
                              nameservice_receive_handler_t recv_handler, void *st)
{
    errval_t err;

    struct lmp_chan *chan = get_init_client_chan();

    size_t trunc_size = MIN(strlen(name), AOS_RPC_BUFFER_SIZE - 1);
    uintptr_t buf[3];

    memset(buf, 0, AOS_RPC_BUFFER_SIZE);
    memcpy(buf, name, trunc_size);

    DEBUG_NS("Sending register request %s to NS\n", buf);

    // send register request to NS
    uintptr_t header = AOS_RPC_HEADER(disp_get_domain_id(), 0x1, AOS_RPC_MSG_NS_REGISTER);
    err = lmp_protocol_send3(chan, header, buf[0], buf[1], buf[2]);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_PROTOCOL_SEND3);
    }

    // wait for ack
    uintptr_t ret;
    err = lmp_protocol_recv1(chan, AOS_RPC_MSG_NS_REGISTER, &ret);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_PROTOCOL_RECV1);
    }

    if (ret != AOS_NS_REGISTER_OK) {
        return LIB_ERR_NS_REGISTER;
    }

    // ack received save handler and state in hashtable
    struct srv_entry *entry = (struct srv_entry *)malloc(sizeof(struct srv_entry));
    entry->name = name;
    entry->recv_handler = recv_handler;
    entry->st = st;

    err = ht->d.put_word(&ht->d, entry->name, strlen(entry->name), (uintptr_t)entry);
    if (err_is_fail(err)) {
        return HT_ERR_PUT_WORD;
    }

    return SYS_ERR_OK;
}

/**
 * @brief deregisters the service 'name'
 *
 * @param the name to deregister
 *
 * @return error value
 */
errval_t nameservice_deregister(const char *name)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief lookup an endpoint and obtain an RPC channel to that
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_lookup(const char *name, nameservice_chan_t *nschan)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief enumerates all entries that match an query (prefix match)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries
 */
errval_t nameservice_enumerate(char *query, size_t *num, char **result)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

