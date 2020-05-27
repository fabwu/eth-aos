/**
 * \file nameservice.h
 * \brief
 */
#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/waitset.h>
#include <aos/nameservice.h>
#include <aos/aos_rpc.h>

#include <hashtable/hashtable.h>

#if 1
#    define DEBUG_NS(fmt...) debug_printf(fmt);
#else
#    define DEBUG_NS(fmt...) ((void)0)
#endif

#define MAX_SERVICE_NAME_LENGTH (AOS_RPC_BUFFER_SIZE - 1)

struct srv_entry {
    char name[MAX_SERVICE_NAME_LENGTH];
    nameservice_receive_handler_t *recv_handler;
    void *st;
};

struct nameservice_chan {
    struct aos_rpc rpc;
    char name[MAX_SERVICE_NAME_LENGTH];
};

struct hashtable *ht = NULL;

static void nameservice_handler(void *arg)
{
    assert(arg == NULL);

    errval_t err;

    struct lmp_chan *chan = get_init_server_chan();
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref recv_cap;
    err = lmp_chan_recv(chan, &msg, &recv_cap);

    if (err_is_ok(err)) {
        // check if buffer frame cap is here
        assert(!capref_is_null(recv_cap));

        // refill slots
        err = lmp_chan_alloc_recv_slot(chan);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_LMP_CHAN_ALLOC_RECV_SLOT);
            goto fail;
        }

        // parse header
        uint64_t recv_header = msg.words[0];
        aos_rpc_msg_t msg_type = AOS_RPC_HEADER_MSG(recv_header);
        domainid_t client = AOS_RPC_HEADER_SEND(recv_header);
        assert(msg_type == AOS_RPC_MSG_NS_RPC);
        size_t recv_bytes = (size_t)msg.words[1];

        // map recv frame
        struct paging_state *st = get_current_paging_state();
        void *recv_buf;
        err = paging_map_frame_attr(st, &recv_buf, recv_bytes, recv_cap,
                                    VREGION_FLAGS_READ, NULL, NULL);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_PAGING_MAP_FRAME_ATTR);
            goto fail;
        }

        // extract service name from beginning of recv buffer
        size_t name_bytes = strlen(recv_buf) + 1;
        char name[name_bytes - 1];
        strcpy(name, recv_buf);

        // get service entry from hashtable
        struct srv_entry *entry;
        ht->d.get(&ht->d, name, strlen(name), (void **)&entry);
        if (entry == NULL) {
            err = HT_ERR_GET;
            DEBUG_ERR(err, "Coudln't find service %s\n", name);
            goto free_recv_buf;
        }

        // call handler
        void *message = recv_buf + name_bytes;
        size_t message_bytes = recv_bytes - name_bytes;
        void *response;
        size_t response_bytes;
        // TODO Handle caps
        entry->recv_handler(entry->st, message, message_bytes, &response, &response_bytes,
                            NULL_CAP, &NULL_CAP);
        // prepend service name to response buffer
        response_bytes += name_bytes;

        // allocate response buffer
        struct capref response_cap;
        size_t ret_bytes;
        err = frame_alloc(&response_cap, response_bytes, &ret_bytes);
        if (err_is_fail(err) || ret_bytes < response_bytes) {
            err = err_push(err, LIB_ERR_FRAME_ALLOC);
            DEBUG_ERR(err, "Couldn't allocate frame for response\n");
            goto free_recv_buf;
        }

        void *response_buf;
        err = paging_map_frame_attr(st, &response_buf, response_bytes, response_cap,
                                    VREGION_FLAGS_WRITE, NULL, NULL);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_PAGING_MAP_FRAME_ATTR);
            DEBUG_ERR(err, "Couldn't map response buffer\n");
            goto free_response_cap;
        }

        // copy and send response
        strcpy(response_buf, name);
        memcpy(response_buf + name_bytes, response, response_bytes);

        uintptr_t arg1 = (uintptr_t)response_bytes;
        uintptr_t header = AOS_RPC_HEADER(disp_get_domain_id(), client,
                                          AOS_RPC_MSG_NS_RPC);
        err = lmp_protocol_send_cap1(chan, header, response_cap, arg1);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_LMP_PROTOCOL_SEND_CAP1);
            DEBUG_ERR(err, "Couldn't send response to client\n");

            // Normally receiver frees memory but there was an error...
            err = frame_free(response_cap, response_bytes);
            if (err_is_fail(err)) {
                err = err_push(err, LIB_ERR_FRAME_FREE);
                goto fail;
            }

            goto unmap_response_buf;
        }

    unmap_response_buf:
        err = paging_unmap(st, (lvaddr_t)response_buf, response_cap, response_bytes);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_PAGING_UNMAP);
            goto fail;
        }

    free_response_cap:
        // client (receiver) frees memory
        err = cap_destroy(response_cap);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_CAP_DESTROY);
            goto fail;
        }

    free_recv_buf:
        err = paging_unmap(st, (lvaddr_t)recv_buf, recv_cap, recv_bytes);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_PAGING_UNMAP);
            goto fail;
        }

        // TODO Doesn't work
        //        err = frame_free(recv_cap, recv_bytes);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_FRAME_FREE);
            goto fail;
        }

        // receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(nameservice_handler, arg));
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
            goto fail;
        }

        return;
    } else if (lmp_err_is_transient(err)) {
        // receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(),
                                     MKCLOSURE(nameservice_handler, arg));
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
            goto fail;
        }

        return;
    }

fail:
    DEBUG_ERR(err, "nameservice_handler failed hard");
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
errval_t nameservice_rpc(nameservice_chan_t nschan_ref, void *message, size_t bytes,
                         void **response, size_t *response_bytes, struct capref tx_cap,
                         struct capref rx_cap)
{
    errval_t err = SYS_ERR_OK;

    if (!capref_is_null(tx_cap) || !capref_is_null(rx_cap)) {
        //TODO Implement caps
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    struct lmp_chan *chan = get_init_client_chan();
    struct nameservice_chan *nschan = (struct nameservice_chan *)nschan_ref;
    domainid_t server = nschan->rpc.recv_id;

    DEBUG_NS("Sending rpc to service %s running at DID %p\n", nschan->name, server);

    // allocate send buffer
    size_t name_bytes = strlen(nschan->name) + 1;
    size_t send_bytes = name_bytes + bytes;
    struct capref send_frame;
    size_t ret_frame_bytes;
    err = frame_alloc(&send_frame, send_bytes, &ret_frame_bytes);
    if (err_is_fail(err) || ret_frame_bytes < send_bytes) {
        err = err_push(err, LIB_ERR_FRAME_ALLOC);
        goto out;
    }

    // map send buffer
    struct paging_state *ps = get_current_paging_state();
    void *send_buf;
    err = paging_map_frame_attr(ps, &send_buf, send_bytes, send_frame,
                                VREGION_FLAGS_WRITE, NULL, NULL);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_PAGING_MAP_FRAME_ATTR);
        goto free_send_frame;
    }

    // copy service name and message
    strcpy(send_buf, nschan->name);
    memcpy(send_buf + name_bytes, message, bytes);

    // send payload to server
    uintptr_t arg1 = (uintptr_t)send_bytes;
    uintptr_t header = AOS_RPC_HEADER(nschan->rpc.send_id, nschan->rpc.recv_id,
                                      AOS_RPC_MSG_NS_RPC);
    err = lmp_protocol_send_cap1(chan, header, send_frame, arg1);
    if (err_is_fail(err)) {
        // send failed so we have to free frame
        DEBUG_ERR(err, "Couldn't send request to server. Free send buffer\n");
        err = paging_unmap(ps, (lvaddr_t)send_buf, send_frame, send_bytes);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_PAGING_UNMAP);
        }

        err = frame_free(send_frame, send_bytes);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_FRAME_FREE);
        }

        return err_push(err, LIB_ERR_LMP_PROTOCOL_SEND3);
    }

    // wait for response
    struct capref recv_frame;
    uintptr_t recv_bytes = 0;
    err = lmp_protocol_recv_cap1(chan, AOS_RPC_MSG_NS_RPC, &recv_frame, &recv_bytes);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_PROTOCOL_RECV_CAP1);
        DEBUG_ERR(err, "Couldn't receive response from server\n");
        goto unmap_send_buf;
    }

    // map receive buffer
    void *recv_buf;
    err = paging_map_frame_attr(ps, &recv_buf, recv_bytes, recv_frame, VREGION_FLAGS_READ,
                                NULL, NULL);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_PAGING_MAP_FRAME_ATTR);
        goto out;
    }

    // copy response
    if (response != NULL && response_bytes != NULL) {
        // extract service name from beginning of recv buffer
        char response_name[name_bytes - 1];
        strcpy(response_name, recv_buf);
        DEBUG_PRINTF("%s %s\n", nschan->name, response_name);
        assert(strcmp(nschan->name, response_name) == 0);

        *response_bytes = ((size_t)recv_bytes) - name_bytes;
        *response = (void *)malloc(*response_bytes);
        memcpy(*response, recv_buf, *response_bytes);
    }

    err = paging_unmap(ps, (lvaddr_t)recv_buf, recv_frame, recv_bytes);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_PAGING_UNMAP);
        goto free_recv_frame;
    }

free_recv_frame:
    // TODO Doesn't work
    //    err = frame_free(recv_frame, recv_bytes);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_FREE);
    }

unmap_send_buf:
    err = paging_unmap(ps, (lvaddr_t)send_buf, send_frame, send_bytes);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_UNMAP);
    }

free_send_frame:
    // server frees send buffer, we destroy our cap here
    err = cap_destroy(send_frame);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_DESTROY);
    }

out:
    return err;
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
    assert(strlen(name) <= MAX_SERVICE_NAME_LENGTH);

    errval_t err;

    if(ht == NULL) {
        // init nameservice on the first register call
        ht = create_hashtable();

        err = lmp_chan_register_recv(get_init_server_chan(), get_default_waitset(),
                                     MKCLOSURE(nameservice_handler, NULL));
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
        }
    }

    struct lmp_chan *chan = get_init_client_chan();

    size_t trunc_size = MIN(strlen(name), MAX_SERVICE_NAME_LENGTH);
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

    if (ret == LIB_ERR_NS_DUP_NAME) {
        return LIB_ERR_NS_DUP_NAME;
    }

    if (ret != SYS_ERR_OK) {
        return LIB_ERR_NS_REGISTER;
    }

    // ack received save handler and state in hashtable
    struct srv_entry *entry = (struct srv_entry *)malloc(sizeof(struct srv_entry));
    assert(entry != NULL);

    strcpy(entry->name, name);
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
errval_t nameservice_lookup(const char *name, nameservice_chan_t *nschan_ref)
{
    assert(name != NULL);
    assert(nschan_ref != NULL);
    assert(strlen(name) <= MAX_SERVICE_NAME_LENGTH);

    errval_t err;

    struct lmp_chan *chan = get_init_client_chan();

    // prepare service name
    size_t trunc_size = MIN(strlen(name), MAX_SERVICE_NAME_LENGTH);
    uintptr_t buf[3];

    memset(buf, 0, AOS_RPC_BUFFER_SIZE);
    memcpy(buf, name, trunc_size);

    DEBUG_NS("Sending lookup request %s to NS\n", buf);

    // send register request to NS
    uintptr_t header = AOS_RPC_HEADER(disp_get_domain_id(), 0x1, AOS_RPC_MSG_NS_LOOKUP);
    err = lmp_protocol_send3(chan, header, buf[0], buf[1], buf[2]);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_PROTOCOL_SEND3);
    }

    // wait for ack
    uintptr_t ret1;
    uintptr_t ret2;
    err = lmp_protocol_recv2(chan, AOS_RPC_MSG_NS_LOOKUP, &ret1, &ret2);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_PROTOCOL_RECV1);
    }

    if (ret1 != SYS_ERR_OK) {
        return LIB_ERR_NS_LOOKUP;
    }

    domainid_t service_did = (domainid_t)ret2;

    DEBUG_NS("Service is running at %p\n", service_did);

    struct nameservice_chan *nschan = (struct nameservice_chan *)malloc(
        sizeof(struct nameservice_chan));
    assert(nschan != NULL);

    strcpy(nschan->name, name);
    nschan->rpc.recv_id = service_did;
    nschan->rpc.send_id = disp_get_domain_id();

    *nschan_ref = nschan;

    return SYS_ERR_OK;
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
