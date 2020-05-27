/**
 * \file
 * \brief nameserver
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <aos/nameservice.h>

#include <hashtable/hashtable.h>

#if 0
#    define DEBUG_NS(fmt...) debug_printf(fmt);
#else
#    define DEBUG_NS(fmt...) ((void)0)
#endif

struct srv_entry {
    const char *name;
    domainid_t did;
};

struct hashtable *ht;

static errval_t handle_register(char *name, domainid_t server_did)
{
    errval_t err;
    aos_rpc_header_t header = AOS_RPC_HEADER(disp_get_domain_id(), server_did,
                                             AOS_RPC_MSG_NS_REGISTER);
    // check if entry is already present
    struct srv_entry *existing_entry;
    ht->d.get(&ht->d, name, strlen(name), (void **)&existing_entry);
    if(existing_entry != NULL) {
        DEBUG_NS("Service %s is already registered running at %p\n", name, existing_entry->did);
        err = lmp_protocol_send1(get_init_server_chan(), header, LIB_ERR_NS_DUP_NAME);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_LMP_PROTOCOL_SEND1);
            goto fail;
        }
        return SYS_ERR_OK;
    }

    struct srv_entry *entry = (struct srv_entry *)malloc(sizeof(struct srv_entry));
    entry->name = name;
    entry->did = server_did;
    err = ht->d.put_word(&ht->d, entry->name, strlen(entry->name), (uintptr_t)entry);
    if (err_is_fail(err)) {
        err = HT_ERR_PUT_WORD;
        goto fail_entry;
    }

    DEBUG_NS("Received register request with name %s from %p\n", entry->name, entry->did);

    err = lmp_protocol_send1(get_init_server_chan(), header, SYS_ERR_OK);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_PROTOCOL_SEND1);
        goto fail_send;
    }

    return SYS_ERR_OK;

fail_send:
    ht->d.remove(&ht->d, entry->name, strlen(entry->name));

fail_entry:
    free(entry);

fail:
    return err;
}

static errval_t handle_lookup(char *name, domainid_t server_did)
{
    errval_t err;

    DEBUG_NS("Received lookup request with name %s from %p\n", name, server_did);

    struct srv_entry *entry;
    uintptr_t success = 0;
    uintptr_t did = 0;

    ht->d.get(&ht->d, name, strlen(name), (void **)&entry);

    if (entry != NULL) {
        did = entry->did;
        success = SYS_ERR_OK;
    } else {
        DEBUG_PRINTF("Couldn't find service %s\n", name);
    }

    aos_rpc_header_t header = AOS_RPC_HEADER(disp_get_domain_id(), server_did,
                                             AOS_RPC_MSG_NS_LOOKUP);
    err = lmp_protocol_send2(get_init_server_chan(), header, success, did);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_PROTOCOL_SEND1);
    }

    return SYS_ERR_OK;
}

static void handler(void *arg)
{
    assert(arg == NULL);

    errval_t err;

    struct lmp_chan *chan = get_init_server_chan();
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    err = lmp_chan_recv(chan, &msg, NULL);

    if (err_is_ok(err)) {
        aos_rpc_header_t header = msg.words[0];
        domainid_t sender = AOS_RPC_HEADER_SEND(header);
        domainid_t receiver = AOS_RPC_HEADER_RECV(header);
        aos_rpc_msg_t message_type = AOS_RPC_HEADER_MSG(header);

        assert(receiver == disp_get_domain_id());

        uintptr_t *buf = msg.words + 1;
        char name[AOS_RPC_BUFFER_SIZE];
        memcpy(name, buf, AOS_RPC_BUFFER_SIZE);

        switch (message_type) {
        case AOS_RPC_MSG_NS_REGISTER:;
            err = handle_register(name, sender);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to handle AOS_RPC_MSG_NS_REGISTER\n");
            }
            break;
        case AOS_RPC_MSG_NS_LOOKUP:;
            err = handle_lookup(name, sender);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to handle AOS_RPC_MSG_NS_LOOKUP\n");
            }
            break;
        default:
            USER_PANIC("Nameserver received unknown msg\n");
        }

        // Want to receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(), MKCLOSURE(handler, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

        return;
    } else if (lmp_err_is_transient(err)) {
        // Receive further messages
        err = lmp_chan_register_recv(chan, get_default_waitset(), MKCLOSURE(handler, arg));
        if (err_is_fail(err)) {
            goto fail;
        }

        return;
    }

fail:
    DEBUG_ERR(err, "nameserver_handler failed hard");
}

int main(int argc, char *argv[])
{
    errval_t err;

    DEBUG_NS("Hello, I'm the nameserver\n");

    ht = create_hashtable();

    err = lmp_chan_register_recv(get_init_server_chan(), get_default_waitset(),
                                 MKCLOSURE(handler, NULL));
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_REGISTER_RECV);
    }

    while (1) {
        event_dispatch(get_default_waitset());
    }

    return EXIT_SUCCESS;
}
