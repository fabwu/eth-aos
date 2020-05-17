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
#include <aos/nameserver.h>

#include <hashtable/hashtable.h>

#if 1
#    define DEBUG_NS(fmt...) debug_printf(fmt);
#else
#    define DEBUG_NS(fmt...) ((void)0)
#endif

struct srv_entry {
    const char *name;
    domainid_t did;
};

struct hashtable *ht;

static void handler(void *arg)
{
    assert(arg == NULL);

    errval_t err;

    struct lmp_chan *chan = get_init_server_chan();
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    err = lmp_chan_recv(chan, &msg, NULL);

    if (err_is_ok(err)) {
        aos_rpc_header_t header = msg.words[0];
        uintptr_t *buf = msg.words + 1;

        char string[AOS_RPC_BUFFER_SIZE];
        memcpy(string, buf, AOS_RPC_BUFFER_SIZE);

        struct srv_entry *entry = (struct srv_entry *)malloc(sizeof(struct srv_entry));
        entry->name = string;
        entry->did = AOS_RPC_HEADER_SEND(header);
        ht->d.put_word(&ht->d, entry->name, strlen(entry->name), (uintptr_t)entry);

        DEBUG_NS("Received register request with name %s from %p\n", entry->name,
                 entry->did);

        header = AOS_RPC_HEADER(disp_get_domain_id(), entry->did, AOS_RPC_MSG_NS_REGISTER);
        err = lmp_protocol_send1(chan, header, AOS_NS_REGISTER_OK);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_LMP_PROTOCOL_SEND1);
            // TODO Clean up entry
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
