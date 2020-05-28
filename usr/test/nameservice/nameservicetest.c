/**
 * \file
 * \brief init process for child spawning
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


#define PANIC_IF_FAIL(err, msg)                                                          \
    if (err_is_fail(err)) {                                                              \
        USER_PANIC_ERR(err, msg);                                                        \
    }

#define SERVICE_NAME_1 "myservicename"
#define SERVICE_NAME_2 "empty"
#define SERVICE_NAME_3 "deregister"
#define UNKNOWN_SERVICE "???WHAT???"
#define TEST_BINARY "nameservicetest"
/*
 * ============================================================================
 * Client
 * ============================================================================
 */

static char *myrequest = "request !!";

static void run_client(void)
{
    errval_t err;

    // look up unknown service
    nameservice_chan_t chan;

    err = nameservice_lookup(UNKNOWN_SERVICE, &chan);
    if (err == err_no(LIB_ERR_NS_LOOKUP)) {
        debug_printf("Got error when looking up unknown service\n");
    } else {
        PANIC_IF_FAIL(err, "no or wrong error for unknown service\n");
    }

    // look up deregistered service
    err = nameservice_lookup(SERVICE_NAME_3, &chan);
    if (err == err_no(LIB_ERR_NS_LOOKUP)) {
        debug_printf("Got error when looking up deregistered service\n");
    } else {
        PANIC_IF_FAIL(err, "no or wrong error for deregistered service\n");
    }

    // look up existing service
    err = nameservice_lookup(SERVICE_NAME_1, &chan);
    PANIC_IF_FAIL(err, "failed to lookup service\n");
    debug_printf("Got the service %p. Sending request '%x'\n", chan, myrequest[0]);

    void *request = myrequest;
    size_t request_size = strlen(myrequest);

    void *response1;
    void *response2;
    size_t response_bytes;
    err = nameservice_rpc(chan, request, request_size, &response1, &response_bytes,
                          NULL_CAP, NULL_CAP);
    PANIC_IF_FAIL(err, "failed to do the nameservice rpc\n");

    debug_printf("got response: %s\n", (char *)response1);
    free(response1);

    err = nameservice_rpc(chan, request, request_size, &response2, &response_bytes,
                          NULL_CAP, NULL_CAP);
    PANIC_IF_FAIL(err, "failed to do the nameservice rpc\n");

    debug_printf("got response: %s\n", (char *)response2);
    free(response2);

    // test empty request/response
    err = nameservice_lookup(SERVICE_NAME_2, &chan);
    PANIC_IF_FAIL(err, "failed to lookup service\n");
    debug_printf("Got the service %p. Sending request '%x'\n", chan, myrequest[0]);

    err = nameservice_rpc(chan, NULL, 0, NULL, NULL, NULL_CAP, NULL_CAP);
    PANIC_IF_FAIL(err, "failed to do the nameservice rpc\n");
    debug_printf("client: done\n");
}

/*
 * ============================================================================
 * Server
 * ============================================================================
 */

static char *myresponse = "reply!!";

static void server_recv_handler(void *st, void *message, size_t bytes, void **response,
                                size_t *response_bytes, struct capref rx_cap,
                                struct capref *tx_cap)
{
    debug_printf("server: got a request: %s\n", (char *)message);
    *response = myresponse;
    *response_bytes = strlen(myresponse);
}

static void server_no_response(void *st, void *message, size_t bytes, void **response,
                               size_t *response_bytes, struct capref rx_cap,
                               struct capref *tx_cap)
{
    debug_printf("server: got a request: %s\n", (char *)message);
    debug_printf("server: but sending no response MUHAHA!\n");
    *response = NULL;
    *response_bytes = 0;
}

static void run_server(void)
{
    errval_t err;

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME_1);
    err = nameservice_register(SERVICE_NAME_1, server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    debug_printf("register with nameservice '%s' TWICE!\n", SERVICE_NAME_1);
    err = nameservice_register(SERVICE_NAME_1, server_recv_handler, NULL);
    if (err == err_no(LIB_ERR_NS_DUP_NAME)) {
        debug_printf("Got error when registering service twice\n");
    } else {
        PANIC_IF_FAIL(err, "no or wrong error for registering service twice\n");
    }

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME_2);
    err = nameservice_register(SERVICE_NAME_2, server_no_response, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME_3);
    err = nameservice_register(SERVICE_NAME_3, server_no_response, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    debug_printf("deregister with nameservice '%s'\n", SERVICE_NAME_3);
    err = nameservice_deregister(SERVICE_NAME_3);
    PANIC_IF_FAIL(err, "failed to deregister...\n");

#if 1
    domainid_t did;
    debug_printf("spawning test binary '%s'\n", TEST_BINARY);
    err = aos_rpc_process_spawn(get_init_rpc(), TEST_BINARY " a", disp_get_core_id(),
                                &did);
    PANIC_IF_FAIL(err, "failed to spawn test\n");
#endif

    while (1) {
        event_dispatch(get_default_waitset());
    }
}

/*
 * ============================================================================
 * Main
 * ============================================================================
 */

int main(int argc, char *argv[])
{
    if (argc == 2) {
        debug_printf("nameservicetest: running client!\n");
        run_client();
    } else {
        debug_printf("nameservicetest: running server!\n");
        run_server();
    }

    return EXIT_SUCCESS;
}
