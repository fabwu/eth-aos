#include <errno.h>
#include <string.h>
#include <aos/deferred.h>
#include <aos/aos.h>
#include <aos/nameservice.h>

#include <aos/netservice.h>

#define NETSERVICE_CONNECT_SLEEP_US (100 * 1000)

struct rpc_udp_service_state {
    netservice_udp_handler_t handler;
    void *handler_state;
    uint16_t port;
    bool closing;
};

struct netservice_listener_node {
    struct rpc_udp_service_state state;
    struct netservice_listener_node *next;
};

static nameservice_chan_t udp_chan = NULL;
static nameservice_chan_t arp_chan = NULL;
static struct netservice_listener_node *local_listeners = NULL;

static nameservice_chan_t netservice_lookup(const char *name) {
    errval_t err;
    nameservice_chan_t chan;
    do {
        err = nameservice_lookup(name, &chan);
        if (err_is_fail(err)) {
            NETS_DEBUG("Failed to lookup %s service.. Trying again later\n", name);
            errval_t sleep_err = barrelfish_usleep(NETSERVICE_CONNECT_SLEEP_US);  // 100ms
            if (err_is_fail(sleep_err)) {
                DEBUG_ERR(err, "Error in barrelfish_usleep");
            }
        }
    } while (err_is_fail(err));

    return chan;
}

static errval_t netservice_setup(void) {
    udp_chan = netservice_lookup(ENET_UDP_SERVICE_NAME);
    return SYS_ERR_OK;
}

static void netservice_udp_handler(void *st, void *message, size_t bytes, void **response,
                            size_t *response_bytes, struct capref tx_cap,
                            struct capref *rx_cap)
{
    *response_bytes = 0;
    if (bytes < sizeof(struct rpc_udp_header)) {
        NETS_DEBUG("Discarding invalid message in netservice_udp_handler\n");
        return;
    }
    struct rpc_udp_service_state *state = (struct rpc_udp_service_state *)st;
    NETS_DEBUG("Handling udp for port %d\n", state->port);

    // The header is located at the end of the message
    struct rpc_udp_header *header = message + bytes - sizeof(struct rpc_udp_header);

    static struct rpc_udp_response udp_response;
    udp_response.type = header->_reserved;
    udp_response.success = false;

    switch (header->_reserved) {
    case AOS_UDP_SEND:
        state->handler(state->handler_state, header, message);
        *response_bytes = 0;
        break;
    case AOS_UDP_CLOSE:
        NETS_DEBUG("Handle udp close request for port %d\n", header->dest_port);
        udp_response.success = header->dest_port == state->port && state->closing;
        *response = &udp_response;
        *response_bytes = sizeof(struct rpc_udp_response);
        break;
    default:
        NETS_DEBUG("Discarding invalid message in netservice_udp_handler\n");
        return;
    }
}

errval_t netservice_udp_send_single(struct rpc_udp_send *message, size_t size)
{
    if (size - sizeof(struct rpc_udp_send) > ENET_UDP_MAX_DATA) {
        return ENET_ERR_UDP_EXCEEDING_SIZE;
    }

    errval_t err;
    if (udp_chan == NULL) {
        err = netservice_setup();
        if (err_is_fail(err)) {
            return ENET_ERR_UDP_NOT_FOUND;
        }
    }

    message->type = AOS_UDP_SEND;

    struct rpc_udp_response *response;
    size_t response_size;
    err = nameservice_rpc(udp_chan, (void *)message, size, (void **)&response, &response_size, NULL_CAP, NULL_CAP);
    if (err_is_fail(err)) {
        return err_push(err, ENET_ERR_NETSERVICE_SEND);
    }

    bool success = response->success;
    free(response);
    return success ? SYS_ERR_OK : ENET_ERR_NETSERVICE_SEND;
}

errval_t netservice_udp_send(uint16_t src_port, uint16_t dest_port, uint32_t dest_ip, void *data,
                      size_t size)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

errval_t netservice_udp_listen(uint16_t port, netservice_udp_handler_t udp_handler,
                               void *udp_handler_state)
{
    errval_t err;
    if (udp_chan == NULL) {
        err = netservice_setup();
        if (err_is_fail(err)) {
            return err_push(err, ENET_ERR_UDP_NOT_FOUND);
        }
    }

    struct rpc_udp_listen message;
    message.type = AOS_UDP_LISTEN;
    message.port = port;

    // Generate service name for receiving udp datagrams
    size_t prefix_len = strlen(ENET_UDP_LISTEN_PREFIX);
    assert(prefix_len + 5 <= AOS_UDP_CALLBACK_MAX_LEN);
    strcpy(message.listen_service, ENET_UDP_LISTEN_PREFIX);
    sprintf(message.listen_service + prefix_len, "%d", port);

    // Register said service
    struct netservice_listener_node *listener = malloc(sizeof(struct netservice_listener_node));
    struct rpc_udp_service_state *service_state = &listener->state;
    service_state->handler = udp_handler;
    service_state->handler_state = udp_handler_state;
    service_state->port = port;
    service_state->closing = false;
    err = nameservice_register(message.listen_service, netservice_udp_handler, service_state);
    if (err_is_fail(err)) {
        free(listener);
        return err_push(err, ENET_ERR_UDP_LISTEN_FAILED);
    }

    // Notify udp service to send the correct udp datagrams to our service
    struct rpc_udp_response *response;
    size_t response_size;
    err = nameservice_rpc(udp_chan, (void *)&message, sizeof(struct rpc_udp_listen), (void **)&response, &response_size, NULL_CAP, NULL_CAP);
    if (err_is_fail(err)) {
        err = err_push(err, ENET_ERR_UDP_LISTEN_FAILED);
        goto error;
    }
    if (!response->success) {
        free(response);
        err = ENET_ERR_UDP_LISTEN_FAILED;
        goto error;
    }

    free(response);
    listener->next = local_listeners;
    local_listeners = listener;
    return SYS_ERR_OK;

    errval_t dereg_err;
error:
    dereg_err = nameservice_deregister(message.listen_service);
    if (err_is_fail(dereg_err)) {
        DEBUG_ERR(dereg_err, "Could not deregister nameservice in error case");
    }
    free(listener);
    return err;
}

errval_t netservice_udp_close(uint16_t port)
{
    errval_t err;

    // Search for listener with given port
    struct netservice_listener_node *parent = NULL;
    struct netservice_listener_node *current = local_listeners;
    while (current != NULL && current->state.port != port) {
        parent = current;
        current = current->next;
    }
    if (current == NULL) {
        return ENET_ERR_NETSERVICE_CLOSE;
    }
    assert(current->state.port == port);

    //Start the closing procedure
    current->state.closing = true;

    if (udp_chan == NULL) {
        err = netservice_setup();
        if (err_is_fail(err)) {
            return err_push(err, ENET_ERR_UDP_NOT_FOUND);
        }
    }

    // Send close request to udp service
    struct rpc_udp_close message;
    message.type = AOS_UDP_CLOSE;
    message.port = port;

    struct rpc_udp_response *response;
    size_t response_size;
    err = nameservice_rpc(udp_chan, (void *)&message, sizeof(struct rpc_udp_close),
                          (void **)&response, &response_size, NULL_CAP, NULL_CAP);
    if (err_is_fail(err)) {
        return err_push(err, ENET_ERR_NETSERVICE_CLOSE);
    } else if (!response->success) {
        return ENET_ERR_NETSERVICE_CLOSE;
    }
    free(response);

    // Remove listener from local list
    if (parent != NULL) {
        parent->next = current->next;
    }
    if (local_listeners == current) {
        local_listeners = current->next;
    }
    free(current);

    return SYS_ERR_OK;
}

errval_t netservice_arp_print_cache(void) {
    if (arp_chan == NULL) {
        errval_t err = nameservice_lookup(ENET_ARP_SERVICE_NAME, &arp_chan);
        if (err_is_fail(err)) {
            printf("Could not print arp table (arp service unreachable)\n");
            return err_push(err, ENET_ERR_ARP_NOT_FOUND);
        }
    }

    uint8_t message = AOS_ARP_PRINT_CACHE;
    return nameservice_rpc(arp_chan, (void *)&message, 1, NULL, NULL, NULL_CAP, NULL_CAP);
}
