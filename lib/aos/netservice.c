#include <errno.h>
#include <string.h>
#include <aos/deferred.h>
#include <aos/aos.h>
#include <aos/nameservice.h>

#include <aos/netservice.h>

static nameservice_chan_t udp_chan = NULL;

#define NETSERVICE_CONNECT_SLEEP_US (100 * 1000)

struct rpc_udp_service_state {
    aos_udp_handler_t handler;
    void *handler_state;
};

static errval_t aos_netservice_setup(void) {
    errval_t err;
    do {
        err = nameservice_lookup(ENET_UDP_SERVICE_NAME, &udp_chan);
        if (err_is_fail(err)) {
            NETS_DEBUG("Failed to lookup udp service.. Trying again later\n");
            errval_t sleep_err = barrelfish_usleep(NETSERVICE_CONNECT_SLEEP_US);  // 100ms
            if (err_is_fail(sleep_err)) {
                return sleep_err;
            }
        }
    } while (err_is_fail(err));

    return SYS_ERR_OK;
}

static void aos_udp_handler(void *st, void *message, size_t bytes, void **response,
                            size_t *response_bytes, struct capref tx_cap,
                            struct capref *rx_cap)
{
    struct rpc_udp_service_state *state = (struct rpc_udp_service_state *)st;
    if (bytes < sizeof(struct rpc_udp_header)) {
        NETS_DEBUG("Discarding invalid message in aos_udp_handler\n");
        return;
    }

    // The header is located at the end of the message
    struct rpc_udp_header *header = message + bytes - sizeof(struct rpc_udp_header);
    switch (header->_reserved) {
    case AOS_UDP_SEND:
        state->handler(state->handler_state, header, message, bytes - sizeof(struct rpc_udp_header));
        *response_bytes = 0;
        break;
    case AOS_UDP_CLOSE:
        // FIXME: Implement
        NETS_DEBUG("TODO Implement closing\n");
        break;
    default:
        NETS_DEBUG("Discarding invalid message in aos_udp_handler\n");
        return;
    }
}

errval_t aos_udp_send_single(struct rpc_udp_send *message, size_t size)
{
    errval_t err;
    if (udp_chan == NULL) {
        err = aos_netservice_setup();
        if (err_is_fail(err)) {
            return ENET_ERR_UDP_NOT_FOUND;
        }
    }

    return SYS_ERR_NOT_IMPLEMENTED;
}

errval_t aos_udp_send(uint16_t src_port, uint16_t dest_port, uint32_t dest_ip, void *data,
                      size_t size)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

errval_t aos_udp_listen(uint16_t port, aos_udp_handler_t udp_handler,
                        void *udp_handler_state)
{
    errval_t err;
    if (udp_chan == NULL) {
        err = aos_netservice_setup();
        if (err_is_fail(err)) {
            return err_push(err, ENET_ERR_UDP_NOT_FOUND);
        }
    }

    struct rpc_udp_listen message;

    // Generate service name for receiving udp datagrams
    size_t prefix_len = strlen(ENET_UDP_LISTEN_PREFIX);
    assert(prefix_len + 5 <= AOS_UDP_CALLBACK_MAX_LEN);
    strcpy(message.listen_service, ENET_UDP_LISTEN_PREFIX);
    sprintf(message.listen_service + prefix_len, "%d", port);

    // Register said service
    struct rpc_udp_service_state *service_state = malloc(sizeof(struct rpc_udp_service_state));
    service_state->handler = udp_handler;
    service_state->handler_state = udp_handler_state;
    err = nameservice_register(message.listen_service, aos_udp_handler, service_state);
    if (err_is_fail(err)) {
        free(service_state);
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
        err = ENET_ERR_UDP_LISTEN_FAILED;
        goto error;
    }

    return SYS_ERR_OK;

    errval_t dereg_err;
error:
    dereg_err = nameservice_deregister(message.listen_service);
    if (err_is_fail(dereg_err)) {
        DEBUG_ERR(dereg_err, "Could not deregister nameservice in error case");
    }
    free(service_state);
    return err;
}