#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <aos/nameservice.h>
#include <aos/netservice.h>

#define UDPECHO_DEFAULT_PORT 50500

int main(int argc, char *argv[])
{
    errval_t err;

    printf("Starting udp echo server\n");

    // Parsing command line
    uint16_t port;
    if (argc <= 1) {
        port = UDPECHO_DEFAULT_PORT;
        printf("No port was given. Using default: %d\n", port);
    } else {
        int p = atoi(argv[1]);
        if (p <= 0 || p > UINT16_MAX) {
            port = UDPECHO_DEFAULT_PORT;
            printf("Invalid port was given. Using default: %d\n", port);
        } else {
            port = p;
        }
    }

    nameservice_chan_t udp_chan;
    do {
        err = nameservice_lookup("udp", &udp_chan);
        if (err_is_fail(err)) {
            printf("Failed to lookup udp service.. Trying again later\n");
            errval_t sleep_err = barrelfish_usleep(100 * 1000);  // 100ms
            assert(err_is_ok(sleep_err));
        }
    } while (err_is_fail(err));

    size_t size = sizeof(struct rpc_udp_send) + 7;
    struct rpc_udp_send *message = malloc(size);
    message->type = AOS_UDP_SEND;
    message->dest_ip = 0x0a000001;
    message->dest_port = 50600;
    message->src_port = port;
    char *data = (char *)(message + 1);
    strcpy(data, "hello\n");

    struct rpc_udp_response *response;
    size_t response_size;
    err = nameservice_rpc(udp_chan, (void *)message, size, (void **)&response, &response_size, NULL_CAP, NULL_CAP);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed trying to use nameservice_rpc");
    }
    free(message);

    if (response->success) {
        printf("Send udp package\n");
    } else {
        printf("Failed to send udp package\n");
    }
    free(response);

    return 0;
}
