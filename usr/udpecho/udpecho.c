#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <aos/aos.h>
#include <aos/netservice.h>

#define UDPECHO_DEFAULT_PORT 50500
#define UDPECHO_MAX_STORED_ECHOS 50

struct udpecho_echo {
    struct rpc_udp_send *message;
    size_t size;
};

static struct udpecho_echo echos[UDPECHO_MAX_STORED_ECHOS];
static size_t echos_size = 0;

static void handle_datagram(void *state, struct rpc_udp_header *header, void *data)
{
    printf("[udpecho] ip=0x%x port=%d\n", header->src_ip, header->dest_port);

    if (echos_size < UDPECHO_MAX_STORED_ECHOS) {
        // Echo datagram back to sender
        size_t response_size = sizeof(struct rpc_udp_send) + header->length;
        struct rpc_udp_send *message = malloc(response_size);
        if (message == NULL) {
            DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "Could not create echo datagram");
            return;
        }
        message->src_port = header->dest_port;
        message->dest_port = header->src_port;
        message->dest_ip = header->src_ip;
        memcpy(message + 1, data, header->length);

        echos[echos_size].message = message;
        echos[echos_size].size = response_size;
        ++echos_size;
    } else {
        printf("[udpecho] Not sending echo: Intermediate store full\n");
    }
}

static void udpecho_send_echos(void)
{
    for (int i = 0; i < echos_size; ++i) {
        errval_t err = netservice_udp_send_single(echos[i].message, echos[i].size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to echo udp datagram");
        }
        free(echos[i].message);
    }
    echos_size = 0;
}

int main(int argc, char *argv[])
{
    errval_t err;
    echos_size = 0;

    printf("[udpecho] Starting udp echo server\n");

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

    // Listen on given port
    err = netservice_udp_listen(port, handle_datagram, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to listen on given port");
        printf("[udpecho] Failed to listen on port %d\n", port);
        return err;
    }

    printf("[udpecho] Listening on port %d\n", port);

    // Wait for incoming and outgoing messages
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        if (echos_size > 0) {
            udpecho_send_echos();

            // Comment in the lines below to test udp close after sending the first echos
            // err = netservice_udp_close(port);
            // if (err_is_fail(err)) {
            //     DEBUG_ERR(err, "Failed to close port");
            //     printf("[udpecho] Failed to close port %d\n", port);
            // } else {
            //     printf("[udpecho] Closed port %d\n", port);
            // }
            // return err;
        }

        err = event_dispatch_non_block(default_ws);
        if (err_is_fail(err) && err != LIB_ERR_NO_EVENT) {
            return err_push(err, LIB_ERR_EVENT_DISPATCH);
        }
        thread_yield();
    }

    return 0;
}
