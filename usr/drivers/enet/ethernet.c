#include <assert.h>
#include <netutil/etharp.h>
#include <netutil/htons.h>
#include <devif/queue_interface_backend.h>
#include "enet.h"
#include "arp.h"

#include "ethernet.h"

struct ethernet_tx_node {
    struct eth_hdr *base;
    struct ethernet_tx_node *next;
};

struct ethernet_state {
    void *rx_base;
    void *tx_base;
    struct enet_queue *txq;
    regionid_t tx_rid;
    struct ethernet_tx_node *nodes;      ///< Linked list of free send buffers.
    struct ethernet_tx_node *all_nodes;  ///< Array containing all send buffer nodes (free
                                         ///< and allocated ones).
};

static struct ethernet_state state;

errval_t ethernet_init(void *rx_base, void *tx_base, struct enet_queue *txq,
                       regionid_t tx_rid)
{
    state.rx_base = rx_base;
    state.tx_base = tx_base;
    state.txq = txq;
    state.tx_rid = tx_rid;
    state.nodes = NULL;

    struct ethernet_tx_node *nodes = malloc(TX_RING_SIZE
                                            * sizeof(struct ethernet_tx_node));
    if (nodes == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    state.all_nodes = nodes;

    void *tx_buffers = tx_base;
    for (int i = 0; i < TX_RING_SIZE; ++i) {
        nodes->base = tx_buffers;
        nodes->next = state.nodes;
        state.nodes = nodes;
        tx_buffers += ENET_MAX_BUF_SIZE;
        nodes += 1;
    }

    return SYS_ERR_OK;
}

errval_t ethernet_handle_frame(struct devq_buf *buf)
{
    struct eth_hdr *eth = state.rx_base + buf->offset + buf->valid_data;
    // FIXME: Only allow own mac and broadcast as destination
    switch (ntohs(eth->type)) {
    case ETH_TYPE_ARP:
        return arp_handle_package((struct arp_hdr *)(eth + 1));
    case ETH_TYPE_IP:
        // TOOD
        DEBUG_PRINTF("IP PACKAGE\n");
        break;
    default:
        ENET_DEBUG("Unknown package (type=0x%x): drop\n", ntohs(eth->type));
        break;
    }

    return SYS_ERR_OK;
}

errval_t ethernet_start_send_frame(struct eth_addr dest, struct eth_addr src,
                                   uint16_t type, struct ethernet_frame_id **ret_frame,
                                   void **ret_data)
{
    assert(ret_frame != NULL);
    assert(ret_data != NULL);

    // Reclaim used buffers
    errval_t err;
    do {
        struct devq_buf buf;
        err = devq_dequeue((struct devq *)state.txq, &buf.rid, &buf.offset, &buf.length,
                           &buf.valid_data, &buf.valid_length, &buf.flags);
        if (err_is_ok(err)) {
            assert(buf.offset % ENET_MAX_BUF_SIZE == 0);
            assert(state.tx_rid == buf.rid);
            size_t offset_index = buf.offset / ENET_MAX_BUF_SIZE;
            struct ethernet_tx_node *node = state.all_nodes + offset_index;
            assert(node->base == state.tx_base + buf.offset);
            node->next = state.nodes;
            state.nodes = node;
        }

    } while (err_is_ok(err));
    if (err != DEVQ_ERR_QUEUE_EMPTY) {
        return err;
    }

    if (state.nodes == NULL) {
        return ENET_ERR_ETH_NO_FREE_BUFFER;
    }

    *ret_frame = (struct ethernet_frame_id *)state.nodes;
    struct eth_hdr *eth = state.nodes->base;
    *ret_data = state.nodes->base + 1;
    state.nodes = state.nodes->next;

    eth->dst = dest;
    eth->src = src;
    eth->type = type;

    return SYS_ERR_OK;
}

errval_t ethernet_send_frame(struct ethernet_frame_id *frame, size_t size)
{
    assert(size + sizeof(struct eth_hdr) <= ENET_MAX_PKT_SIZE);
    struct ethernet_tx_node *node = (struct ethernet_tx_node *)frame;
    return devq_enqueue((struct devq *)state.txq, state.tx_rid,
                        (lvaddr_t)node->base - (lvaddr_t)state.tx_base, ENET_MAX_BUF_SIZE,
                        0, sizeof(struct eth_hdr) + size, 0);
}
