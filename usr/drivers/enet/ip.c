#include <assert.h>
#include <errno.h>
#include <string.h>
#include <netutil/etharp.h>
#include <netutil/ip.h>
#include <netutil/htons.h>
#include "consts.h"
#include "ethernet.h"
#include "arp.h"

#include "ip.h"

struct ip_waiting_node {
    ip_addr_t ip;
    uint16_t length;
    struct ip_waiting_node *next;
    uint8_t data[ENET_MAX_PKT_SIZE - sizeof(struct eth_hdr)];
};

struct ip_state {
    struct ip_waiting_node *waiting_nodes;  ///< Linked list of ip packages that are
                                            ///< waiting on arp to be sent.
    size_t waiting_nodes_length;
};

struct ip_package_id {
    bool is_frame;
    union {
        struct ethernet_frame_id *frame;
        struct ip_waiting_node *ip_node;
    } id;
    struct ip_hdr *ip;
};

static struct ip_state state;

errval_t ip_init(void)
{
    state.waiting_nodes = NULL;
    state.waiting_nodes_length = 0;
    return SYS_ERR_OK;
}

errval_t ip_handle_package(struct ip_hdr *ip)
{
    if (ip->offset != 0 && ip->offset != htons(IP_DF)) {
        IP_DEBUG("Dropping fragmented package\n");
    }
    switch (ip->proto) {
    case IP_PROTO_ICMP:

        break;
    case IP_PROTO_UDP:
        IP_DEBUG("TODO UDP\n");
        break;
    default:
        IP_DEBUG("Unkown ip protocol (type=0x%x)\n", ip->proto);
        break;
    }

    return SYS_ERR_OK;
}

errval_t ip_start_send_package(ip_addr_t dest_ip, struct ip_package_id **ret_package,
                               void **ret_data)
{
    errval_t err = SYS_ERR_OK;
    assert(ret_package != NULL);
    assert(ret_data != NULL);

    struct ip_package_id *package = malloc(sizeof(struct ip_package_id));
    if (package == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    package->id.ip_node = NULL;

    struct eth_addr *dest_eth = arp_lookup_ip(dest_ip);
    struct ip_hdr *ip = NULL;

    if (dest_eth == NULL) {
        if (state.waiting_nodes_length >= IP_MAX_WAITING_NODES) {
            err = ENET_ERR_IP_BUFFER_FULL;
            goto out;
        }
        package->is_frame = false;
        package->id.ip_node = malloc(sizeof(struct ip_waiting_node));
        if (package->id.ip_node == NULL) {
            err = LIB_ERR_MALLOC_FAIL;
            goto out;
        }
        package->id.ip_node->ip = dest_ip;
        package->id.ip_node->next = NULL;
        ip = (struct ip_hdr *)&package->id.ip_node->data;
    } else {
        package->is_frame = true;
        err = ethernet_start_send_frame(*dest_eth, consts_eth_self, htons(ETH_TYPE_IP),
                                        &package->id.frame, (void **)&ip);
        if (err_is_fail(err)) {
            goto out;
        }
    }

    // ip->v_hl =
    // ip->tos =
    // ip->len is set when finishing the package
    // ip->id =
    ip->offset = htons(IP_DF);
    // ip->ttl =
    // ip->proto =
    // ip->chksum is set when finishing the package
    ip->src = htonl(ENET_STATIC_IP);
    ip->dest = htonl(dest_ip);

    package->ip = ip;
    *ret_package = package;
    *ret_data = (void *)(ip + 1);
out:
    if (err_is_fail(err)) {
        if (package != NULL) {
            if (!package->is_frame && package->id.ip_node != NULL) {
                free(package->id.ip_node);
            }
            free(package);
        }
        *ret_package = NULL;
        *ret_data = NULL;
    }

    return err;
}

void ip_send_waiting_packages(ip_addr_t dest_ip, struct eth_addr dest_eth)
{
    errval_t err;
    struct ip_waiting_node *parent = NULL;
    struct ip_waiting_node *cur = state.waiting_nodes;
    while (cur != NULL) {
        if (cur->ip == dest_ip) {
            struct ethernet_frame_id *frame;
            void *data;
            err = ethernet_start_send_frame(dest_eth, consts_eth_self, htons(ETH_TYPE_IP),
                                            &frame, &data);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Could not start sending pending ip package");
                continue;
            }

            memcpy(data, cur->data, cur->length);

            err = ethernet_send_frame(frame, cur->length);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Could not send pending ip package");
                continue;
            }

            if (parent != NULL) {
                parent->next = cur->next;
            }
            if (state.waiting_nodes == cur) {
                state.waiting_nodes = cur->next;
            }
            --state.waiting_nodes_length;

            free(cur);
        }
        parent = cur;
        cur = cur->next;
    }
}

errval_t ip_send_package(struct ip_package_id *package, size_t size)
{
    errval_t err;
    size += sizeof(struct ip_hdr);
    assert(size + sizeof(struct eth_hdr) <= ENET_MAX_PKT_SIZE);

    package->ip->len = htons((uint16_t)size);
    // FIXME: package->ip->chksum

    if (package->is_frame) {
        err = ethernet_send_frame(package->id.frame, size);
        if (err_is_fail(err)) {
            return err;
        }
    } else {
        package->id.ip_node->length = (uint16_t)size;
        // Add package to waiting nodes
        package->id.ip_node->next = state.waiting_nodes;
        state.waiting_nodes = package->id.ip_node;
        ++state.waiting_nodes_length;

        // Lookup ip again and send package if ip is present
        struct eth_addr *dest_eth = arp_lookup_ip(package->id.ip_node->ip);
        if (dest_eth != NULL) {
            ip_send_waiting_packages(package->id.ip_node->ip, *dest_eth);
        }
    }

    free(package);

    return SYS_ERR_OK;
}
