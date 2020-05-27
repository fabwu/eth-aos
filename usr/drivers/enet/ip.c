#include <assert.h>
#include <errno.h>
#include <string.h>
#include <netutil/etharp.h>
#include <netutil/ip.h>
#include <netutil/htons.h>
#include <netutil/checksum.h>
#include "consts.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"

#include "ip.h"

struct ip_waiting_node {
    ip_addr_t ip;  ///< Target address in host byte order
    uint16_t length; ///< Length of ip package including header
    struct ip_waiting_node *next;
    uint8_t data[ENET_MAX_PKT_SIZE - sizeof(struct eth_hdr)];
};

struct ip_state {
    struct ip_waiting_node *waiting_nodes;  ///< Linked list of ip packages that are
                                            ///< waiting on arp to be sent.
    size_t waiting_nodes_length;
    uint16_t next_id;  ///< Giving each package an id by counting up.
};

static struct ip_state state;

errval_t ip_init(void)
{
    state.waiting_nodes = NULL;
    state.waiting_nodes_length = 0;
    state.next_id = 1;
    return SYS_ERR_OK;
}

errval_t ip_handle_package(struct ip_hdr *ip)
{
    errval_t err;
    IP_DEBUG("Handling ip package\n");
    uint16_t checksum = inet_checksum((void *)ip, IPH_HL(ip) * 4);
    if (checksum != 0) {
        IP_DEBUG("Checksum invalid 0x%x\n", checksum);
    }

    if (IPH_V(ip) != 4) {
        IP_DEBUG("Dropping package of ip version: %d\n", IPH_V(ip));
        return ENET_ERR_IP_DROPPING;
    }

    if (ip->offset != 0 && ip->offset != htons(IP_DF)) {
        IP_DEBUG("Dropping fragmented package\n");
        return ENET_ERR_IP_DROPPING;
    }

    if (ip->dest != htonl(ENET_STATIC_IP)
        && (ntohl(ip->dest) & ~ENET_STATIC_SUBNET) != ~ENET_STATIC_SUBNET) {
        IP_DEBUG("Dropping ip package: Destination is neither us nor broadcast "
                 "(dest=0x%x)\n",
                 ntohl(ip->dest));
        return ENET_ERR_IP_DROPPING;
    }

    IP_DEBUG("From 0x%x to 0x%x\n", ntohl(ip->src), ntohl(ip->dest));
    void *data = ((void *)ip) + IPH_HL(ip) * 4;
    switch (ip->proto) {
    case IP_PROTO_ICMP:
        IP_DEBUG("ICMP\n");
        err = icmp_handle_package(data, ntohl(ip->src), ntohs(ip->len) - IPH_HL(ip) * 4);
        if (err == ENET_ERR_ICMP_DROPPING) {
            return SYS_ERR_OK;
        }
        return err;
    case IP_PROTO_UDP:
        IP_DEBUG("UDP\n");
        return udp_handle_package(data, ntohl(ip->src));
    default:
        IP_DEBUG("Unkown ip protocol (type=0x%x)\n", ip->proto);
        return ENET_ERR_IP_DROPPING;
    }
}

errval_t ip_start_send_package(ip_addr_t dest_ip, uint8_t protocol,
                               struct ip_package_id *package, void **ret_data)
{
    errval_t err;
    assert(package != NULL);
    assert(ret_data != NULL);

    package->id.ip_node = NULL;

    struct eth_addr *dest_eth = arp_lookup_ip(dest_ip);
    struct ip_hdr *ip;

    if (dest_eth == NULL) {
        // Send arp request to discover unkown hw address for given ip address
        err = arp_send(dest_ip);
        if (err_is_fail(err)) {
            IP_DEBUG("Could not send arp request for unkown ip 0x%x\n", dest_ip);
            return err;
        }

        // Reached limit of packages that are buffered (client has to retry later)
        if (state.waiting_nodes_length >= IP_MAX_WAITING_NODES) {
            return ENET_ERR_IP_BUFFER_FULL;
        }

        // Buffer ip package in memory and send it as soon as hw address is discovered
        package->is_frame = false;
        package->id.ip_node = malloc(sizeof(struct ip_waiting_node));
        if (package->id.ip_node == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        package->id.ip_node->ip = dest_ip;
        package->id.ip_node->next = NULL;
        ip = (struct ip_hdr *)&package->id.ip_node->data;
    } else {
        package->is_frame = true;
        err = ethernet_start_send_frame(*dest_eth, consts_eth_self, htons(ETH_TYPE_IP),
                                        &package->id.frame, (void **)&ip);
        if (err_is_fail(err)) {
            return err;
        }
    }

    // 4 = IPv4, IP_HLEN / 4 = 5 integers = no options
    IPH_VHL_SET(ip, 4, IP_HLEN / 4);
    ip->tos = 0;
    // ip->len is set when finishing the package
    ip->id = state.next_id;
    ++state.next_id;
    ip->offset = htons(IP_DF);
    ip->ttl = IP_TTL;
    ip->proto = protocol;
    // ip->chksum is set when finishing the package
    ip->src = htonl(ENET_STATIC_IP);
    ip->dest = htonl(dest_ip);

    package->ip = ip;
    *ret_data = (void *)(ip + 1);

    return SYS_ERR_OK;
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
    package->ip->chksum = 0;
    package->ip->chksum = inet_checksum(package->ip, sizeof(struct ip_hdr));

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

    return SYS_ERR_OK;
}
