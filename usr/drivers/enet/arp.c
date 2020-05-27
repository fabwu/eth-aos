#include <assert.h>
#include <stdlib.h>
#include <netutil/etharp.h>
#include <netutil/ip.h>
#include <netutil/htons.h>
#include <collections/hash_table.h>
#include "consts.h"
#include "ethernet.h"
#include "ip.h"

#include "arp.h"

#define ARP_PROBE_MESSAGE_COUNT 3

struct arp_state {
    collections_hash_table *cache;  ///< ARP cache with ip as key and mac address in
                                    ///< network byte order as entry.
};

static struct arp_state state;


errval_t arp_init(void)
{
    // Create arp cache table
    collections_hash_create(&state.cache, NULL);
    assert(state.cache != NULL);

    return SYS_ERR_OK;
}

static errval_t arp_send_raw(ip_addr_t dest_ip, ip_addr_t src_ip, uint16_t opcode,
                             struct eth_addr dest_eth)
{
    struct ethernet_frame_id *frame;
    struct arp_hdr *arp;
    errval_t err = ethernet_start_send_frame(dest_eth, consts_eth_self,
                                             htons(ETH_TYPE_ARP), &frame, (void **)&arp);
    if (err_is_fail(err)) {
        return err;
    }

    arp->hwtype = htons(ARP_HW_TYPE_ETH);
    arp->proto = htons(ARP_PROT_IP);
    arp->hwlen = 0x6;
    arp->protolen = 0x4;
    arp->opcode = opcode;
    arp->eth_src = consts_eth_self;
    arp->ip_src = src_ip;
    arp->eth_dst = dest_eth;
    arp->ip_dst = dest_ip;

    return ethernet_send_frame(frame, sizeof(struct arp_hdr));
}

static void arp_handle_new_entry(struct arp_hdr *package)
{
    // Abort if our static ip is already in use
    // Because we send a probe message we should get an answer if our ip was in use
    if (package->ip_src == htonl(ENET_STATIC_IP)) {
        DEBUG_PRINTF("Stopping ip driver: Static ip address is already in use in "
                        "this network\n");
        assert(0);
    }

    // Add to hashtable
    uint64_t ip = (uint64_t)ntohl(package->ip_src);
    struct eth_addr *entry = collections_hash_find(state.cache, ip);
    if (entry == NULL) {
        // Address unkown: Add new entry
        entry = malloc(sizeof(struct eth_addr));
        collections_hash_insert(state.cache, ip, (void *)entry);
    }

    // Write new address (overwrite if entry already existed)
    ETHARP_DEBUG("ARP new entry for 0x%x\n", ip);
    *entry = package->eth_src;

    // Notify ip protocoll so pending packages can be sent
    ip_send_waiting_packages(ntohl(package->ip_src), package->eth_src);
}

errval_t arp_handle_package(struct arp_hdr *package)
{
    ETHARP_DEBUG("ARP package: 0x%x -> 0x%x [0x%x]\n", ntohl(package->ip_src),
                 ntohl(package->ip_dst), ntohs(package->opcode));
    switch (ntohs(package->opcode)) {
    case ARP_OP_REQ:
        if (package->ip_dst == htonl(ENET_STATIC_IP)) {
            // Send response to arp request for our static ip
            errval_t err = arp_send_raw(package->ip_src, htonl(ENET_STATIC_IP),
                                        htons(ARP_OP_REP), package->eth_src);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Could not answer arp request");
            }
        } else if (package->ip_dst == package->ip_src) {
            // Accept arp anouncements
            arp_handle_new_entry(package);
        }
        break;
    case ARP_OP_REP:
        if (package->ip_dst == 0 || package->ip_dst == htonl(ENET_STATIC_IP)) {
            arp_handle_new_entry(package);
        }
        break;
    default:
        ETHARP_DEBUG("Unknown arp opcode: 0x%x\n", ntohs(package->opcode));
        break;
    }
    return SYS_ERR_OK;
}

errval_t arp_send_probe(void)
{
    errval_t err = SYS_ERR_OK;
    for (int i = 0; err_is_ok(err) && i < ARP_PROBE_MESSAGE_COUNT; ++i) {
        // Probe is a regular ARP request with empty source and the own ip as destination
        err = arp_send_raw(htonl(ENET_STATIC_IP), 0, htons(ARP_OP_REQ), consts_eth_zeros);
    }

    return err;
}

errval_t arp_send(ip_addr_t ip_addr)
{
    return arp_send_raw(htonl(ip_addr), htonl(ENET_STATIC_IP), htons(ARP_OP_REQ),
                        consts_eth_broadcast);
}

struct eth_addr *arp_lookup_ip(ip_addr_t ip)
{
    return collections_hash_find(state.cache, (uint64_t)ip);
}

void arp_print_cache(void)
{
    printf("ARP Cache:\n");
    printf("Address   HWAddress\n");

    if (collections_hash_traverse_start(state.cache) <= 0) {
        return;
    }

    uint64_t ip;
    struct eth_addr *eth;
    while (true) {
        eth = collections_hash_traverse_next(state.cache, &ip);
        if (eth == NULL) {
            break;
        }

        printf("%d.%d.%d.%d    %02x:%02x:%02x:%02x:%02x:%02x\n", (ip_addr_t)ip >> 24,
               ((ip_addr_t)ip >> 16) & 0xff, ((ip_addr_t)ip >> 8) & 0xff,
               (ip_addr_t)ip & 0xff, eth->addr[0], eth->addr[1], eth->addr[2],
               eth->addr[3], eth->addr[4], eth->addr[5]);
    }

    collections_hash_traverse_end(state.cache);
}
