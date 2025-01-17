#include <assert.h>
#include <errno.h>
#include <netutil/ip.h>
#include <netutil/udp.h>
#include <netutil/htons.h>
#include <netutil/checksum.h>
#include "ip.h"
#include "rpc.h"

#include "udp.h"

errval_t udp_init(void)
{
    return SYS_ERR_OK;
}

errval_t udp_handle_package(struct udp_hdr *udp, struct ip_hdr *ip)
{
    UDP_DEBUG("Handling udp datagram src=%d dest=%d len=%d chksum=%d\n", ntohs(udp->src),
              ntohs(udp->dest), ntohs(udp->len), ntohs(udp->chksum));

    if (udp->chksum == 0) {
        UDP_DEBUG("Datagram without checksum\n");
    } else {
        uint16_t checksum = inet_checksum_ip_pseudo(udp, ntohs(udp->len), ip);
        if (checksum != 0) {
            UDP_DEBUG("Checksum invalid 0x%x\n", checksum);
        }
    }

    return enet_rpc_handle_udp(udp, ntohl(ip->src));
}

errval_t udp_start_send_datagram(ip_addr_t dest_ip, uint16_t dest_port, uint16_t src_port,
                                 struct udp_datagram_id *datagram, void **ret_data)
{
    errval_t err;
    struct udp_hdr *udp;
    err = ip_start_send_package(dest_ip, IP_PROTO_UDP, &datagram->package, (void **)&udp);
    if (err_is_fail(err)) {
        return err;
    }

    udp->dest = htons(dest_port);
    udp->src = htons(src_port);
    // udp->len and udp->chksum are set in udp_send_datagram

    datagram->udp = udp;
    *ret_data = (void *)(udp + 1);

    return SYS_ERR_OK;
}

errval_t udp_send_datagram(struct udp_datagram_id *datagram, size_t size)
{
    size += sizeof(struct udp_hdr);
    datagram->udp->len = htons((uint16_t)size);
    datagram->udp->chksum = 0;
    datagram->udp->chksum = inet_checksum_ip_pseudo(datagram->udp, size,
                                                    datagram->package.ip);

    // Checksum has to be set to 0xffff if it turns out to be 0,
    // because 0 means the checksum is omitted.
    // 0xffff and 0x0 are equivalent in one complement representation
    if (datagram->udp->chksum == 0) {
        datagram->udp->chksum = 0xffff;
    }

    return ip_send_package(&datagram->package, size);
}
