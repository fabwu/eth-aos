#include <errno.h>
#include <netutil/ip.h>
#include <netutil/icmp.h>
#include <netutil/htons.h>
#include <netutil/checksum.h>
#include "ip.h"

#include "icmp.h"

errval_t icmp_handle_package(struct icmp_echo_hdr *icmp, ip_addr_t src, uint16_t size)
{
    errval_t err;
    if (icmp->type != ICMP_ECHO) {
        ICMP_DEBUG("Dropping icmp package of type %d\n", icmp->type);
        return ENET_ERR_ICMP_DROPPING;
    }

    ICMP_DEBUG("Handling echo request from 0x%x\n", src);
    ICMP_DEBUG("type=%d code=%d chksum=0x%x\n", icmp->type, icmp->code, ntohs(icmp->chksum));
    ICMP_DEBUG("id=%d seqno=%d\n", ntohs(icmp->id), ntohs(icmp->seqno));

    uint16_t checksum = inet_checksum((void *)icmp, size);
    if (checksum != 0) {
        ICMP_DEBUG("Invalid checksum: 0x%x\n", checksum);
    }

    struct ip_package_id package;
    struct icmp_echo_hdr *reply;
    err = ip_start_send_package(src, IP_PROTO_ICMP, &package, (void **)&reply);
    if (err_is_fail(err)) {
        return err;
    }

    reply->type = ICMP_ER;
    reply->code = 0;
    reply->chksum = 0;
    reply->id = icmp->id;
    reply->seqno = icmp->seqno;

    size_t data_size = size - sizeof(struct icmp_echo_hdr);
    if (data_size > 0) {
        memcpy(reply + 1, icmp + 1, data_size);
    }

    reply->chksum = inet_checksum((void *)reply, size);

    err = ip_send_package(&package, size);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}
