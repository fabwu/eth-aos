#ifndef AOS_PROTOCOL
#define AOS_PROTOCOL

#include <aos/aos.h>
#include <aos/ump.h>
#include <aos/lmp_protocol.h>

struct aos_chan {
    bool is_lmp;
    struct lmp_chan *lmp;
    domainid_t remote_pid;
};


void aos_protocol_set_ump(struct aos_ump *ump);
errval_t aos_protocol_wait_for(bool *ready_bit);

errval_t aos_protocol_send(struct aos_chan *chan, uint16_t message_type, struct capref cap,
                           uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
errval_t aos_protocol_recv(struct aos_chan *chan, uint16_t message_type,
                           struct capref *ret_cap, uintptr_t *ret_arg1,
                           uintptr_t *ret_arg2, uintptr_t *ret_arg3);
errval_t aos_protocol_send_bytes_cap(struct aos_chan *chan, uint16_t message_type,
                                     struct capref cap, size_t size, const uint8_t *bytes);
errval_t aos_protocol_recv_bytes_cap(struct aos_chan *chan, uint16_t message_type,
                                     struct capref *ret_cap, size_t *ret_size,
                                     uint8_t **ret_bytes);
errval_t aos_protocol_send_string_cap(struct aos_chan *chan, uint16_t message_type,
                                      struct capref cap, const char *string);
errval_t aos_protocol_recv_string_cap(struct aos_chan *chan, uint16_t message_type,
                                      struct capref *ret_cap, char **ret_string);

#endif
