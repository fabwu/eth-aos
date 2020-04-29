#ifndef AOS_PROTOCOL
#define AOS_PROTOCOL

#include <aos/aos.h>
#include <aos/ump.h>
#include <aos/lmp_protocol.h>

struct aos_chan {
    bool is_lmp;
    struct lmp_chan *lmp;
    domainid_t local_pid;
    domainid_t remote_pid;
};

struct aos_chan make_aos_chan_lmp(struct lmp_chan *lmp);
struct aos_chan make_aos_chan_ump(domainid_t local_pid, domainid_t remote_pid);

struct callback {
    void (*handler)(void *arg, uint8_t *buf);
    void *arg;
};

#define MKCALLBACK(h,a)  (struct callback){ /*handler*/ (h), /*arg*/ (a) }
#define NOP_CALLBACK     MKCALLBACK(NULL, NULL)

void aos_protocol_set_ump(struct aos_ump *ump);
errval_t aos_protocol_wait_for(bool *ready_bit);

errval_t aos_protocol_register_recv(domainid_t pid, struct callback callback);

errval_t aos_protocol_send(struct aos_chan *chan, uint16_t message_type, struct capref cap,
                           uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

#define aos_protocol_send0(chan, msg_type)                                               \
    aos_protocol_send((chan), (msg_type), NULL_CAP, 0, 0, 0)
#define aos_protocol_send1(chan, msg_type, arg1)                                         \
    aos_protocol_send((chan), (msg_type), NULL_CAP, (arg1), 0, 0)
#define aos_protocol_send2(chan, msg_type, arg1, arg2)                                   \
    aos_protocol_send((chan), (msg_type), NULL_CAP, (arg1), (arg2), 0)
#define aos_protocol_send3(chan, msg_type, arg1, arg2, arg3)                             \
    aos_protocol_send((chan), (msg_type), NULL_CAP, (arg1), (arg2), (arg3))
#define aos_protocol_send_cap(chan, msg_type, send_cap)                                  \
    aos_protocol_send((chan), (msg_type), (send_cap), 0, 0, 0)
#define aos_protocol_send_cap1(chan, msg_type, send_cap, arg1)                           \
    aos_protocol_send((chan), (msg_type), (send_cap), (arg1), 0, 0)
#define aos_protocol_send_cap2(chan, msg_type, send_cap, arg1, arg2)                     \
    aos_protocol_send((chan), (msg_type), (send_cap), (arg1), (arg2), 0)
#define aos_protocol_send_cap3(chan, msg_type, send_cap, arg1, arg2, arg3)               \
    aos_protocol_send((chan), (msg_type), (send_cap), (arg1), (arg2), (arg3))

errval_t aos_protocol_recv(struct aos_chan *chan, uint16_t message_type,
                           struct capref *ret_cap, uintptr_t *ret_arg1,
                           uintptr_t *ret_arg2, uintptr_t *ret_arg3);

#define aos_protocol_recv0(chan, msg_type)                                               \
    aos_protocol_recv((chan), (msg_type), NULL, NULL, NULL, NULL)
#define aos_protocol_recv1(chan, msg_type, ret_arg1)                                     \
    aos_protocol_recv((chan), (msg_type), NULL, (ret_arg1), NULL, NULL)
#define aos_protocol_recv2(chan, msg_type, ret_arg1, ret_arg2)                           \
    aos_protocol_recv((chan), (msg_type), NULL, (ret_arg1), (ret_arg2), NULL)
#define aos_protocol_recv3(chan, msg_type, ret_arg1, ret_arg2, ret_arg3)                 \
    aos_protocol_recv((chan), (msg_type), NULL, (ret_arg1), (ret_arg2), (ret_arg3))
#define aos_protocol_recv_cap(chan, msg_type, ret_cap)                                   \
    aos_protocol_recv((chan), (msg_type), (ret_cap), NULL, NULL, NULL)
#define aos_protocol_recv_cap1(chan, msg_type, ret_cap, ret_arg1)                        \
    aos_protocol_recv((chan), (msg_type), (ret_cap), (ret_arg1), NULL, NULL)
#define aos_protocol_recv_cap2(chan, msg_type, ret_cap, ret_arg1, ret_arg2)              \
    aos_protocol_recv((chan), (msg_type), (ret_cap), (ret_arg1), (ret_arg2), NULL)
#define aos_protocol_recv_cap3(chan, msg_type, ret_cap, ret_arg1, ret_arg2, ret_arg3)    \
    aos_protocol_recv((chan), (msg_type), (ret_cap), (ret_arg1), (ret_arg2), (ret_arg3))

errval_t aos_protocol_send_bytes_cap(struct aos_chan *chan, uint16_t message_type,
                                     struct capref cap, size_t size, const uint8_t *bytes);
errval_t aos_protocol_recv_bytes_cap(struct aos_chan *chan, uint16_t message_type,
                                     struct capref *ret_cap, size_t *ret_size,
                                     uint8_t **ret_bytes);

#define aos_protocol_send_bytes(chan, msg_type, size, bytes)                             \
    aos_protocol_send_bytes_cap((chan), (msg_type), NULL_CAP, (size), (bytes))
#define aos_protocol_recv_bytes(chan, msg_type, ret_size, ret_bytes)                     \
    aos_protocol_recv_bytes_cap((chan), (msg_type), NULL, (ret_size), (ret_bytes))

errval_t aos_protocol_send_string_cap(struct aos_chan *chan, uint16_t message_type,
                                      struct capref cap, const char *string);
errval_t aos_protocol_recv_string_cap(struct aos_chan *chan, uint16_t message_type,
                                      struct capref *ret_cap, char **ret_string);

#define aos_protocol_send_string(chan, msg_type, string)                                 \
    aos_protocol_send_string_cap((chan), (msg_type), NULL_CAP, (string))
#define aos_protocol_recv_string(chan, msg_type, ret_string)                             \
    aos_protocol_recv_string_cap((chan), (msg_type), NULL, (ret_string))

#endif
