/**
 * \file
 * \brief LMP Protocol for AOS
 */

#ifndef _LIB_BARRELFISH_LMP_PROTOCOL_H
#define _LIB_BARRELFISH_LMP_PROTOCOL_H

errval_t lmp_protocol_send(struct lmp_chan *chan, uint16_t message_type, struct capref cap,
                           uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

#define lmp_protocol_send0(chan, msg_type)                                               \
    lmp_protocol_send((chan), (msg_type), NULL_CAP, 0, 0, 0)
#define lmp_protocol_send1(chan, msg_type, arg1)                                         \
    lmp_protocol_send((chan), (msg_type), NULL_CAP, (arg1), 0, 0)
#define lmp_protocol_send2(chan, msg_type, arg1, arg2)                                   \
    lmp_protocol_send((chan), (msg_type), NULL_CAP, (arg1), (arg2), 0)
#define lmp_protocol_send3(chan, msg_type, arg1, arg2, arg3)                             \
    lmp_protocol_send((chan), (msg_type), NULL_CAP, (arg1), (arg2), (arg3))
#define lmp_protocol_send_cap(chan, msg_type, send_cap)                                  \
    lmp_protocol_send((chan), (msg_type), (send_cap), 0, 0, 0)
#define lmp_protocol_send_cap1(chan, msg_type, send_cap, arg1)                           \
    lmp_protocol_send((chan), (msg_type), (send_cap), (arg1), 0, 0)
#define lmp_protocol_send_cap2(chan, msg_type, send_cap, arg1, arg2)                     \
    lmp_protocol_send((chan), (msg_type), (send_cap), (arg1), (arg2), 0)
#define lmp_protocol_send_cap3(chan, msg_type, send_cap, arg1, arg2, arg3)               \
    lmp_protocol_send((chan), (msg_type), (send_cap), (arg1), (arg2), (arg3))

errval_t lmp_protocol_recv(struct lmp_chan *chan, uint16_t message_type,
                           struct capref *ret_cap, uintptr_t *ret_arg1,
                           uintptr_t *ret_arg2, uintptr_t *ret_arg3);

#define lmp_protocol_recv0(chan, msg_type)                                               \
    lmp_protocol_recv((chan), (msg_type), NULL, NULL, NULL, NULL)
#define lmp_protocol_recv1(chan, msg_type, ret_arg1)                                     \
    lmp_protocol_recv((chan), (msg_type), NULL, (ret_arg1), NULL, NULL)
#define lmp_protocol_recv2(chan, msg_type, ret_arg1, ret_arg2)                           \
    lmp_protocol_recv((chan), (msg_type), NULL, (ret_arg1), (ret_arg2), NULL)
#define lmp_protocol_recv3(chan, msg_type, ret_arg1, ret_arg2, ret_arg3)                 \
    lmp_protocol_recv((chan), (msg_type), NULL, (ret_arg1), (ret_arg2), (ret_arg3))
#define lmp_protocol_recv_cap(chan, msg_type, ret_cap)                                   \
    lmp_protocol_recv((chan), (msg_type), (ret_cap), NULL, NULL, NULL)
#define lmp_protocol_recv_cap1(chan, msg_type, ret_cap, ret_arg1)                        \
    lmp_protocol_recv((chan), (msg_type), (ret_cap), (ret_arg1), NULL, NULL)
#define lmp_protocol_recv_cap2(chan, msg_type, ret_cap, ret_arg1, ret_arg2)              \
    lmp_protocol_recv((chan), (msg_type), (ret_cap), (ret_arg1), (ret_arg2), NULL)
#define lmp_protocol_recv_cap3(chan, msg_type, ret_cap, ret_arg1, ret_arg2, ret_arg3)    \
    lmp_protocol_recv((chan), (msg_type), (ret_cap), (ret_arg1), (ret_arg2), (ret_arg3))

errval_t lmp_protocol_send_bytes_cap(struct lmp_chan *chan, uint16_t message_type,
                                     struct capref cap, size_t size, const uint8_t *bytes);
errval_t lmp_protocol_recv_bytes_cap_la(struct lmp_chan *chan, uint16_t message_type,
                                        struct capref *ret_cap, size_t *ret_size,
                                        uint8_t **ret_bytes,
                                        struct lmp_recv_msg *lookahead);
#define lmp_protocol_send_bytes(chan, msg_type, size, bytes)                             \
    lmp_protocol_send_bytes_cap((chan), (msg_type), NULL_CAP, (size), (bytes))
#define lmp_protocol_recv_bytes_cap(chan, msg_type, ret_cap, ret_size, ret_bytes)        \
    lmp_protocol_recv_bytes_cap_la((chan), (msg_type), (ret_cap), (ret_size),            \
                                   (ret_bytes), NULL)
#define lmp_protocol_recv_bytes(chan, msg_type, ret_size, ret_bytes)                     \
    lmp_protocol_recv_bytes_cap_la((chan), (msg_type), NULL, (ret_size), (ret_bytes),    \
                                   NULL)

errval_t lmp_protocol_send_string_cap(struct lmp_chan *chan, uint16_t message_type,
                                      struct capref cap, const char *string);
errval_t lmp_protocol_recv_string_cap_la(struct lmp_chan *chan, uint16_t message_type,
                                         struct capref *ret_cap, char **ret_string,
                                         struct lmp_recv_msg *lookahead);
#define lmp_protocol_send_string(chan, msg_type, string)                                 \
    lmp_protocol_send_string_cap((chan), (msg_type), NULL_CAP, (string))
#define lmp_protocol_recv_string_cap(chan, msg_type, ret_cap, ret_string)                \
    lmp_protocol_recv_string_cap_la((chan), (msg_type), (ret_cap), (ret_string), NULL)
#define lmp_protocol_recv_string(chan, msg_type, ret_string)                             \
    lmp_protocol_recv_string_cap_la((chan), (msg_type), NULL, (ret_string), NULL)


#endif