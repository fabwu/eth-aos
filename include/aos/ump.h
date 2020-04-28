#ifndef AOS_UMP
#define AOS_UMP

#include <aos/aos.h>

struct aos_ump_queue {
    volatile uint8_t *app_buf;
    volatile uint8_t *ack_buf;
    uint64_t free;
    uint64_t acks;
    uint64_t next_app_slot;
    uint64_t next_ack_slot;
    uint64_t next_app_ack;
    uint64_t next_ack_ack;
    uint64_t slots_to_ack;
};

// Upper byte of cache line reserved for metadata
// Upper two bits can signify
// 10 -> no ack, just message
// 11 -> one ack, and message, bits 0 to 5 of meta byte is acked slot
// 01 -> multiple acks, no message, bits 0 to 5 of meta byte is num of acked slots, acked
// slots as array in cache line, 0 to acked slots - 1
struct aos_ump {
    struct aos_ump_queue send;
    struct aos_ump_queue recv;
    uint64_t slots;
    uint64_t line_size;
};

static const uint8_t AOS_UMP_META_ACK_WATERMARK = 8;
static const uint8_t AOS_UMP_META_NUMBER_MASK = 0x3F;
static const uint8_t AOS_UMP_META_JUST_MESSAGE = 0x80;
static const uint8_t AOS_UMP_META_MESSAGE_AND_ACK = 0xC0;
static const uint8_t AOS_UMP_META_JUST_ACKS = 0x40;

/**
 * \brief recv_buf, send_buf need to be zeroed on start
 */
errval_t aos_ump_init(struct aos_ump *ump, void *send_buf, void *recv_buf, uint64_t slots,
                      uint64_t line_size);

/**
 * \brief max amount of bytes sent, received (buf size)
 */
uint64_t aos_ump_get_capacity(struct aos_ump *ump);

/**
 * \brief can send without blocking/error?
 */
uint64_t aos_ump_can_enqueue(struct aos_ump *ump);

/*
 * \brief sends buf, if not able to send, errors out
 *
 * if len < capacity, len upto capacity might be anything upon receiving
 */
errval_t aos_ump_enqueue(struct aos_ump *ump, void *buf, uint64_t len);

/**
 * \brief can receive without blocking/error?
 */
uint64_t aos_ump_can_dequeue(struct aos_ump *ump);

/**
 * \brief if nothing to receive, blocks
 */
errval_t aos_ump_dequeue(struct aos_ump *ump, void *buf, uint64_t len);

#endif
