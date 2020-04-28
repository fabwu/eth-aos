#include <aos/ump.h>

#if 0
#    define DEBUG_AOS_UMP(fmt...) debug_printf(fmt);
#else
#    define DEBUG_AOS_UMP(fmt...) ((void)0)
#endif


static void aos_ump_queue_init(struct aos_ump *ump, struct aos_ump_queue *queue, void *buf)
{
    queue->app_buf = buf;
    queue->ack_buf = buf + ump->slots * ump->line_size;
    queue->free = ump->slots;
    queue->acks = 0;
    queue->next_app_slot = 0;
    queue->next_ack_slot = 0;
    queue->next_app_ack = 0;
    queue->next_ack_ack = 0;
    queue->slots_to_ack = 0;
}

errval_t aos_ump_init(struct aos_ump *ump, void *send_buf, void *recv_buf, uint64_t slots,
                      uint64_t line_size)
{
    assert(slots % 4 == 0);

    slots = slots >> 1;

    assert(slots <= 64);
    assert(slots >= 8);

    ump->slots = slots;
    ump->line_size = line_size;

    aos_ump_queue_init(ump, &ump->send, send_buf);
    aos_ump_queue_init(ump, &ump->recv, recv_buf);

    return SYS_ERR_OK;
}

uint64_t aos_ump_get_capacity(struct aos_ump *ump)
{
    return ump->line_size - 1;
}

uint64_t aos_ump_can_enqueue(struct aos_ump *ump)
{
    return ump->send.free > 0;
}

static int aos_ump_is_just_acks(volatile uint8_t *meta)
{
    return (*meta & ~AOS_UMP_META_NUMBER_MASK) == AOS_UMP_META_JUST_ACKS;
}

static int aos_ump_is_just_message(volatile uint8_t *meta)
{
    return (*meta & ~AOS_UMP_META_NUMBER_MASK) == AOS_UMP_META_JUST_MESSAGE;
}

static int aos_ump_is_message_and_ack(volatile uint8_t *meta)
{
    return (*meta & ~AOS_UMP_META_NUMBER_MASK) == AOS_UMP_META_MESSAGE_AND_ACK;
}

static void aos_ump_dequeue_acks(struct aos_ump *ump, struct aos_ump_queue *queue)
{
    volatile uint8_t *current_ack_slot = queue->ack_buf
                                         + ump->line_size * queue->next_ack_slot;
    volatile uint8_t *current_ack_slot_meta = current_ack_slot + ump->line_size - 1;

    if (*current_ack_slot_meta) {
        dmb();

        DEBUG_AOS_UMP("aos_ump_dequeue_acks reading from: 0x%" PRIx64 "\n",
                      current_ack_slot);

        assert(aos_ump_is_just_acks(current_ack_slot_meta));

        uint8_t slot_acks = *current_ack_slot_meta & AOS_UMP_META_NUMBER_MASK;
        for (uint8_t i = 0; i < slot_acks; ++i) {
            uint8_t slot_acked = *(current_ack_slot + i);
            assert(slot_acked == queue->next_app_ack);
            assert((queue->acks & ((uint64_t)1 << slot_acked)) != 0);
            queue->acks = queue->acks & ~(~queue->acks | ((uint64_t)1 << slot_acked));
            ++queue->next_app_ack;
            queue->next_app_ack &= (ump->slots - 1);
            ++queue->free;
        }

        ++queue->slots_to_ack;

        // No barrier needed on dequeue, as only through acks is the slot really given
        // free again

        *current_ack_slot_meta = 0;

        queue->next_ack_slot += 1;
        queue->next_ack_slot &= (ump->slots - 1);
    }
}

static errval_t aos_ump_enqueue_app(struct aos_ump *ump, struct aos_ump_queue *queue,
                                    void *buf, uint64_t len)
{
    if (queue->free == 0) {
        return LIB_ERR_UMP_ENQUEUE_FULL;
    }

    assert(len <= aos_ump_get_capacity(ump));

    // While enqueuing, potentially ack ack
    volatile uint8_t *current_app_slot = queue->app_buf
                                         + ump->line_size * queue->next_app_slot;
    volatile uint8_t *current_app_slot_meta = current_app_slot + ump->line_size - 1;

    assert(*current_app_slot_meta == 0);

    DEBUG_AOS_UMP("aos_ump_enqueue_app writing to: 0x%" PRIx64 "\n", current_app_slot);

    // Dropping volatile here is fine, as it is only really needed for the meta byte
    memcpy((uint8_t *)current_app_slot, buf, len);

    dmb();

    // Set send slot ack to one
    queue->acks |= ((uint64_t)1 << queue->next_app_slot);

    if (queue->slots_to_ack > 0) {
        *current_app_slot_meta = AOS_UMP_META_MESSAGE_AND_ACK | queue->next_ack_ack;

        queue->slots_to_ack -= 1;
        queue->next_ack_ack += 1;
        queue->next_ack_ack &= (ump->slots - 1);
    } else {
        *current_app_slot_meta = AOS_UMP_META_JUST_MESSAGE;
    }

    queue->next_app_slot += 1;
    queue->next_app_slot &= (ump->slots - 1);

    --queue->free;

    return SYS_ERR_OK;
}

errval_t aos_ump_enqueue(struct aos_ump *ump, void *buf, uint64_t len)
{
    aos_ump_dequeue_acks(ump, &ump->send);

    return aos_ump_enqueue_app(ump, &ump->send, buf, len);
}

uint64_t aos_ump_can_dequeue(struct aos_ump *ump)
{
    struct aos_ump_queue *recv = &ump->recv;
    volatile uint8_t *current_app_slot = recv->app_buf
                                         + ump->line_size * recv->next_app_slot;
    volatile uint8_t *current_app_slot_meta = current_app_slot + ump->line_size - 1;

    return *current_app_slot_meta;
}

static void aos_ump_dequeue_app(struct aos_ump *ump, struct aos_ump_queue *queue,
                                void *buf, uint64_t len)
{
    assert(len <= aos_ump_get_capacity(ump));

    volatile uint8_t *current_app_slot = queue->app_buf
                                         + ump->line_size * queue->next_app_slot;
    volatile uint8_t *current_app_slot_meta = current_app_slot + ump->line_size - 1;

    while (!*current_app_slot_meta) {
    }

    dmb();

    DEBUG_AOS_UMP("aos_ump_dequeue_app reading from: 0x%" PRIx64 "\n", current_app_slot);

    assert(aos_ump_is_just_message(current_app_slot_meta)
           || aos_ump_is_message_and_ack(current_app_slot_meta));

    // Did we receive a message and an ack?
    if (aos_ump_is_message_and_ack(current_app_slot_meta)) {
        uint8_t slot_acked = *current_app_slot_meta & AOS_UMP_META_NUMBER_MASK;

        assert(slot_acked == queue->next_ack_ack);
        assert((queue->acks & ((uint64_t)1 << slot_acked)) != 0);

        queue->acks = queue->acks & ~(~queue->acks | ((uint64_t)1 << slot_acked));

        ++queue->next_ack_ack;
        queue->next_ack_ack &= (ump->slots - 1);

        ++queue->free;
    }

    // Dropping volatile here is fine, as it is only really needed for the meta byte
    memcpy(buf, (uint8_t *)current_app_slot, len);

    // No barrier needed on dequeue, as only through acks is the slot really given free again

    ++queue->slots_to_ack;

    *current_app_slot_meta = 0;

    queue->next_app_slot += 1;
    queue->next_app_slot &= (ump->slots - 1);
}

static void aos_ump_enqueue_acks(struct aos_ump *ump, struct aos_ump_queue *queue)
{
    assert(queue->free > 0);

    if (queue->slots_to_ack >= AOS_UMP_META_ACK_WATERMARK) {
        assert(queue->slots_to_ack < ump->line_size - 1);

        volatile uint8_t *current_ack_slot = queue->ack_buf
                                             + ump->line_size * queue->next_ack_slot;
        volatile uint8_t *current_ack_slot_meta = current_ack_slot + ump->line_size - 1;

        DEBUG_AOS_UMP("aos_ump_enqueue_acks writing to: 0x%" PRIx64 "\n",
                      current_ack_slot);

        assert(*current_ack_slot_meta == 0);

        for (uint8_t i = 0; i < queue->slots_to_ack; ++i) {
            *(current_ack_slot + i) = (queue->next_app_ack + i) & (ump->slots - 1);
        }

        queue->acks |= ((uint64_t)1 << queue->next_ack_slot);

        dmb();

        *current_ack_slot_meta = queue->slots_to_ack | AOS_UMP_META_JUST_ACKS;

        queue->next_app_ack += queue->slots_to_ack;
        queue->next_app_ack &= (ump->slots - 1);

        queue->slots_to_ack = 0;

        queue->next_ack_slot += 1;
        queue->next_ack_slot &= (ump->slots - 1);

        --queue->free;
    }
}

errval_t aos_ump_dequeue(struct aos_ump *ump, void *buf, uint64_t len)
{
    aos_ump_dequeue_app(ump, &ump->recv, buf, len);

    aos_ump_enqueue_acks(ump, &ump->recv);

    return SYS_ERR_OK;
}
