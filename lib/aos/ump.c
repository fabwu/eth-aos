#include <aos/ump.h>

#if 0
#    define DEBUG_AOS_UMP(fmt...) debug_printf(fmt);
#else
#    define DEBUG_AOS_UMP(fmt...) ((void)0)
#endif


errval_t aos_ump_init(struct aos_ump *ump, void *send_buf, void *recv_buf, uint64_t slots,
                      uint64_t line_size)
{
    assert(slots % 2 == 0);
    assert(slots <= 64);

    ump->send_buf = send_buf;
    ump->recv_buf = recv_buf;
    ump->free = slots;
    ump->acks = 0;
    ump->next_send_slot = 0;
    ump->next_recv_slot = 0;
    ump->slots = slots;
    ump->line_size = line_size;
    ump->next_slot_ack = 0;
    ump->next_slot_to_ack = 0;
    ump->slots_to_ack = 0;

    return SYS_ERR_OK;
}

uint64_t aos_ump_get_capacity(struct aos_ump *ump)
{
    return ump->line_size - 1;
}

uint64_t aos_ump_can_enqueue(struct aos_ump *ump)
{
    return ump->free > 0;
}

errval_t aos_ump_enqueue(struct aos_ump *ump, void *buf, uint64_t len)
{
    assert(len <= aos_ump_get_capacity(ump));

    DEBUG_AOS_UMP("aos_ump_enqueue free: 0x%" PRIx64 "\n", ump->free);

    // Keep one slot reserved so we can ack, don't deadlock
    if (ump->free < 2) {
        return LIB_ERR_UMP_ENQUEUE_FULL;
    }

    uint8_t *current_send_slot = ump->send_buf + ump->line_size * ump->next_send_slot;
    uint8_t *current_send_slot_meta = current_send_slot + ump->line_size - 1;

    memcpy(current_send_slot, buf, len);

    dmb();

    // Set send slot ack to one
    ump->acks |= ((uint64_t)1 << ump->next_send_slot);

    if (ump->slots_to_ack > 0) {
        *current_send_slot_meta = AOS_UMP_META_MESSAGE_AND_ACK | ump->next_slot_to_ack;

        ump->slots_to_ack -= 1;
        ump->next_slot_to_ack += 1;
        ump->next_slot_to_ack &= (ump->slots - 1);
    } else {
        *current_send_slot_meta = AOS_UMP_META_JUST_MESSAGE;
    }

    DEBUG_AOS_UMP("aos_ump_enqueue next_send_slot: 0x%" PRIx64 "\n", ump->next_send_slot);
    DEBUG_AOS_UMP("aos_ump_enqueue meta: 0x%" PRIx64 "\n", *current_send_slot_meta);

    ump->next_send_slot += 1;
    ump->next_send_slot &= (ump->slots - 1);

    DEBUG_AOS_UMP("aos_ump_enqueue after wrap next_send_slot: 0x%" PRIx64 "\n",
                  ump->next_send_slot);

    --ump->free;

    DEBUG_AOS_UMP("aos_ump_enqueue after send free: 0x%" PRIx64 "\n", ump->free);

    return SYS_ERR_OK;
}

uint64_t aos_ump_can_dequeue(struct aos_ump *ump)
{
    uint8_t *current_recv_slot = ump->recv_buf + ump->line_size * ump->next_recv_slot;
    uint8_t *current_recv_slot_meta = current_recv_slot + ump->line_size - 1;

    do {
        DEBUG_AOS_UMP("aos_ump_can_dequeue next_recv_slot: 0x%" PRIx64 "\n",
                      ump->next_recv_slot);
        DEBUG_AOS_UMP("aos_ump_can_dequeue meta: 0x%" PRIx64 "\n",
                      *current_recv_slot_meta);

        if (!*current_recv_slot_meta) {
            return 0;
        }

        DEBUG_AOS_UMP("Got something\n");

        dmb();

        // Did we receive an ack list?
        if ((*current_recv_slot_meta & ~AOS_UMP_META_NUMBER_MASK)
            == AOS_UMP_META_JUST_ACKS) {
            DEBUG_AOS_UMP("aos_ump_can_dequeue got just ack_list\n");

            uint8_t slot_acks = *current_recv_slot_meta & AOS_UMP_META_NUMBER_MASK;
            for (uint8_t i = 0; i < slot_acks; ++i) {
                uint8_t slot_acked = *(current_recv_slot + i);
                DEBUG_AOS_UMP("aos_ump_can_dequeu slot_acked: 0x%" PRIx64 "\n",
                              slot_acked);
                DEBUG_AOS_UMP("aos_ump_can_dequeu ump->acks: 0x%" PRIx64 "\n", ump->acks);
                assert(slot_acked == ump->next_slot_ack);
                assert((ump->acks & ((uint64_t)1 << slot_acked)) != 0);
                ump->acks = ump->acks & ~(~ump->acks | ((uint64_t)1 << slot_acked));
                ++ump->next_slot_ack;
                ump->next_slot_ack &= (ump->slots - 1);
                ++ump->free;
            }

            ++ump->slots_to_ack;

            *current_recv_slot_meta = 0;

            ump->next_recv_slot += 1;
            ump->next_recv_slot &= (ump->slots - 1);

            current_recv_slot = ump->recv_buf + ump->line_size * ump->next_recv_slot;
            current_recv_slot_meta = current_recv_slot + ump->line_size - 1;

            DEBUG_AOS_UMP("aos_ump_can_dequeu after dequeue free: 0x%" PRIx64 "\n", ump->free);
        } else {
            return 1;
        }
    } while (*current_recv_slot_meta);

    return 0;
}

errval_t aos_ump_dequeue(struct aos_ump *ump, void *buf, uint64_t len)
{
    assert(len >= aos_ump_get_capacity(ump));

    while (1) {
        uint8_t *current_recv_slot = ump->recv_buf + ump->line_size * ump->next_recv_slot;
        uint8_t *current_recv_slot_meta = current_recv_slot + ump->line_size - 1;

        DEBUG_AOS_UMP("aos_ump_dequeue next_recv_slot: 0x%" PRIx64 "\n",
                      ump->next_recv_slot);
        DEBUG_AOS_UMP("aos_ump_dequeue meta: 0x%" PRIx64 "\n", *current_recv_slot_meta);


        while (!*current_recv_slot_meta) {
        }

        DEBUG_AOS_UMP("Got something\n");

        dmb();

        // Did we receive an ack list?
        if ((*current_recv_slot_meta & ~AOS_UMP_META_NUMBER_MASK)
            == AOS_UMP_META_JUST_ACKS) {
            DEBUG_AOS_UMP("aos_ump_dequeue got just ack_list\n");

            uint8_t slot_acks = *current_recv_slot_meta & AOS_UMP_META_NUMBER_MASK;
            for (uint8_t i = 0; i < slot_acks; ++i) {
                uint8_t slot_acked = *(current_recv_slot + i);
                DEBUG_AOS_UMP("aos_ump_dequeu slot_acked: 0x%" PRIx64 "\n", slot_acked);
                DEBUG_AOS_UMP("aos_ump_dequeu ump->acks: 0x%" PRIx64 "\n", ump->acks);
                assert(slot_acked == ump->next_slot_ack);
                assert((ump->acks & ((uint64_t)1 << slot_acked)) != 0);
                ump->acks = ump->acks & ~(~ump->acks | ((uint64_t)1 << slot_acked));
                ++ump->next_slot_ack;
                ump->next_slot_ack &= (ump->slots - 1);
                ++ump->free;
            }

            ++ump->slots_to_ack;

            *current_recv_slot_meta = 0;

            ump->next_recv_slot += 1;
            ump->next_recv_slot &= (ump->slots - 1);
        } else {
            // Did we receive a message and an ack?
            if ((*current_recv_slot_meta & ~AOS_UMP_META_NUMBER_MASK)
                == AOS_UMP_META_MESSAGE_AND_ACK) {
                DEBUG_AOS_UMP("aos_ump_dequeue got message and ack\n");

                uint8_t slot_acked = *current_recv_slot_meta & AOS_UMP_META_NUMBER_MASK;
                assert(slot_acked == ump->next_slot_ack);
                assert((ump->acks & ((uint64_t)1 << slot_acked)) != 0);
                ump->acks = ump->acks & ~(~ump->acks | ((uint64_t)1 << slot_acked));
                ++ump->next_slot_ack;
                ump->next_slot_ack &= (ump->slots - 1);
                ++ump->free;
            } else {
                DEBUG_AOS_UMP("aos_ump_dequeue got just message\n");
            }

            memcpy(buf, current_recv_slot, ump->line_size);

            ++ump->slots_to_ack;

            *current_recv_slot_meta = 0;

            ump->next_recv_slot += 1;
            ump->next_recv_slot &= (ump->slots - 1);

            break;
        }
    }

    // So we read and meta clearing finishes before we give slots free again for writing
    dmb();

    if (ump->slots_to_ack > AOS_UMP_META_ACK_WATERMARK && ump->free > 0) {
        assert(ump->slots_to_ack < ump->line_size - 1);

        DEBUG_AOS_UMP("aos_ump_dequeue acking next_send_slot: 0x%" PRIx64 "\n",
                      ump->next_send_slot);

        uint8_t *current_send_slot = ump->send_buf + ump->line_size * ump->next_send_slot;
        uint8_t *current_send_slot_meta = current_send_slot + ump->line_size - 1;
        for (uint8_t i = 0; i < ump->slots_to_ack; ++i) {
            DEBUG_AOS_UMP("aos_ump_dequeue acking slot_to_ack: 0x%" PRIx64 "\n",
                          (ump->next_slot_to_ack + i) & (ump->slots - 1));
            *(current_send_slot + i) = (ump->next_slot_to_ack + i) & (ump->slots - 1);
        }

        ump->acks |= ((uint64_t)1 << ump->next_send_slot);

        dmb();

        *current_send_slot_meta = ump->slots_to_ack | AOS_UMP_META_JUST_ACKS;

        DEBUG_AOS_UMP("aos_ump_dequeue acking meta: 0x%" PRIx64 "\n",
                      *current_send_slot_meta);

        ump->next_slot_to_ack += ump->slots_to_ack;
        ump->next_slot_to_ack &= (ump->slots - 1);

        ump->slots_to_ack = 0;

        ump->next_send_slot += 1;
        ump->next_send_slot &= (ump->slots - 1);

        --ump->free;
    }

    DEBUG_AOS_UMP("aos_ump_dequeue after dequeue free: 0x%" PRIx64 "\n", ump->free);
    DEBUG_AOS_UMP("aos_ump_dequeue after dequeue free: 0x%" PRIx64 "\n", ump->slots_to_ack);

    return SYS_ERR_OK;
}
