#include <aos/ump.h>

#include "ump.h"

static void test_ump_same(void)
{
    debug_printf("test_ump_same start\n");
    const int slots = 64;
    const int line_size = 64;

    errval_t err;

    assert(slots * line_size <= BASE_PAGE_SIZE);

    void *buf1 = calloc(BASE_PAGE_SIZE, 1);
    assert(buf1 != NULL);
    void *buf2 = calloc(BASE_PAGE_SIZE, 1);
    assert(buf2 != NULL);

    struct aos_ump ump1;
    struct aos_ump ump2;

    aos_ump_init(&ump1, buf1, buf2, slots, line_size);
    aos_ump_init(&ump2, buf2, buf1, slots, line_size);

    uint64_t capacity = aos_ump_get_capacity(&ump1);

    void *value = malloc(capacity);
    assert(value != NULL);

    for (int i = 0; i < slots - slots / AOS_UMP_META_ACK_WATERMARK; ++i) {
        err = aos_ump_enqueue(&ump1, value, capacity);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "test_ump_same enqueue failed");
            abort();
        }
    }

    for (int i = 0; i < slots - slots / AOS_UMP_META_ACK_WATERMARK; ++i) {
        err = aos_ump_enqueue(&ump2, value, capacity);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "test_ump_same enqueue failed");
            abort();
        }
    }

    for (int i = 0; i < slots - slots / AOS_UMP_META_ACK_WATERMARK; ++i) {
        err = aos_ump_dequeue(&ump1, value, capacity);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "test_ump_same dequeue failed");
            abort();
        }
    }

    for (int i = 0; i < slots - slots / AOS_UMP_META_ACK_WATERMARK; ++i) {
        err = aos_ump_dequeue(&ump2, value, capacity);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "test_ump_same dequeue failed");
            abort();
        }
    }

    // Kinda hacky, as only acks on queue, can just dequeue with this which works to queue
    // untils finds a message or nothing any more
    aos_ump_can_dequeue(&ump1);
    aos_ump_can_dequeue(&ump2);

    for (int j = 0; j < 12; ++j) {
        for (int i = 0; i < slots / 3; ++i) {
            err = aos_ump_enqueue(&ump1, value, capacity);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "test_ump_same enqueue failed");
                abort();
            }
        }

        for (int i = 0; i < slots / 3; ++i) {
            err = aos_ump_enqueue(&ump2, value, capacity);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "test_ump_same enqueue failed");
                abort();
            }
        }

        for (int i = 0; i < slots / 3; ++i) {
            err = aos_ump_dequeue(&ump1, value, capacity);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "test_ump_same dequeue failed");
                abort();
            }
        }

        for (int i = 0; i < slots / 3; ++i) {
            err = aos_ump_dequeue(&ump2, value, capacity);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "test_ump_same dequeue failed");
                abort();
            }
        }
    }

    debug_printf("test_ump_same end\n");
}

#define TEST_UMP_SAME 0

void grading_test_ump(void)
{
    if (TEST_UMP_SAME) {
        debug_printf("TEST_UMP_SAME start\n");
        test_ump_same();
        debug_printf("TEST_UMP_SAME end\n");
    }
}
