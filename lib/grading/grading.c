#include <stdio.h>

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>
#include <grading.h>
#include <spawn/spawn.h>


void
grading_setup_bsp_init(int argc, char **argv) {
}

void
grading_setup_app_init(struct bootinfo * bi) {
}

void
grading_setup_noninit(int *argc, char ***argv) {
}

void
grading_test_mm(struct mm * test) {
}

void
grading_test_early(void) {
    debug_printf("Grading test early\n");
    // TODO: Allow for larger than one frame page mapping
    struct capref frame_cap0, frame_cap1;
    errval_t err;
    size_t got;

    err = frame_alloc(&frame_cap0, BASE_PAGE_SIZE, &got);
    assert(got == BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }

    err = frame_alloc(&frame_cap1, BASE_PAGE_SIZE, &got);
    assert(got == BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }

    void *buf0, *buf1;

    err = paging_map_frame(get_current_paging_state(), &buf0, BASE_PAGE_SIZE,
            frame_cap0, NULL, NULL);
    assert(err_is_ok(err));

    err = paging_map_frame(get_current_paging_state(), &buf1, BASE_PAGE_SIZE,
            frame_cap1, NULL, NULL);
    assert(err_is_ok(err));

    struct capref *refs0 = (struct capref *)buf0;
    for (size_t i = 0; i < BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        debug_printf("Try: %"PRIu64"\n", i);
        err = ram_alloc(refs0 + i, (1 << 12));
        assert(err_is_ok(err));
        debug_printf("Success: %"PRIu64"\n", i);
    }

    struct capref *refs1 = (struct capref *)buf1;
    for (size_t i = 0; i < BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        debug_printf("Try: %"PRIu64"\n", i);
        err = ram_alloc(refs1 + i, (1 << 12));
        assert(err_is_ok(err));
        debug_printf("Success: %"PRIu64"\n", i);
    }

    for (size_t i = 0; i < BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        struct capability ref_cp;
        err = cap_direct_identify(*(refs0 + i), &ref_cp);
        assert(err_is_ok(err));
        err = ram_free(*(refs0 + i), get_size(&ref_cp));
        assert(err_is_ok(err));
    }

    for (size_t i = 0; i < BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        struct capability ref_cp;
        err = cap_direct_identify(*(refs1 + i), &ref_cp);
        assert(err_is_ok(err));
        err = ram_free(*(refs1 + i), get_size(&ref_cp));
        assert(err_is_ok(err));
    }
}

void
grading_test_late(void) {
}
