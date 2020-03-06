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
    struct capref frame_cap;
    errval_t err;
    size_t got;
    err = frame_alloc(&frame_cap, BASE_PAGE_SIZE, &got);
    assert(got == BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }
    void *buf;
    err = paging_map_frame(get_current_paging_state(), &buf, BASE_PAGE_SIZE,
            frame_cap, NULL, NULL);
    assert(err_is_ok(err));
    struct capref *refs = (struct capref *)buf;
    for (size_t i = 0; i < BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        debug_printf("Try: %"PRIu64"\n", i);
        err = ram_alloc(refs + i, (1 << 12));
        assert(err_is_ok(err));
        debug_printf("Success: %"PRIu64"\n", i);
    }
    for (size_t i = 0; i < BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        struct capability ref_cp;
        err = cap_direct_identify(*(refs + i), &ref_cp);
        assert(err_is_ok(err));
        err = ram_free(*(refs + i), get_size(&ref_cp));
        assert(err_is_ok(err));
    }
}

void
grading_test_late(void) {
}
