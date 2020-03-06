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
    struct capref ram;
    errval_t err;
    err = ram_alloc(&ram, sizeof(struct capref)*1000);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }
    struct capability ram_cp;
    err = cap_direct_identify(ram, &ram_cp);
    assert(err_is_ok(err));
    struct capref *refs = (struct capref *)get_address(&ram_cp);
    for (size_t i = 0; i < 1000; ++i) {
        debug_printf("Try: %"PRIu64"\n", i);
        struct capref ref;
        // err = ram_alloc(refs + i, (1 << 12));
        err = ram_alloc(&ref, (1 << 12));
        assert(err_is_ok(err));
        debug_printf("Success: %"PRIu64"\n", i);
    }
    for (size_t i = 0; i < 1000; ++i) {
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
