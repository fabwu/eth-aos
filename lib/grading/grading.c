#include <stdio.h>

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>
#include <grading.h>
#include <spawn/spawn.h>


void grading_setup_bsp_init(int argc, char **argv) {
}

void grading_setup_app_init(struct bootinfo * bi) {
}

void grading_setup_noninit(int *argc, char ***argv) {
}

void grading_test_mm(struct mm * test) {
}

static void test_mem(void) {
    debug_printf("test mem\n");
    errval_t err;
    for (size_t i = 0; i < 512*512; ++i) {
        struct capref t;
        err = ram_alloc(&t, BASE_PAGE_SIZE);
        assert(err_is_ok(err));
        struct capability ref_cp;
        err = cap_direct_identify(t, &ref_cp);
        assert(get_address(&ref_cp) != 0);
    }

}

static void test_easy(void) {
    debug_printf("test easy\n");
    // TODO: Allow for larger than one frame page mapping
    struct capref frame_cap0, frame_cap1;
    errval_t err;
    size_t got;

    err = frame_alloc(&frame_cap0, 2*BASE_PAGE_SIZE, &got);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }
    assert(got == 2*BASE_PAGE_SIZE);

    err = frame_alloc(&frame_cap1, 2*BASE_PAGE_SIZE, &got);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }
    assert(got == 2*BASE_PAGE_SIZE);

    void *buf0, *buf1;

    err = paging_map_frame(get_current_paging_state(), &buf0, 2*BASE_PAGE_SIZE,
            frame_cap0, NULL, NULL);
    assert(err_is_ok(err));

    err = paging_map_frame(get_current_paging_state(), &buf1, 2*BASE_PAGE_SIZE,
            frame_cap1, NULL, NULL);
    assert(err_is_ok(err));

    struct capref *refs0 = (struct capref *)buf0;
    for (size_t i = 0; i < 2*BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        // debug_printf("Trya0: %"PRIu64"\n", i);
        err = ram_alloc(refs0 + i, BASE_PAGE_SIZE);
        assert(err_is_ok(err));
        struct capability ref_cp;
        err = cap_direct_identify(*(refs0 + i), &ref_cp);
        assert(get_address(&ref_cp) != 0);
        // debug_printf("Successa0: %"PRIu64"\n", i);
    }

    struct capref *refs1 = (struct capref *)buf1;
    for (size_t i = 0; i < 2*BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        // debug_printf("Trya1: %"PRIu64"\n", i);
        err = ram_alloc(refs1 + i, BASE_PAGE_SIZE);
        assert(err_is_ok(err));
        // debug_printf("Successa1: %"PRIu64"\n", i);
    }

    debug_printf("Its: %"PRIu64"\n", 2*BASE_PAGE_SIZE/sizeof(struct capref));
    for (size_t i = 0; i < 2*BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        // debug_printf("Tryf0: %"PRIu64"\n", i);
        struct capability ref_cp;
        err = cap_direct_identify(*(refs0 + i), &ref_cp);
        assert(err_is_ok(err));
        assert(get_address(&ref_cp) != 0);
        err = ram_free(*(refs0 + i), get_address(&ref_cp));
        assert(err_is_ok(err));
        // debug_printf("Successf0: %"PRIu64"\n", i);
    }

    for (size_t i = 0; i < 2*BASE_PAGE_SIZE/sizeof(struct capref); ++i) {
        // debug_printf("Tryf1: %"PRIu64"\n", i);
        struct capability ref_cp;
        err = cap_direct_identify(*(refs1 + i), &ref_cp);
        assert(err_is_ok(err));
        err = ram_free(*(refs1 + i), get_address(&ref_cp));
        assert(err_is_ok(err));
        // debug_printf("Successf1: %"PRIu64"\n", i);
    }

    err = paging_unmap(get_current_paging_state(), (lvaddr_t)buf1, frame_cap1,
                        2*BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    err = frame_free(frame_cap1, 2*BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    err = paging_unmap(get_current_paging_state(), (lvaddr_t)buf0, frame_cap0,
                        2*BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    err = frame_free(frame_cap0, 2*BASE_PAGE_SIZE);
    assert(err_is_ok(err));
}

static void test_hard(void) {
    debug_printf("test hard\n");
    // TODO: Allow for larger than one frame page mapping
    struct capref frame_cap;
    errval_t err;
    size_t got;
    const size_t arr_its = 512*512;
    const size_t arr_size =  arr_its*sizeof(struct capref);

    err = frame_alloc(&frame_cap, arr_size, &got);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }
    assert(got >= arr_size);

    void *buf;

    err = paging_map_frame(get_current_paging_state(), &buf, arr_size,
            frame_cap, NULL, NULL);
    assert(err_is_ok(err));

    assert(0);

    struct capref *refs = (struct capref *)buf;
    for (size_t i = 0; i < arr_its; ++i) {
        // debug_printf("Trya0: %"PRIu64"\n", i);
        err = ram_alloc(refs + i, BASE_PAGE_SIZE);
        assert(err_is_ok(err));
        struct capability ref_cp;
        err = cap_direct_identify(*(refs + i), &ref_cp);
        assert(get_address(&ref_cp) != 0);
        // debug_printf("Successa0: %"PRIu64"\n", i);
    }

    for (size_t i = 0; i < arr_its; ++i) {
        // debug_printf("Tryf0: %"PRIu64"\n", i);
        struct capability ref_cp;
        err = cap_direct_identify(*(refs + i), &ref_cp);
        assert(err_is_ok(err));
        assert(get_address(&ref_cp) != 0);
        err = ram_free(*(refs + i), get_address(&ref_cp));
        assert(err_is_ok(err));
        // debug_printf("Successf0: %"PRIu64"\n", i);
    }

    err = paging_unmap(get_current_paging_state(), (lvaddr_t)buf, frame_cap,
                        arr_size);
    assert(err_is_ok(err));

    err = frame_free(frame_cap, arr_size);
    assert(err_is_ok(err));
}
void
grading_test_early(void) {
    debug_printf("Grading test early\n");
    if (0) {
    test_hard();
    test_mem();
    test_easy();
    }
}

void
grading_test_late(void) {
}
