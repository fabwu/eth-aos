#include <stdio.h>

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>
#include <grading.h>
#include <spawn/spawn.h>

// #define DEBUG_TEST_EASY

void grading_setup_bsp_init(int argc, char **argv) {}

void grading_setup_app_init(struct bootinfo *bi) {}

void grading_setup_noninit(int *argc, char ***argv) {}

void grading_test_mm(struct mm *test) {}

static void test_mem(void)
{
    debug_printf("test mem\n");
    errval_t err;
    for (size_t i = 0; i < 512 * 512; ++i) {
        struct capref t;
        err = ram_alloc(&t, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ram_alloc failed");

            abort();
        }
        struct capability ref_cp;
        err = cap_direct_identify(t, &ref_cp);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "couldn't cap_direct_identify cap from ram_alloc");

            abort();
        }
        assert(get_address(&ref_cp) != 0);
    }
}

static void test_easy(void)
{
    debug_printf("test easy\n");
    // TODO: Allow for larger than one frame page mapping
    struct capref frame_cap0, frame_cap1;
    errval_t err;
    size_t got;

    err = frame_alloc(&frame_cap0, 2 * BASE_PAGE_SIZE, &got);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }
    assert(got == 2 * BASE_PAGE_SIZE);

    err = frame_alloc(&frame_cap1, 2 * BASE_PAGE_SIZE, &got);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }
    assert(got == 2 * BASE_PAGE_SIZE);

    void *buf0, *buf1;

    err = paging_map_frame(get_current_paging_state(), &buf0, 2 * BASE_PAGE_SIZE,
                           frame_cap0, NULL, NULL);
    assert(err_is_ok(err));

    err = paging_map_frame(get_current_paging_state(), &buf1, 2 * BASE_PAGE_SIZE,
                           frame_cap1, NULL, NULL);
    assert(err_is_ok(err));

    struct capref *refs0 = (struct capref *)buf0;
    for (size_t i = 0; i < 2 * BASE_PAGE_SIZE / sizeof(struct capref); ++i) {
#ifdef DEBUG_TEST_EASY
        debug_printf("Trya0: %" PRIu64 "\n", i);
#endif
        err = ram_alloc(refs0 + i, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't alloc ram");

            abort();
        }
        struct capability ref_cp;
        err = cap_direct_identify(*(refs0 + i), &ref_cp);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't identify cap");

            abort();
        }
        assert(get_address(&ref_cp) != 0);
#ifdef DEBUG_TEST_EASY
        debug_printf("Successa0: %" PRIu64 "\n", i);
#endif
    }

    struct capref *refs1 = (struct capref *)buf1;
    for (size_t i = 0; i < 2 * BASE_PAGE_SIZE / sizeof(struct capref); ++i) {
#ifdef DEBUG_TEST_EASY
        debug_printf("Trya1: %" PRIu64 "\n", i);
#endif
        err = ram_alloc(refs1 + i, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't alloc ram");

            abort();
        }
        struct capability ref_cp;
        err = cap_direct_identify(*(refs1 + i), &ref_cp);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't identify cap");

            abort();
        }
        assert(get_address(&ref_cp) != 0);
#ifdef DEBUG_TEST_EASY
        debug_printf("Successa1: %" PRIu64 "\n", i);
#endif
    }

    debug_printf("Its: %" PRIu64 "\n", 2 * BASE_PAGE_SIZE / sizeof(struct capref));
    for (size_t i = 0; i < 2 * BASE_PAGE_SIZE / sizeof(struct capref); ++i) {
#ifdef DEBUG_TEST_EASY
        debug_printf("Tryf0: %" PRIu64 "\n", i);
#endif
        struct capability ref_cp;
        err = cap_direct_identify(*(refs0 + i), &ref_cp);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't identify cap");

            abort();
        }
        assert(get_address(&ref_cp) != 0);
        genpaddr_t addr = get_address(&ref_cp);
        err = cap_destroy(*(refs0 + i));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't destroy ram cap");

            abort();
        }
        err = ram_free(addr);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't free ram");

            abort();
        }
#ifdef DEBUG_TEST_EASY
        debug_printf("Successf0: %" PRIu64 "\n", i);
#endif
    }

    for (size_t i = 0; i < 2 * BASE_PAGE_SIZE / sizeof(struct capref); ++i) {
#ifdef DEBUG_TEST_EASY
        debug_printf("Tryf1: %" PRIu64 "\n", i);
#endif
        struct capability ref_cp;
        err = cap_direct_identify(*(refs1 + i), &ref_cp);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't identify cap");

            abort();
        }
        assert(err_is_ok(err));
        assert(get_address(&ref_cp) != 0);
        genpaddr_t addr = get_address(&ref_cp);
        err = cap_destroy(*(refs1 + i));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't destroy ram cap");

            abort();
        }
        err = ram_free(addr);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't free ram");

            abort();
        }
#ifdef DEBUG_TEST_EASY
        debug_printf("Successf1: %" PRIu64 "\n", i);
#endif
    }

    err = paging_unmap(get_current_paging_state(), (lvaddr_t)buf1, frame_cap1,
                       2 * BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    err = frame_free(frame_cap1, 2 * BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    err = paging_unmap(get_current_paging_state(), (lvaddr_t)buf0, frame_cap0,
                       2 * BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    err = frame_free(frame_cap0, 2 * BASE_PAGE_SIZE);
    assert(err_is_ok(err));
}

static void test_hard(void)
{
    debug_printf("test hard\n");
    // TODO: Allow for larger than one frame page mapping
    struct capref frame_cap;
    errval_t err;
    size_t got;
    // const size_t arr_its = 512*512;
    const size_t arr_its = 10 * 512;
    // const size_t arr_its = 512;
    const size_t arr_size = arr_its * sizeof(struct capref);

    err = frame_alloc(&frame_cap, arr_size, &got);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Can't allocate refs array");

        abort();
    }
    assert(got >= arr_size);

    void *buf;

    err = paging_map_frame(get_current_paging_state(), &buf, arr_size, frame_cap, NULL,
                           NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't map frame");

        abort();
    }

    struct capref *refs = (struct capref *)buf;
    for (size_t i = 0; i < arr_its; ++i) {
#ifdef DEBUG_TEST_HARD
        debug_printf("Trya0: %" PRIu64 "\n", i);
#endif
        err = ram_alloc(refs + i, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't allocate ram");

            abort();
        }
        struct capability ref_cp;
        err = cap_direct_identify(*(refs + i), &ref_cp);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't identify cap");

            abort();
        }
        assert(get_address(&ref_cp) != 0);
#ifdef DEBUG_TEST_HARD
        debug_printf("Successa0: %" PRIu64 "\n", i);
#endif
    }

    for (size_t i = 0; i < arr_its; ++i) {
#ifdef DEBUG_TEST_HARD
        debug_printf("Tryf0: %" PRIu64 "\n", i);
#endif
        struct capability ref_cp;
        err = cap_direct_identify(*(refs + i), &ref_cp);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't identify cap");

            abort();
        }
        assert(get_address(&ref_cp) != 0);

        genpaddr_t addr = get_address(&ref_cp);
        err = cap_destroy(*(refs + i));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't destroy ram cap");

            abort();
        }
        err = ram_free(addr);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't free ram");

            abort();
        }
#ifdef DEBUG_TEST_HARD
        debug_printf("Successf0: %" PRIu64 "\n", i);
#endif
    }

    err = paging_unmap(get_current_paging_state(), (lvaddr_t)buf, frame_cap, arr_size);
    assert(err_is_ok(err));

    err = frame_free(frame_cap, arr_size);
    assert(err_is_ok(err));
}

static void test_paging_region_default(void)
{
    errval_t err;
    const int PAGE_COUNT = 10;
    const size_t REQUEST_SIZE = 256;
    struct paging_state *st = get_current_paging_state();
    struct paging_region region;

    err = paging_region_init(st, &region, PAGE_COUNT * BASE_PAGE_SIZE,
                             VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to init region");
        return;
    }

    void *buf;
    size_t retsize;
    int valid_requests = (PAGE_COUNT * BASE_PAGE_SIZE) / REQUEST_SIZE;
    for (int i = 0; i < valid_requests; ++i) {
        err = paging_region_map(&region, REQUEST_SIZE, &buf, &retsize);
        if (err_is_fail(err) || retsize < REQUEST_SIZE || buf == NULL) {
            DEBUG_ERR(err, "Failed to map using region");
            return;
        }
        *(uint64_t *)buf = 55;                       // Write to first 8 bytes
        *(uint64_t *)(buf + REQUEST_SIZE - 8) = 55;  // Write to last 8 bytes
    }

    // Should fail now, because region is full
    err = paging_region_map(&region, REQUEST_SIZE, &buf, &retsize);
    if (err_is_ok(err)) {
        DEBUG_ERR(err, "Did not fail when maping in full region");
        return;
    }

    DEBUG_PRINTF("\033[92mSuccess\033[0m paging_region using %d * 4KB in %d byte "
                 "blocks\n",
                 PAGE_COUNT, REQUEST_SIZE);
}

static void test_paging_region_special_cases(void)
{
    errval_t err;
    const int PAGE_COUNT = 10;
    // Try out e.g. 500 as soon as alignment code in addr_mgr works
    const int ADD_SPACE = 0;
    const size_t REQUEST_SIZE = 300;
    struct paging_state *st = get_current_paging_state();
    struct paging_region region;

    err = paging_region_init(st, &region, PAGE_COUNT * BASE_PAGE_SIZE + ADD_SPACE,
                             VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to init region");
        return;
    }

    void *buf;
    size_t retsize;
    int valid_requests = (PAGE_COUNT * BASE_PAGE_SIZE) / REQUEST_SIZE;
    for (int i = 0; i < valid_requests; ++i) {
        err = paging_region_map(&region, REQUEST_SIZE, &buf, &retsize);
        if (err_is_fail(err) || retsize < REQUEST_SIZE || buf == NULL) {
            DEBUG_ERR(err, "Failed to map using region");
            return;
        }
        *(uint8_t *)buf = 0x55;                       // Write to first 8 bytes
        *(uint8_t *)(buf + REQUEST_SIZE - 1) = 0x55;  // Write to last 8 bytes
    }

    // Should fail now, because region is full
    size_t remaining_bytes = PAGE_COUNT * BASE_PAGE_SIZE - valid_requests * REQUEST_SIZE
                             + ADD_SPACE;
    err = paging_region_map(&region, remaining_bytes, &buf, &retsize);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to map remaining space using region");
        return;
    }

    // Should fail now, because region is full
    err = paging_region_map(&region, 1, &buf, &retsize);
    if (err_is_ok(err)) {
        DEBUG_ERR(err, "Did not fail when maping in full region");
        return;
    }

    DEBUG_PRINTF("\033[92mSuccess\033[0m paging_region using %d * 4KB + %d\n", PAGE_COUNT,
                 ADD_SPACE);
}

static void test_spawn(void)
{
    errval_t err;
    for (int i = 0; i < 10; ++i) {  // Required for assessment
        struct spawninfo *si = (struct spawninfo *)malloc(sizeof(struct spawninfo));
        err = spawn_load_by_name("hello", si, NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Couldn't spawn module");
        }
        free(si);
    }
}

static void test_rpc(void)
{
    errval_t err;
    struct spawninfo *si = (struct spawninfo *)malloc(sizeof(struct spawninfo));
    err = spawn_load_by_name("memeater", si, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Couldn't spawn memeater");
    }
    free(si);
}

#define TEST_PAGING 0
#define TEST_PAGING_REGION 0
#define TEST_SPAWN 0
#define TEST_RPC 1

void grading_test_early(void)
{
    if (TEST_PAGING) {
        debug_printf("Grading test early\n");
        test_hard();
        test_easy();
        test_mem();
    }

    if (TEST_PAGING_REGION) {
        DEBUG_PRINTF("Start testing paging regions\n");
        test_paging_region_default();
        test_paging_region_special_cases();
        DEBUG_PRINTF("End testing paging regions\n");
    }

    if (TEST_SPAWN) {
        test_spawn();
    }

    if (TEST_RPC) {
        test_rpc();
    }
}

void grading_test_late(void) {}
