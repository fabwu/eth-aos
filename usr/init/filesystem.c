#include <aos/kernel_cap_invocations.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>

#include <aos/aos.h>
#include <filesystem.h>

#if 1
#    define DEBUG_FS(fmt...) debug_printf(fmt);
#else
#    define DEBUG_FS(fmt...) ((void)0)
#endif

// TODO: How to clean up?

static errval_t fs_init_sd(struct sdhc_s **sd)
{
    DEBUG_FS("fs_init_sd begin\n");

    errval_t err;

    assert(IMX8X_SDHC_SIZE % BASE_PAGE_SIZE == 0);
    assert(IMX8X_SDHC2_BASE % BASE_PAGE_SIZE == 0);

    struct capref device_register_capref = { .cnode = { .croot = CPTR_ROOTCN,
                                                        .cnode = CPTR_TASKCN_BASE,
                                                        .level = CNODE_TYPE_OTHER },
                                             .slot = TASKCN_SLOT_DEV };

    struct capref device_register_frame_capref;
    err = slot_alloc(&device_register_frame_capref);
    assert(err_is_ok(err));

    struct capability device_register_cap;
    err = cap_direct_identify(device_register_capref, &device_register_cap);

    err = cap_retype(device_register_frame_capref, device_register_capref,
                     IMX8X_SDHC2_BASE - get_address(&device_register_cap),
                     ObjType_DevFrame, IMX8X_SDHC_SIZE, 1);
    assert(err_is_ok(err));

    void *device_register;
    err = paging_map_frame_attr(get_current_paging_state(), &device_register,
                                IMX8X_SDHC_SIZE, device_register_frame_capref,
                                VREGION_FLAGS_READ_WRITE_NOCACHE, NULL, NULL);
    assert(err_is_ok(err));

    err = sdhc_init(sd, device_register);
    assert(err_is_ok(err));

    DEBUG_FS("fs_init_sd end\n");

    return SYS_ERR_OK;
}

static errval_t fs_test_sd(struct sdhc_s *sd)
{
    DEBUG_FS("fs_test_sd begin\n");

    errval_t err;

    struct capref scratch_capref;
    size_t retbytes;
    err = frame_alloc(&scratch_capref, SDHC_BLOCK_SIZE, &retbytes);
    assert(err_is_ok(err));
    assert(retbytes >= SDHC_BLOCK_SIZE);

    void *scratch;
    err = paging_map_frame_attr(get_current_paging_state(), &scratch, SDHC_BLOCK_SIZE,
                                scratch_capref, VREGION_FLAGS_READ_WRITE_NOCACHE, NULL,
                                NULL);
    assert(err_is_ok(err));

    struct capability scratch_cap;
    err = cap_direct_identify(scratch_capref, &scratch_cap);
    assert(err_is_ok(err));

    genpaddr_t scratch_phy_addr = get_address(&scratch_cap);

    err = sdhc_test(sd, scratch, scratch_phy_addr);
    assert(err_is_ok(err));

    DEBUG_FS("fs_test_sd end\n");

    return SYS_ERR_OK;
}

static errval_t fs_read_first(struct sdhc_s *sd)
{
    DEBUG_FS("fs_read_fist begin\n");

    errval_t err;

    struct capref block_capref;
    size_t retbytes;
    err = frame_alloc(&block_capref, SDHC_BLOCK_SIZE, &retbytes);
    assert(err_is_ok(err));
    assert(retbytes >= SDHC_BLOCK_SIZE);

    void *block;
    err = paging_map_frame(get_current_paging_state(), &block, SDHC_BLOCK_SIZE,
                           block_capref, NULL, NULL);
    assert(err_is_ok(err));

    struct capability block_cap;
    err = cap_direct_identify(block_capref, &block_cap);
    assert(err_is_ok(err));

    genpaddr_t block_phy_addr = get_address(&block_cap);

    err = sdhc_read_block(sd, 0, block_phy_addr);
    assert(err_is_ok(err));

    // TODO: Invalidate cache

    // TODO: Readout blocks, so we know parameters of filesystem

    DEBUG_FS("fs_read_fist end\n");

    return SYS_ERR_OK;
}

errval_t fs_init(void)
{
    DEBUG_FS("fs_init begin\n");

    errval_t err;
    struct sdhc_s *sd;

    err = fs_init_sd(&sd);
    assert(err_is_ok(err));

    err = fs_test_sd(sd);
    assert(err_is_ok(err));

    err = fs_read_first(sd);
    assert(err_is_ok(err));

    DEBUG_FS("fs_init end\n");

    return SYS_ERR_OK;
}
