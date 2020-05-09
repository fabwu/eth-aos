#include <aos/kernel_cap_invocations.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>

#include <aos/aos.h>
#include <aos/cache.h>
#include <filesystem.h>

#define BPB_BYTES_PER_SEC_OFFSET 11
#define BPB_SEC_PER_CLUS_OFFSET 13
#define BPB_RSVD_SEC_CNT_OFFSET 14
#define BPB_NUM_FATS_OFFSET 16
#define BPB_ROOT_ENT_CNT_OFFSET 17
#define BPB_TOT_SEC_16_OFFSET 19
#define BPB_FATS_Z_16_OFFSET 22
#define BPB_HIDD_SEC_OFFSET 28
#define BPB_FATS_Z_32_OFFSET 36
#define MIN_CLUSTERS_FAT_32 65525
#define BPB_EXT_FLAGS_OFFSET 40
#define BPB_FS_VER_OFFSET 42
#define BPB_ROOT_CLUS_OFFSET 44
#define BPB_TOT_SEC_32_OFFSET 32

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

static errval_t fs_read_metadata(struct sdhc_s *sd, struct fat32_fs *fs)
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

    cpu_dcache_wbinv_range((genvaddr_t)block, ROUND_UP(SDHC_BLOCK_SIZE, BASE_PAGE_SIZE));

    err = sdhc_read_block(sd, 0, block_phy_addr);
    assert(err_is_ok(err));

    // cpu_dcache_inv_range((genvaddr_t)block, ROUND_UP(SDHC_BLOCK_SIZE, BASE_PAGE_SIZE));

    // TODO: Readout blocks, so we know parameters of filesystem
    // How large the sectors of the disk are
    uint16_t bytes_per_sec = *(uint16_t *)(block + BPB_BYTES_PER_SEC_OFFSET);
    assert(bytes_per_sec = 512);

    // How many sectores per cluster, so that for limited size FAT larger disks are still usable
    uint8_t sec_per_clus = *(uint8_t *)(block + BPB_SEC_PER_CLUS_OFFSET);
    assert(sec_per_clus * bytes_per_sec <= 32 * 1024);

    // How many sectors there are in the reserved region
    uint16_t rsvd_sec_cnt = *(uint16_t *)(block + BPB_RSVD_SEC_CNT_OFFSET);

    // How many copy of the FAT there are
    uint8_t num_FATs = *(uint8_t *)(block + BPB_NUM_FATS_OFFSET);

    // Number of root dir entries
    uint16_t root_ent_cnt = *(uint16_t *)(block + BPB_ROOT_ENT_CNT_OFFSET);
    // We only support FAT32
    assert(root_ent_cnt == 0);

    // Total count of sectors of this volume
    uint16_t tot_sec_16 = *(uint16_t *)(block + BPB_TOT_SEC_16_OFFSET);
    // We only support FAT32
    assert(tot_sec_16 == 0);

    // Sectors occupied by one FAT
    uint16_t FATs_z_16 = *(uint16_t *)(block + BPB_FATS_Z_16_OFFSET);
    // We only support FAT32
    assert(FATs_z_16 == 0);

    // Although we don't know yet, that it is FAT32, because that we are only allowed to
    // find out via the count of clusters, we already know that it's FAT32 because
    // FATs_z_16 is zero
    uint32_t FATs_z_32 = *(uint32_t *)(block + BPB_FATS_Z_32_OFFSET);

    // Number of hidden sectors that preceed this partition
    uint32_t hidd_sec = *(uint32_t *)(block + BPB_HIDD_SEC_OFFSET);
    // Don't support partitioned media
    assert(hidd_sec == 0);

    // Total count of sectors of this volume
    uint32_t tot_sec_32 = *(uint32_t *)(block + BPB_TOT_SEC_32_OFFSET);
    // For FAT32, this field must be non zero
    assert(tot_sec_32 != 0);

    // FAT32 has no root dir
    uint32_t root_dir_sectors = 0;
    uint32_t FATs_z = FATs_z_32;
    uint32_t tot_sec = tot_sec_32;
    uint32_t data_sec = tot_sec - (rsvd_sec_cnt + (num_FATs * FATs_z) + root_dir_sectors);
    uint32_t count_of_clusters = data_sec / sec_per_clus;

    // We only support FAT32
    assert(count_of_clusters >= MIN_CLUSTERS_FAT_32);

    // Determines if FAT is mirrored
    uint16_t ext_flags = *(uint16_t *)(block + BPB_EXT_FLAGS_OFFSET);

    // FAT32 version
    uint16_t FS_ver = *(uint16_t *)(block + BPB_FS_VER_OFFSET);
    // Only support FAT32 version 0
    assert(FS_ver == 0);

    // First cluster of root directory
    uint32_t root_clus = *(uint32_t *)(block + BPB_ROOT_CLUS_OFFSET);

    // Why ever this is needed, no rational given in specification
    uint8_t byte_510 = *(uint8_t *)(block + 510);
    assert(byte_510 == 0x55);
    uint8_t byte_511 = *(uint8_t *)(block + 511);
    assert(byte_511 == 0xAA);

    fs->FATs_z = FATs_z;
    fs->root_clus = root_clus;
    fs->rsvd_sec_cnt = rsvd_sec_cnt;
    fs->num_FATs = num_FATs;
    if (ext_flags & (1 << 7)) {
        fs->is_mirrored_FAT = 1;
    } else {
        fs->is_mirrored_FAT = 0;
        fs->main_FAT = ext_flags & 0xF;
    }
    fs->first_data_sector = rsvd_sec_cnt + num_FATs * FATs_z + root_dir_sectors;
    fs->sec_per_clus = sec_per_clus;

    // TODO: Add check if tot_sec is smaller than the amount of sectors the disk has

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

    struct fat32_fs fs;

    err = fs_read_metadata(sd, &fs);
    assert(err_is_ok(err));

    DEBUG_FS("fs_init end\n");

    return SYS_ERR_OK;
}
