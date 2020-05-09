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
#define BPB_EXT_FLAGS_OFFSET 40
#define BPB_FS_VER_OFFSET 42
#define BPB_ROOT_CLUS_OFFSET 44
#define BPB_TOT_SEC_32_OFFSET 32
#define FAT_32_MIN_CLUSTERS 65525
#define FAT_32_BAD_CLUSTER_ENTRY 0x0FFFFFF7
#define FAT_32_MIN_EOF_CLUSTER_ENTRY 0x0FFFFFF8
#define FAT_32_CLUSTER_ENTRY_MASK 0x0FFFFFFF
#define FAT_32_BYTES_PER_CLUSTER_ENTRY 4
#define FAT_32_HOLE_DIR_ENTRY 0xE5
#define FAT_32_ONLY_FREE_DIR_ENTRY 0x00
#define FAT_32_REPLACE_DIR_ENTRY 0x5
#define FAT_32_REPLACE_DIR_ENTRY_VALUE 0xE5

#if 1
#    define DEBUG_FS(fmt...) debug_printf(fmt);
#else
#    define DEBUG_FS(fmt...) ((void)0)
#endif

#define FS_TEST_SDHC 0

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

static errval_t fs_init_sd_block(struct sd_block *block)
{
    errval_t err;

    struct capref capref;
    size_t retbytes;
    err = frame_alloc(&capref, SDHC_BLOCK_SIZE, &retbytes);
    assert(err_is_ok(err));
    assert(retbytes >= SDHC_BLOCK_SIZE);

    void *virt;
    err = paging_map_frame(get_current_paging_state(), &virt, SDHC_BLOCK_SIZE, capref,
                           NULL, NULL);
    assert(err_is_ok(err));

    struct capability cap;
    err = cap_direct_identify(capref, &cap);
    assert(err_is_ok(err));

    genpaddr_t phy = get_address(&cap);

    block->virt = virt;
    block->capref = capref;
    block->phy = phy;

    return SYS_ERR_OK;
}

static errval_t fs_read_sector(struct sdhc_s *sd, struct sd_block *block, uint32_t sector)
{
    errval_t err;

    cpu_dcache_wbinv_range((genvaddr_t)block->virt, SDHC_BLOCK_SIZE);

    err = sdhc_read_block(sd, sector, block->phy);
    assert(err_is_ok(err));

    // cpu_dcache_inv_range((genvaddr_t)block, ROUND_UP(SDHC_BLOCK_SIZE, BASE_PAGE_SIZE));

    return SYS_ERR_OK;
}

static errval_t fs_read_metadata(struct sdhc_s *sd, struct fat32_fs *fs)
{
    DEBUG_FS("fs_read_fist begin\n");

    errval_t err;

    err = fs_init_sd_block(&fs->fat);
    assert(err_is_ok(err));

    err = fs_init_sd_block(&fs->data);
    assert(err_is_ok(err));

    err = fs_read_sector(sd, &fs->fat, 0);
    assert(err_is_ok(err));

    // How large the sectors of the disk are
    uint16_t bytes_per_sec = *(uint16_t *)(fs->fat.virt + BPB_BYTES_PER_SEC_OFFSET);
    // TODO: Should not be needed, code general enough to be correct even if not 512
    assert(bytes_per_sec == 512);

    // How many sectores per cluster, so that for limited size FAT larger disks are still usable
    uint8_t sec_per_clus = *(uint8_t *)(fs->fat.virt + BPB_SEC_PER_CLUS_OFFSET);
    assert(sec_per_clus * bytes_per_sec <= 32 * 1024);

    // How many sectors there are in the reserved region
    uint16_t rsvd_sec_cnt = *(uint16_t *)(fs->fat.virt + BPB_RSVD_SEC_CNT_OFFSET);

    // How many copy of the FAT there are
    uint8_t num_FATs = *(uint8_t *)(fs->fat.virt + BPB_NUM_FATS_OFFSET);

    // Number of root dir entries
    uint16_t root_ent_cnt = *(uint16_t *)(fs->fat.virt + BPB_ROOT_ENT_CNT_OFFSET);
    // We only support FAT32
    assert(root_ent_cnt == 0);

    // Total count of sectors of this volume
    uint16_t tot_sec_16 = *(uint16_t *)(fs->fat.virt + BPB_TOT_SEC_16_OFFSET);
    // We only support FAT32
    assert(tot_sec_16 == 0);

    // Sectors occupied by one FAT
    uint16_t FATs_z_16 = *(uint16_t *)(fs->fat.virt + BPB_FATS_Z_16_OFFSET);
    // We only support FAT32
    assert(FATs_z_16 == 0);

    // Although we don't know yet, that it is FAT32, because that we are only allowed to
    // find out via the count of clusters, we already know that it's FAT32 because
    // FATs_z_16 is zero
    uint32_t FATs_z_32 = *(uint32_t *)(fs->fat.virt + BPB_FATS_Z_32_OFFSET);

    // Number of hidden sectors that preceed this partition
    uint32_t hidd_sec = *(uint32_t *)(fs->fat.virt + BPB_HIDD_SEC_OFFSET);
    // Don't support partitioned media
    assert(hidd_sec == 0);

    // Total count of sectors of this volume
    uint32_t tot_sec_32 = *(uint32_t *)(fs->fat.virt + BPB_TOT_SEC_32_OFFSET);
    // For FAT32, this field must be non zero
    assert(tot_sec_32 != 0);

    // FAT32 has no root dir
    uint32_t root_dir_sectors = 0;
    uint32_t FATs_z = FATs_z_32;
    uint32_t tot_sec = tot_sec_32;
    uint32_t data_sec = tot_sec - (rsvd_sec_cnt + (num_FATs * FATs_z) + root_dir_sectors);
    uint32_t count_of_clusters = data_sec / sec_per_clus;

    // We only support FAT32
    assert(count_of_clusters >= FAT_32_MIN_CLUSTERS);

    // Determines if FAT is mirrored
    uint16_t ext_flags = *(uint16_t *)(fs->fat.virt + BPB_EXT_FLAGS_OFFSET);

    // FAT32 version
    uint16_t FS_ver = *(uint16_t *)(fs->fat.virt + BPB_FS_VER_OFFSET);
    // Only support FAT32 version 0
    assert(FS_ver == 0);

    // First cluster of root directory
    uint32_t root_clus = *(uint32_t *)(fs->fat.virt + BPB_ROOT_CLUS_OFFSET);

    // Why ever this is needed, no rational given in specification
    uint8_t byte_510 = *(uint8_t *)(fs->fat.virt + 510);
    assert(byte_510 == 0x55);
    uint8_t byte_511 = *(uint8_t *)(fs->fat.virt + 511);
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
    fs->bytes_per_sec = bytes_per_sec;

    // TODO: Add check if tot_sec is smaller than the amount of sectors the disk has
    // TODO: Read out EOC mark out of second cluster entry

    DEBUG_FS("fs_read_fist end\n");

    return SYS_ERR_OK;
}

static uint32_t get_sector_for_data(struct fat32_fs *fs, uint32_t cluster)
{
    return (cluster - 2) * fs->sec_per_clus + fs->first_data_sector;
}

static uint32_t get_sector_for_fat(struct fat32_fs *fs, uint32_t cluster)
{
    return fs->rsvd_sec_cnt
           + ((cluster * FAT_32_BYTES_PER_CLUSTER_ENTRY) / fs->bytes_per_sec);
}

static uint32_t get_offset_for_fat(struct fat32_fs *fs, uint32_t cluster)
{
    return (cluster * FAT_32_BYTES_PER_CLUSTER_ENTRY) % fs->bytes_per_sec;
}

static errval_t fs_list_root_dir(struct sdhc_s *sd, struct fat32_fs *fs)
{
    DEBUG_FS("fs_list_root_dir begin\n");

    errval_t err;

    uint32_t clus_entry = fs->root_clus;
    uint32_t curr_fat_sector = get_sector_for_fat(fs, clus_entry);
    uint32_t last_fat_sector = 0;

    uint8_t more_entries = 1;
    do {
        if (curr_fat_sector != last_fat_sector) {
            err = fs_read_sector(sd, &fs->fat, curr_fat_sector);
            assert(err_is_ok(err));

            last_fat_sector = curr_fat_sector;
        }

        DEBUG_FS("fs_list_root_dir cluster: 0x%" PRIx32 "\n", clus_entry);

        for (uint8_t sector = 0; sector < fs->sec_per_clus && more_entries; ++sector) {
            DEBUG_FS("fs_list_root_dir sector: 0x%" PRIx8 "\n", sector);
            err = fs_read_sector(sd, &fs->data,
                                 get_sector_for_data(fs, clus_entry) + sector);
            assert(err_is_ok(err));

            assert(fs->bytes_per_sec % 32 == 0);
            for (size_t entry_offset = 0; entry_offset < fs->bytes_per_sec;
                 entry_offset += 32) {
                DEBUG_FS("fs_list_root_dir entry: 0x%" PRIx64 "\n", entry_offset);

                void *entry = fs->data.virt + entry_offset;
                if (*(uint8_t *)entry == FAT_32_HOLE_DIR_ENTRY) {
                    continue;
                } else if (*(uint8_t *)entry == FAT_32_ONLY_FREE_DIR_ENTRY) {
                    // TODO: Better control flow
                    more_entries = 0;
                    break;
                }
                char *name = (char *)entry;
                if (*name == FAT_32_REPLACE_DIR_ENTRY) {
                    *name = FAT_32_REPLACE_DIR_ENTRY_VALUE;
                }
                DEBUG_FS("fs_list_root_dir entry: %.*s\n", 11, name);
            }
        }

        clus_entry = *(uint32_t *)(fs->fat.virt + get_offset_for_fat(fs, clus_entry));
        clus_entry &= FAT_32_CLUSTER_ENTRY_MASK;
        curr_fat_sector = get_sector_for_fat(fs, clus_entry);
    } while ((clus_entry != FAT_32_BAD_CLUSTER_ENTRY
              && clus_entry < FAT_32_MIN_EOF_CLUSTER_ENTRY)
             && more_entries);

    DEBUG_FS("fs_list_root_dir end\n");

    return SYS_ERR_OK;
}

errval_t fs_init(void)
{
    DEBUG_FS("fs_init begin\n");

    errval_t err;
    struct sdhc_s *sd;

    err = fs_init_sd(&sd);
    assert(err_is_ok(err));

    if (FS_TEST_SDHC) {
        err = fs_test_sd(sd);
        assert(err_is_ok(err));
    }

    struct fat32_fs fs;

    err = fs_read_metadata(sd, &fs);
    assert(err_is_ok(err));

    err = fs_list_root_dir(sd, &fs);
    assert(err_is_ok(err));

    DEBUG_FS("fs_init end\n");

    return SYS_ERR_OK;
}
