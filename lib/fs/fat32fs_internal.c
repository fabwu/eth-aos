#include <aos/kernel_cap_invocations.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>

#include <aos/aos.h>
#include <aos/cache.h>
#include <aos/aos_rpc.h>
#include <fat32fs_internal.h>

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

    struct aos_rpc *init_rpc = aos_rpc_get_init_channel();
    if (!init_rpc) {
        return AOS_ERR_RPC_GET_INIT_CHANNEL;
    }

    struct capref device_register_frame_capref;
    err = aos_rpc_get_device_cap(init_rpc, IMX8X_SDHC2_BASE, IMX8X_SDHC_SIZE,
                                 &device_register_frame_capref);
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
    block->sec = ~0x0;

    return SYS_ERR_OK;
}

errval_t fs_read_sector(struct sdhc_s *sd, struct sd_block *block, uint32_t sector)
{
    errval_t err;

    cpu_dcache_wbinv_range((genvaddr_t)block->virt, SDHC_BLOCK_SIZE);

    err = sdhc_read_block(sd, sector, block->phy);
    assert(err_is_ok(err));

    block->sec = sector;

    // cpu_dcache_inv_range((genvaddr_t)block, ROUND_UP(SDHC_BLOCK_SIZE, BASE_PAGE_SIZE));

    return SYS_ERR_OK;
}

static errval_t fs_read_metadata(struct fat32_fs *fs)
{
    DEBUG_FS("fs_read_fist begin\n");

    errval_t err;

    err = fs_init_sd_block(&fs->fat);
    assert(err_is_ok(err));

    err = fs_init_sd_block(&fs->data);
    assert(err_is_ok(err));

    err = fs_read_sector(fs->sd, &fs->fat, 0);
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

uint32_t get_sector_for_data(struct fat32_fs *fs, uint32_t cluster)
{
    return (cluster - 2) * fs->sec_per_clus + fs->first_data_sector;
}

uint32_t get_sector_for_fat(struct fat32_fs *fs, uint32_t cluster)
{
    return fs->rsvd_sec_cnt
           + ((cluster * FAT_32_BYTES_PER_CLUSTER_ENTRY) / fs->bytes_per_sec);
}

uint32_t get_offset_for_fat(struct fat32_fs *fs, uint32_t cluster)
{
    return (cluster * FAT_32_BYTES_PER_CLUSTER_ENTRY) % fs->bytes_per_sec;
}

static int fs_is_illegal_character_dir_entry_name(char c)
{
    return c < 0x20 || c == 0x22 || c == 0x2A || c == 0x2B || c == 0x2C || c == 0x2E
           || c == 0x2F || c == 0x3A || c == 0x3B || c == 0x3C || c == 0x3D || c == 0x3E
           || c == 0x3F || c == 0x5B || c == 0x5C || c == 0x5D || c == 0x7C;
}

void fs_process_dir_entry_name(unsigned char *name, unsigned char *eff_name)
{
    // First char of name also used to signal entry status, clashes with a character,
    // which needs replacement
    if (*name == FAT_32_REPLACE_DIR_ENTRY) {
        *name = FAT_32_REPLACE_DIR_ENTRY_VALUE;
    }
    // 11 chars, first 8 main, last 3 extension, if extension, than add dot, also remove
    // trailing spaces (0x20) of main and extension
    // We also add NULL byte, so that it is a proper c string
    int last_char_main = 7;
    for (; last_char_main >= 0; --last_char_main) {
        if (name[last_char_main] != 0x20)
            break;
    }
    // First char is not allowed to be 0x20
    assert(last_char_main >= 0);

    int des_pos = 0;
    for (int src_pos = 0; src_pos <= last_char_main; ++src_pos) {
        DEBUG_FS("fs_process_dir_entry_name char: 0x%" PRIx8 "\n", name[src_pos]);
        assert(!fs_is_illegal_character_dir_entry_name(name[src_pos]));

        eff_name[des_pos] = name[src_pos];
        ++des_pos;
    }

    int last_char_extension = 10;
    for (; last_char_extension > 7; --last_char_extension) {
        if (name[last_char_extension] != 0x20)
            break;
    }

    if (last_char_extension >= 8) {
        eff_name[des_pos] = '.';
        ++des_pos;
        for (int src_pos = 8; src_pos <= last_char_extension; ++src_pos) {
            assert(!fs_is_illegal_character_dir_entry_name(name[src_pos]));

            eff_name[des_pos] = name[src_pos];
            ++des_pos;
        }
    }

    eff_name[des_pos] = '\0';

    DEBUG_FS("fs_process_dir_entry: %.*s\n", 13, eff_name);
}

static void fs_process_dir_entry(void *entry, uint8_t *more_entries)
{
    if (*(uint8_t *)entry == FAT_32_HOLE_DIR_ENTRY) {
        return;
    } else if (*(uint8_t *)entry == FAT_32_ONLY_FREE_DIR_ENTRY) {
        // TODO: Better control flow
        *more_entries = 0;
        return;
    }

    char eff_name[FAT_32_MAX_BYTES_EFF_NAME];
    fs_process_dir_entry_name((unsigned char *)entry, (unsigned char *)eff_name);
}

static void fs_process_dir_cluster_sectors(struct sdhc_s *sd, struct fat32_fs *fs,
                                           uint32_t base_sector, uint8_t *more_entries)
{
    errval_t err;

    for (uint8_t sector = 0; sector < fs->sec_per_clus && *more_entries; ++sector) {
        DEBUG_FS("fs_list_root_dir sector: 0x%" PRIx8 "\n", sector);
        err = fs_read_sector(sd, &fs->data, base_sector + sector);
        assert(err_is_ok(err));

        assert(fs->bytes_per_sec % 32 == 0);
        for (size_t entry_offset = 0; entry_offset < fs->bytes_per_sec && *more_entries;
             entry_offset += 32) {
            fs_process_dir_entry(fs->data.virt + entry_offset, more_entries);
        }
    }
}

static errval_t fs_list_dir(struct fat32_fs *fs, uint32_t cluster)
{
    DEBUG_FS("fs_list_dir begin\n");

    errval_t err;

    uint32_t clus_entry = cluster;
    uint32_t curr_fat_sector = get_sector_for_fat(fs, clus_entry);

    uint8_t more_entries = 1;
    do {
        if (curr_fat_sector != fs->fat.sec) {
            err = fs_read_sector(fs->sd, &fs->fat, curr_fat_sector);
            assert(err_is_ok(err));
        }

        fs_process_dir_cluster_sectors(fs->sd, fs, get_sector_for_data(fs, clus_entry),
                                       &more_entries);

        clus_entry = *(uint32_t *)(fs->fat.virt + get_offset_for_fat(fs, clus_entry));
        clus_entry &= FAT_32_CLUSTER_ENTRY_MASK;
        curr_fat_sector = get_sector_for_fat(fs, clus_entry);
    } while ((clus_entry != FAT_32_BAD_CLUSTER_ENTRY
              && clus_entry < FAT_32_MIN_EOF_CLUSTER_ENTRY)
             && more_entries);

    DEBUG_FS("fs_list_dir end\n");

    return SYS_ERR_OK;
}

static errval_t fs_list_root_dir(struct fat32_fs *fs)
{
    return fs_list_dir(fs, fs->root_clus);
}

#define FS_LIST_ROOT_DIR 0

errval_t fs_init(struct fs_mount *mount)
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

    struct fat32_fs *fs = malloc(sizeof(struct fat32_fs));
    assert(fs != NULL);

    fs->sd = sd;

    err = fs_read_metadata(fs);
    assert(err_is_ok(err));

    if (FS_LIST_ROOT_DIR) {
        err = fs_list_root_dir(fs);
        assert(err_is_ok(err));
    }

    mount->state = (void *)fs;

    DEBUG_FS("fs_init end\n");

    return SYS_ERR_OK;
}
