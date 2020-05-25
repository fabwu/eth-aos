#ifndef _INIT_FILESYSTEM_H_
#define _INIT_FILESYSTEM_H_

#include "fs_internal.h"

#define FAT_32_MAX_BYTES_DIR_ENTRY_NAME 11
#define FAT_32_MAX_BYTES_NORMAL_NAME 13
#define FAT_32_MIN_CLUSTERS 65525
#define FAT_32_BAD_CLUSTER_ENTRY 0x0FFFFFF7
#define FAT_32_MIN_EOF_CLUSTER_ENTRY 0x0FFFFFF8
#define FAT_32_CLUSTER_ENTRY_MASK 0x0FFFFFFF
#define FAT_32_BYTES_PER_CLUSTER_ENTRY 4
#define FAT_32_HOLE_DIR_ENTRY 0xE5
#define FAT_32_ONLY_FREE_DIR_ENTRY 0x00
#define FAT_32_REPLACE_DIR_ENTRY 0x5
#define FAT_32_REPLACE_DIR_ENTRY_VALUE 0xE5

struct sd_block {
    void *virt;
    struct capref capref;
    genpaddr_t phy;
    uint32_t sec;
    bool dirty;
};

struct fat32_fs {
    struct sdhc_s *sd;
    struct sd_block fat;
    struct sd_block data;
    uint32_t FATs_z;
    uint32_t root_clus;
    uint32_t first_data_sector;
    uint32_t last_free_clus;
    uint16_t bytes_per_sec;
    uint16_t rsvd_sec_cnt;
    uint8_t sec_per_clus;
    uint8_t num_FATs;
    uint8_t is_mirrored_FAT;
    uint8_t main_FAT;
};

errval_t fs_init(struct fs_mount *mount);
uint32_t get_sector_for_data(struct fat32_fs *fs, uint32_t cluster);
uint32_t get_sector_for_fat(struct fat32_fs *fs, uint32_t cluster);
uint32_t get_offset_for_fat(struct fat32_fs *fs, uint32_t cluster);
uint32_t get_bytes_per_clus(struct fat32_fs *fs);
uint32_t get_num_clus(struct fat32_fs *fs);
errval_t fs_read_sector(struct sdhc_s *sd, struct sd_block *block, uint32_t sector);
errval_t fs_write_sector(struct sdhc_s *sd, struct sd_block *block);
errval_t fs_dir_entry_name_to_normal_name(const unsigned char *name, unsigned char *eff_name);
errval_t fs_normal_name_to_dir_entry_name(const unsigned char *normal_name,
                                      unsigned char **dir_entry_name);

#endif
