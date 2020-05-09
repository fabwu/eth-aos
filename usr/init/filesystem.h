#ifndef _INIT_FILESYSTEM_H_
#define _INIT_FILESYSTEM_H_

struct sd_block {
    void *virt;
    struct capref capref;
    genpaddr_t phy;
};

struct fat32_fs {
    struct sd_block fat;
    struct sd_block data;
    uint32_t FATs_z;
    uint32_t root_clus;
    uint32_t first_data_sector;
    uint16_t bytes_per_sec;
    uint16_t rsvd_sec_cnt;
    uint8_t sec_per_clus;
    uint8_t num_FATs;
    uint8_t is_mirrored_FAT;
    uint8_t main_FAT;
};

errval_t fs_init(void);

#endif
