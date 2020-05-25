#include <fs/fat32fs.h>
#include "fs_internal.h"
#include "fat32fs_internal.h"

// FIXME: Clean up when error
// FIXME: Don't do arithmetic on void pointer

#if 1
#    define DEBUG_FAT32FS(fmt...) debug_printf(fmt);
#else
#    define DEBUG_FAT32FS(fmt...) ((void)0)
#endif

#define FAT_32_DIR_ENTRY_FST_CLUS_LO_OFFSET 26
#define FAT_32_DIR_ENTRY_FST_CLUS_HI_OFFSET 20
#define FAT_32_DIR_ENTRY_FILE_SIZE_OFFSET 28

#define FAT_32_DIR_ENTRY_NAME_OFFSET 0
#define FAT_32_DIR_ENTRY_ATTR_OFFSET 11
#define FAT_32_DIR_ENTRY_NT_RES_OFFSET 12
#define FAT_32_DIR_ENTRY_CRT_TIME_TENTH_OFFSET 13
#define FAT_32_DIR_ENTRY_WRT_TIME_OFFSET 22
#define FAT_32_DIR_ENTRY_WRT_DATE_OFFSET 24
#define FAT_32_DIR_ENTRY_ATTR_DIRECTORY 0x10
#define FAT_32_FAT_FREE_ENTRY 0x0
#define FAT_32_FAT_EOC_ENTRY 0x0FFFFFFF

struct fat32fs_dir_state {
    uint32_t clus;
    uint32_t sec;
    // Position in between bytes, as need/defined by seek
    uint32_t des_pos;
    // How many clusters we dereferenced already
    uint32_t depth;
    uint16_t entry;

    bool is_eof;
};

struct fat32fs_dirent {
    char *name;
    size_t size;
    uint32_t clus;

    uint32_t dir_clus;

    struct fat32fs_dir_state dir_state;
    bool is_dir;
};

// Exactly 11 long
static const char *DOT_DIR_ENT_NAME = ".           ";
static const char *DOTDOT_DIR_ENT_NAME = "..          ";

static errval_t fat32fs_split_path(const char *path, char **parent_path, char **childname)
{
    const char *childname_tmp;
    // TODO: It's questionable to not always have paths beginning with /
    char *lastsep = strrchr(path, FS_PATH_SEP);
    if (lastsep != NULL) {
        childname_tmp = lastsep + 1;

        if (parent_path) {
            size_t pathlen = lastsep - path;

            *parent_path = calloc(1, sizeof(char) * pathlen + 1);
            if (*parent_path == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }

            memcpy(*parent_path, path, pathlen);

            (*parent_path)[pathlen] = '\0';
        }
    } else {
        childname_tmp = path;

        if (parent_path) {
            *parent_path = calloc(1, sizeof(char) * 1);
            if (*parent_path == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }

            **parent_path = '\0';
        }
    }

    if (childname) {
        size_t size = strlen(childname_tmp) + 1;

        *childname = malloc(size);
        if (*childname == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }

        memcpy(*childname, childname_tmp, size);
    }

    return SYS_ERR_OK;
}

static errval_t fat32fs_zero_cluster(struct fat32_fs *fs, uint32_t clus)
{
    errval_t err;
    uint32_t base_sector = get_sector_for_data(fs, clus);

    DEBUG_FAT32FS("fat32fs_zero_cluster begin clus: 0x%" PRIx32 ", sector: 0x%" PRIx32
                  ", sec_per_clus: 0x%" PRIx8 "\n",
                  clus, base_sector, fs->sec_per_clus);

    for (uint32_t sec = 0; sec < fs->sec_per_clus; ++sec) {
        err = fs_read_sector(fs->sd, &fs->data, base_sector + sec);
        if (err_is_fail(err)) {
            return err;
        }
        memset(fs->data.virt, 0, fs->bytes_per_sec);

        fs->data.dirty = true;
    }

    DEBUG_FAT32FS("fat32fs_zero_cluster end\n");

    return SYS_ERR_OK;
}

static void fat32fs_close_dirent(struct fat32fs_dirent *dirent)
{
    free(dirent->name);
    free(dirent);
}
static void fat32fs_close_handle(struct fs_handle *fh)
{
    struct fat32fs_dirent *dirent = fh->state;
    fat32fs_close_dirent(dirent);
    free(fh);
}

static bool fat32fs_is_clus_eof(uint32_t clus)
{
    return clus == FAT_32_BAD_CLUSTER_ENTRY || clus >= FAT_32_MIN_EOF_CLUSTER_ENTRY;
}

static errval_t fat32fs_free_clus(struct fat32_fs *fs, uint32_t clus_to_free)
{
    errval_t err;

    uint32_t clus_to_free_fat_sector = get_sector_for_fat(fs, clus_to_free);
    err = fs_read_sector(fs->sd, &fs->fat, clus_to_free_fat_sector);
    if (err_is_fail(err)) {
        return err;
    }

    uint32_t *clus_to_free_fat = (uint32_t *)(fs->fat.virt
                                              + get_offset_for_fat(fs, clus_to_free));

    *clus_to_free_fat = (FAT_32_FAT_FREE_ENTRY & FAT_32_CLUSTER_ENTRY_MASK)
                        | (*clus_to_free_fat & ~FAT_32_CLUSTER_ENTRY_MASK);

    fs->fat.dirty = true;

    return SYS_ERR_OK;
}

// Finds a free_cluster, marks it with EOC, and returns its number
static errval_t fat32fs_get_free_clus(struct fat32_fs *fs, uint32_t *free_clus)
{
    errval_t err;

    uint32_t tmp_free_clus = fs->last_free_clus + 1;
    int iterations = 0;
    bool found = 0;
    while (iterations < 2) {
        uint32_t curr_fat_sector = get_sector_for_fat(fs, tmp_free_clus);
        err = fs_read_sector(fs->sd, &fs->fat, curr_fat_sector);
        if (err_is_fail(err)) {
            return err;
        }

        uint32_t *tmp_free_clus_fat
            = (uint32_t *)(fs->fat.virt + get_offset_for_fat(fs, tmp_free_clus));

        if ((*tmp_free_clus_fat & FAT_32_CLUSTER_ENTRY_MASK) == 0x0) {
            *tmp_free_clus_fat = (FAT_32_FAT_EOC_ENTRY & FAT_32_CLUSTER_ENTRY_MASK)
                                 | (*tmp_free_clus_fat & ~FAT_32_CLUSTER_ENTRY_MASK);

            fs->fat.dirty = true;

            found = 1;
            break;
        }

        ++tmp_free_clus;
        if (tmp_free_clus >= get_num_clus(fs)) {
            tmp_free_clus = 2;
            ++iterations;
        }
    }

    if (!found) {
        return FS_ERR_FULL;
    }

    fs->last_free_clus = tmp_free_clus;
    *free_clus = tmp_free_clus;

    return SYS_ERR_OK;
}

static errval_t fat32fs_get_next_clus(struct fat32_fs *fs, uint32_t curr_clus,
                                      uint32_t *next_clus)
{
    errval_t err;

    uint32_t curr_fat_sector = get_sector_for_fat(fs, curr_clus);
    err = fs_read_sector(fs->sd, &fs->fat, curr_fat_sector);
    if (err_is_fail(err)) {
        return err;
    }

    uint32_t tmp_next_clus = *(uint32_t *)(fs->fat.virt
                                           + get_offset_for_fat(fs, curr_clus));
    tmp_next_clus &= FAT_32_CLUSTER_ENTRY_MASK;

    *next_clus = tmp_next_clus;

    return SYS_ERR_OK;
}

static errval_t fat32fs_is_last_dir_entry(struct fat32_fs *fs,
                                          struct fat32fs_dir_state *state)
{
    errval_t err;

    // TODO: Add next_clus to fat32fs_dir_state
    uint32_t tmp_clus;
    err = fat32fs_get_next_clus(fs, state->clus, &tmp_clus);
    if (err_is_fail(err)) {
        return err;
    }

    return state->entry + 32 > fs->bytes_per_sec && state->sec + 1 > fs->sec_per_clus
           && fat32fs_is_clus_eof(tmp_clus);
}

static errval_t fat32fs_next_dir_entry(struct fat32_fs *fs,
                                       struct fat32fs_dir_state *state, void **entry,
                                       bool *end)
{
    errval_t err;

    assert(!state->is_eof);
    assert(state->sec < fs->sec_per_clus);
    assert(state->entry < fs->bytes_per_sec);

    uint32_t data_sector = state->sec + get_sector_for_data(fs, state->clus);
    err = fs_read_sector(fs->sd, &fs->data, data_sector);
    if (err_is_fail(err)) {
        return err;
    }

    *end = 0;
    *entry = fs->data.virt + state->entry;

    if (*(uint8_t *)*entry == FAT_32_ONLY_FREE_DIR_ENTRY) {
        *end = 1;
        return SYS_ERR_OK;
    }

    // Don't want to trash our dir_state if eof
    if (state->entry + 32 < fs->bytes_per_sec) {
        state->entry += 32;
    } else {
        if (state->sec + 1 < fs->sec_per_clus) {
            state->entry = 0;
            ++state->sec;
        } else {
            uint32_t tmp_clus;
            err = fat32fs_get_next_clus(fs, state->clus, &tmp_clus);
            if (err_is_fail(err)) {
                return err;
            }
            if (!fat32fs_is_clus_eof(tmp_clus)) {
                state->entry = 0;
                state->sec = 0;
                state->clus = tmp_clus;
            } else {
                state->is_eof = true;
                *end = 1;
                return SYS_ERR_OK;
            }
        }
    }

    return SYS_ERR_OK;
}

static errval_t fat32fs_expand(struct fat32_fs *fs, uint32_t to_expand_clus,
                               uint32_t *ret_clus)
{
    DEBUG_FAT32FS("fat32fs_expand begin\n");

    errval_t err;
    // Get free cluster
    uint32_t new_clus;
    err = fat32fs_get_free_clus(fs, &new_clus);
    if (err_is_fail(err)) {
        return err;
    }
    // Set free cluster to eof
    uint32_t new_fat_sector = get_sector_for_fat(fs, new_clus);
    err = fs_read_sector(fs->sd, &fs->fat, new_fat_sector);
    if (err_is_fail(err)) {
        return err;
    }

    // Change fat data to chain in free cluster
    uint32_t to_expand_fat_sector = get_sector_for_fat(fs, to_expand_clus);
    err = fs_read_sector(fs->sd, &fs->fat, to_expand_fat_sector);
    if (err_is_fail(err)) {
        return err;
    }

    uint32_t *to_expand_clus_fat = (uint32_t *)(fs->fat.virt
                                                + get_offset_for_fat(fs, to_expand_clus));
    *to_expand_clus_fat = (new_clus & FAT_32_CLUSTER_ENTRY_MASK)
                          | (*to_expand_clus_fat & ~FAT_32_CLUSTER_ENTRY_MASK);

    fs->fat.dirty = true;

    *ret_clus = new_clus;

    DEBUG_FAT32FS("fat32fs_expand end\n");

    return SYS_ERR_OK;
}

static errval_t fat32fs_get_free_dir_entry(struct fat32_fs *fs,
                                           struct fat32fs_dirent *dirent, void **entry)
{
    errval_t err;

    struct fat32fs_dir_state *dir_state = &dirent->dir_state;
    bool end;
    do {
        err = fat32fs_next_dir_entry(fs, dir_state, entry, &end);
        if (err_is_fail(err)) {
            return err;
        }
    } while (!end && *(uint8_t *)*entry != FAT_32_HOLE_DIR_ENTRY);

    if (*(uint8_t *)*entry != FAT_32_HOLE_DIR_ENTRY
        && *(uint8_t *)*entry != FAT_32_ONLY_FREE_DIR_ENTRY) {
        uint32_t new_clus;
        err = fat32fs_expand(fs, dirent->clus, &new_clus);
        if (err_is_fail(err)) {
            return err;
        }

        err = fat32fs_zero_cluster(fs, new_clus);
        if (err_is_fail(err)) {
            return err;
        }

        dir_state->clus = new_clus;
        dir_state->sec = 0;
        dir_state->entry = 0;
        dir_state->is_eof = false;

        err = fat32fs_next_dir_entry(fs, dir_state, entry, &end);
        if (err_is_fail(err)) {
            return err;
        }
        assert(!end && *(uint8_t *)*entry == FAT_32_ONLY_FREE_DIR_ENTRY);
    }

    return SYS_ERR_OK;
}

static errval_t fat32fs_create_dirent(uint32_t clus, char *name, uint32_t parent_clus,
                                      bool is_dir, bool size,
                                      struct fat32fs_dirent **ret_dirent)
{
    struct fat32fs_dirent *dirent = calloc(1, sizeof(struct fat32fs_dirent));
    if (dirent == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    dirent->name = name;
    dirent->clus = clus;

    dirent->is_dir = is_dir;
    dirent->size = size;

    dirent->dir_state.clus = dirent->clus;
    dirent->dir_state.sec = 0;
    dirent->dir_state.entry = 0;
    dirent->dir_state.is_eof = false;

    dirent->dir_clus = parent_clus;

    *ret_dirent = dirent;

    return SYS_ERR_OK;
}

static errval_t fat32fs_create_dirent_from_entry(void *entry,
                                                 struct fat32fs_dirent **ret_dirent,
                                                 char *name, uint32_t parent_clus)
{
    uint32_t clus;
    clus = *(uint16_t *)(entry + FAT_32_DIR_ENTRY_FST_CLUS_LO_OFFSET);
    clus |= *(uint16_t *)(entry + FAT_32_DIR_ENTRY_FST_CLUS_HI_OFFSET) << 16;

    uint8_t dir_attr = *(uint8_t *)(entry + FAT_32_DIR_ENTRY_ATTR_OFFSET);
    bool is_dir;
    uint32_t size;
    if (dir_attr & FAT_32_DIR_ENTRY_ATTR_DIRECTORY) {
        is_dir = true;
        size = 0;
    } else {
        is_dir = 0;
        size = *(uint32_t *)(entry + FAT_32_DIR_ENTRY_FILE_SIZE_OFFSET);
    }

    return fat32fs_create_dirent(clus, name, parent_clus, is_dir, size, ret_dirent);

    return SYS_ERR_OK;
}

static errval_t fat32fs_find_dirent_entry(struct fat32_fs *fs, uint32_t cluster,
                                          const char *name, void **ret_entry,
                                          char **ret_name)
{
    DEBUG_FAT32FS("fat32fs_find_dirent_entry begin start_clus: 0x%" PRIx32 "\n", cluster);

    errval_t err;
    void *entry;

    struct fat32fs_dir_state dir_state;
    dir_state.clus = cluster;
    dir_state.sec = 0;
    dir_state.entry = 0;
    dir_state.is_eof = false;

    bool end;

    do {
        err = fat32fs_next_dir_entry(fs, &dir_state, &entry, &end);
        if (err_is_fail(err)) {
            return err;
        }

        if (*(uint8_t *)entry == FAT_32_ONLY_FREE_DIR_ENTRY) {
            return FS_ERR_NOTFOUND;
        }

        if (*(uint8_t *)entry == FAT_32_HOLE_DIR_ENTRY) {
            continue;
        }

        char *normal_name = malloc(sizeof(char) * FAT_32_MAX_BYTES_NORMAL_NAME);
        if (normal_name == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }

        err = fs_dir_entry_name_to_normal_name((unsigned char *)entry,
                                               (unsigned char *)normal_name);
        if (err_is_fail(err)) {
            return err;
        }

        DEBUG_FAT32FS("fat32fs_find_dirent_entry name: %s\n", normal_name);

        if (strncmp(normal_name, name, FAT_32_MAX_BYTES_NORMAL_NAME) == 0) {
            *ret_entry = entry;

            if (ret_name) {
                *ret_name = normal_name;
            } else {
                free(normal_name);
            }

            DEBUG_FAT32FS("fat32fs_find_dirent_entry end\n");

            return SYS_ERR_OK;
        }

    } while (!end);

    return FS_ERR_NOTFOUND;
}

static errval_t fat32fs_find_dirent(struct fat32_fs *fs, uint32_t cluster,
                                    const char *name, struct fat32fs_dirent **ret_dirent)
{
    DEBUG_FAT32FS("fat32fs_find_dirent begin\n");

    errval_t err;

    void *entry;
    char *normal_name;
    err = fat32fs_find_dirent_entry(fs, cluster, name, &entry, &normal_name);
    if (err_is_fail(err)) {
        return err;
    }

    err = fat32fs_create_dirent_from_entry(entry, ret_dirent, normal_name, cluster);
    if (err_is_fail(err)) {
        return err;
    }

    DEBUG_FAT32FS("fat32fs_find_dirent end\n");

    return SYS_ERR_OK;
}

static errval_t fat32fs_create_fh_from_dirent(struct fs_mount *mount,
                                              struct fat32fs_dirent *dirent,
                                              struct fs_handle **ret_fh)
{
    struct fs_handle *fh = calloc(1, sizeof(struct fs_handle));
    if (fh == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    fh->mount = mount;
    fh->state = dirent;

    *ret_fh = fh;

    return SYS_ERR_OK;
}

// TODO: Mostly duplicating resolve_path of ramfs
static errval_t fat32fs_resolve_path(struct fs_mount *mount, const char *path,
                                     struct fs_handle **ret_fh)
{
    DEBUG_FAT32FS("fat32fs_resolve_path begin\n");
    DEBUG_FAT32FS("fat32fs_resolve_path path: %s\n", path);

    errval_t err;

    struct fat32_fs *fs = mount->state;

    size_t pos = 0;
    if (path[pos] == FS_PATH_SEP) {
        pos++;
    }

    struct fat32fs_dirent *next_dirent = NULL;

    // Root folder is called for
    if (path[pos] == '\0') {
        char *name = calloc(1, sizeof(char) * 1);
        if (name == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }

        name[0] = '\0';

        err = fat32fs_create_dirent(fs->root_clus, name, 0, true, 0, &next_dirent);
        if (err_is_fail(err)) {
            return err;
        }
    } else {
        uint32_t root = fs->root_clus;

        // Some normal folder is called for
        while (path[pos] != '\0') {
            char *nextsep = strchr(&path[pos], FS_PATH_SEP);
            size_t nextlen;
            if (nextsep == NULL) {
                nextlen = strlen(&path[pos]);
            } else {
                nextlen = nextsep - &path[pos];
            }

            char pathbuf[nextlen + 1];
            memcpy(pathbuf, &path[pos], nextlen);
            pathbuf[nextlen] = '\0';

            DEBUG_FAT32FS("fat32fs_resolve_path path_part: %s\n", pathbuf);

            err = fat32fs_find_dirent(fs, root, pathbuf, &next_dirent);
            if (err_is_fail(err) && err_no(err) == FS_ERR_NOTFOUND) {
                DEBUG_FAT32FS("fat32fs_resolve_path not_found path_part: %s\n", pathbuf);
                return FS_ERR_NOTFOUND;
            } else if (err_is_fail(err)) {
                return err;
            }

            if (!next_dirent->is_dir && nextsep != NULL) {
                DEBUG_FAT32FS("fat32fs_resolve_path not_dir but next_sep path_part: %s\n",
                              pathbuf);

                fat32fs_close_dirent(next_dirent);

                return FS_ERR_NOTFOUND;
            }

            if (nextsep == NULL) {
                break;
            }

            DEBUG_FAT32FS("fat32fs_resolve_path path_part: %s clus: 0x%" PRIx32 "\n",
                          pathbuf, next_dirent->clus);

            root = next_dirent->clus;

            fat32fs_close_dirent(next_dirent);

            pos += nextlen + 1;
        }
    }

    if (ret_fh) {
        err = fat32fs_create_fh_from_dirent(mount, next_dirent, ret_fh);
        if (err_is_fail(err)) {
            return err;
        }
    } else {
        fat32fs_close_dirent(next_dirent);
    }

    DEBUG_FAT32FS("fat32fs_resolve_path end\n");

    return SYS_ERR_OK;
}

errval_t fat32fs_open(void *st, const char *path, fs_dirhandle_t *ret_handle)
{
    errval_t err;

    err = fat32fs_resolve_path(st, path, (struct fs_handle **)ret_handle);
    if (err_is_fail(err)) {
        return err;
    }

    struct fat32fs_dirent *dirent = (*(struct fs_handle **)ret_handle)->state;
    if (dirent->is_dir) {
        fat32fs_close_handle(*ret_handle);
        return FS_ERR_NOTFILE;
    }

    return SYS_ERR_OK;
}

// TODO: Too many arguments
static errval_t fat32fs_add_to_dir(struct fat32_fs *fs, struct fat32fs_dirent *dirent,
                                   uint32_t clus, const char *dir_entry_name, bool is_dir,
                                   uint32_t size, void **ret_entry)
{
    errval_t err;

    // Add new directory to parent directory
    // Find free directory entry
    void *entry;
    err = fat32fs_get_free_dir_entry(fs, dirent, &entry);
    if (err_is_fail(err)) {
        return err;
    }

    fs->data.dirty = true;

    // Copy name over
    memcpy(entry + FAT_32_DIR_ENTRY_NAME_OFFSET, dir_entry_name,
           FAT_32_MAX_BYTES_DIR_ENTRY_NAME);

    if (is_dir) {
        *(uint32_t *)(entry + FAT_32_DIR_ENTRY_FILE_SIZE_OFFSET) = 0x0;
        *(uint8_t *)(entry + FAT_32_DIR_ENTRY_ATTR_OFFSET)
            = FAT_32_DIR_ENTRY_ATTR_DIRECTORY;
    } else {
        *(uint32_t *)(entry + FAT_32_DIR_ENTRY_FILE_SIZE_OFFSET) = size;
        *(uint8_t *)(entry + FAT_32_DIR_ENTRY_ATTR_OFFSET) = 0x0;
    }

    *(uint8_t *)(entry + FAT_32_DIR_ENTRY_NT_RES_OFFSET) = 0x0;

    *(uint8_t *)(entry + FAT_32_DIR_ENTRY_CRT_TIME_TENTH_OFFSET) = 0x0;
    *(uint16_t *)(entry + FAT_32_DIR_ENTRY_WRT_TIME_OFFSET) = 0x0;
    *(uint16_t *)(entry + FAT_32_DIR_ENTRY_WRT_DATE_OFFSET) = 0x0;

    *(uint16_t *)(entry + FAT_32_DIR_ENTRY_FST_CLUS_LO_OFFSET) = (uint16_t)clus;
    *(uint16_t *)(entry + FAT_32_DIR_ENTRY_FST_CLUS_HI_OFFSET) = (uint16_t)(clus >> 16);

    if (ret_entry) {
        *ret_entry = entry;
    }

    return SYS_ERR_OK;
}

// TODO: Mostly duplicating fat32fs_mkdir
errval_t fat32fs_create(void *st, const char *path, fs_dirhandle_t *ret_handle)
{
    DEBUG_FAT32FS("fat32fs_create begin\n");

    errval_t err;

    struct fs_mount *mount = st;
    struct fat32_fs *fs = mount->state;

    err = fat32fs_resolve_path(st, path, NULL);
    if (err_is_ok(err)) {
        return FS_ERR_EXISTS;
    } else if (err_is_fail(err) && err_no(err) != FS_ERR_NOTFOUND) {
        return err;
    }

    char *childname;
    char *parent_path;
    err = fat32fs_split_path(path, &parent_path, &childname);
    if (err_is_fail(err)) {
        return err;
    }

    struct fs_handle *parent_fh = NULL;
    struct fat32fs_dirent *parent_dirent = NULL;
    err = fat32fs_resolve_path(st, parent_path, &parent_fh);
    if (err_is_fail(err)) {
        return err;
    }

    parent_dirent = parent_fh->state;
    if (!parent_dirent->is_dir) {
        fat32fs_close_handle(parent_fh);
        return FS_ERR_NOTDIR;
    }

    free(parent_path);

    uint32_t clus;
    err = fat32fs_get_free_clus(fs, &clus);
    if (err_is_fail(err)) {
        return err;
    }

    char *dir_entry_name;
    err = fs_normal_name_to_dir_entry_name((const unsigned char *)childname,
                                           (unsigned char **)&dir_entry_name);
    if (err_is_fail(err)) {
        return err;
    }

    void *entry;
    err = fat32fs_add_to_dir(fs, parent_dirent, clus, dir_entry_name, false, 0, &entry);
    if (err_is_fail(err)) {
        return err;
    }

    free(dir_entry_name);

    struct fat32fs_dirent *dirent;
    err = fat32fs_create_dirent_from_entry(entry, &dirent, childname, parent_dirent->clus);
    if (err_is_fail(err)) {
        return err;
    }

    err = fat32fs_create_fh_from_dirent(mount, dirent, (struct fs_handle **)ret_handle);
    if (err_is_fail(err)) {
        return err;
    }

    DEBUG_FAT32FS("fat32fs_create end\n");

    return SYS_ERR_OK;
}

static bool fat32fs_right_clus(struct fat32_fs *fs, uint32_t des_pos, uint32_t depth)
{
    uint32_t current_clus_pos = depth * get_bytes_per_clus(fs);
    return des_pos >= current_clus_pos
           && des_pos < current_clus_pos + get_bytes_per_clus(fs);
}

errval_t fat32fs_read(void *handle, void *buffer, size_t bytes, size_t *bytes_read)
{
    errval_t err;
    struct fs_handle *fh = handle;
    struct fat32fs_dirent *dirent = fh->state;
    struct fs_mount *mount = fh->mount;
    struct fat32_fs *fs = mount->state;

    if (dirent->dir_state.des_pos > dirent->size) {
        USER_PANIC("We seeked past the end, but we can't write yet!");
    }

    if (dirent->dir_state.des_pos == dirent->size) {
        *bytes_read = 0;
        return SYS_ERR_OK;
    }

    size_t loc_bytes_read = 0;
    uint32_t bytes_left = dirent->size - dirent->dir_state.des_pos;
    while (bytes > 0 && bytes_left > 0) {
        // Are we at the right clus?
        uint32_t current_clus_pos = dirent->dir_state.depth * get_bytes_per_clus(fs);
        if (!fat32fs_right_clus(fs, dirent->dir_state.des_pos, dirent->dir_state.depth)) {
            dirent->dir_state.depth = 0;
            dirent->dir_state.clus = dirent->clus;
            while (!fat32fs_right_clus(fs, dirent->dir_state.des_pos,
                                       dirent->dir_state.depth)) {
                // If this assert triggers, something with the size is off
                assert(!fat32fs_is_clus_eof(dirent->dir_state.clus));

                err = fat32fs_get_next_clus(fs, dirent->dir_state.clus,
                                            &dirent->dir_state.clus);
                if (err_is_fail(err)) {
                    return err;
                }
                ++dirent->dir_state.depth;
            }

            current_clus_pos = dirent->dir_state.depth * get_bytes_per_clus(fs);
        }

        // Are we at the right sec?
        uint32_t current_sec_pos = current_clus_pos
                                   + fs->bytes_per_sec * dirent->dir_state.sec;
        if (dirent->dir_state.des_pos < current_sec_pos
            || dirent->dir_state.des_pos >= current_sec_pos + fs->bytes_per_sec) {
            dirent->dir_state.sec = (dirent->dir_state.des_pos - current_clus_pos)
                                    / fs->bytes_per_sec;

            current_sec_pos = current_clus_pos + fs->bytes_per_sec * dirent->dir_state.sec;
        }

        uint32_t data_sector = dirent->dir_state.sec
                               + get_sector_for_data(fs, dirent->dir_state.clus);
        err = fs_read_sector(fs->sd, &fs->data, data_sector);
        if (err_is_fail(err)) {
            return err;
        }

        size_t max_chunk = fs->bytes_per_sec
                           - dirent->dir_state.des_pos % fs->bytes_per_sec;
        max_chunk = max_chunk < bytes_left ? max_chunk : bytes_left;

        size_t chunk = bytes < max_chunk ? bytes : max_chunk;

        memcpy(buffer, fs->data.virt + dirent->dir_state.des_pos % fs->bytes_per_sec,
               chunk);

        buffer += chunk;
        bytes -= chunk;
        dirent->dir_state.des_pos += chunk;
        loc_bytes_read += chunk;
        bytes_left -= chunk;
    }

    *bytes_read = loc_bytes_read;

    return SYS_ERR_OK;
}

errval_t fat32fs_write(void *handle, const void *buffer, size_t bytes,
                       size_t *bytes_written)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_seek(void *handle, enum fs_seekpos whence, off_t offset)
{
    struct fs_handle *fh = handle;
    struct fat32fs_dirent *dirent = fh->state;

    if (dirent->is_dir) {
        USER_PANIC("NYI\n");
    }

    // FIXME: Write holes when seeking to end

    switch (whence) {
    case FS_SEEK_SET:
        assert(offset >= 0);

        dirent->dir_state.des_pos = offset;

        break;

    case FS_SEEK_CUR:
        assert(offset >= 0 || -offset <= dirent->dir_state.des_pos);

        dirent->dir_state.des_pos += offset;

        break;

    case FS_SEEK_END:
        assert(offset >= 0 || -offset <= dirent->size);

        dirent->dir_state.des_pos = dirent->size + offset;

        break;

    default:
        USER_PANIC("Invalid whence argument to fat32fs_seek");
    }

    return SYS_ERR_OK;
}

errval_t fat32fs_tell(void *handle, size_t *pos)
{
    struct fs_handle *fh = handle;
    struct fat32fs_dirent *dirent = fh->state;

    if (dirent->is_dir) {
        USER_PANIC("NYI\n");
    } else {
        *pos = dirent->dir_state.des_pos;
    }

    return SYS_ERR_OK;
}

errval_t fat32fs_close(void *handle)
{
    struct fs_handle *fh = handle;
    struct fat32fs_dirent *dirent = fh->state;

    if (dirent->is_dir) {
        return FS_ERR_NOTFILE;
    }

    fat32fs_close_handle(handle);

    return SYS_ERR_OK;
}

errval_t fat32fs_remove(void *st, const char *path)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_opendir(void *st, const char *path, fs_dirhandle_t *ret_handle)
{
    errval_t err;

    DEBUG_FAT32FS("fat32fs_opendir path: %s\n", path);

    err = fat32fs_resolve_path(st, path, (struct fs_handle **)ret_handle);
    if (err_is_fail(err)) {
        return err;
    }

    struct fat32fs_dirent *dirent = (*(struct fs_handle **)ret_handle)->state;
    if (!dirent->is_dir) {
        fat32fs_close_handle(*ret_handle);
        return FS_ERR_NOTDIR;
    }

    // DEBUG_FAT32FS("fat32fs_opendir found start_clus: 0x%" PRIx32 "\n", dirent->clus);
    DEBUG_FAT32FS("fat32fs_opendir found start_clus: 0x%" PRIx32 ", clus: 0x%" PRIx32
                  ", sec: 0x%" PRIx32 ", entry: 0x%" PRIx32 "\n",
                  dirent->clus, dirent->dir_state.clus, dirent->dir_state.sec,
                  dirent->dir_state.entry);
    DEBUG_FAT32FS("fat32fs_opendir end\n");

    return SYS_ERR_OK;
}

errval_t fat32fs_mkdir(void *st, const char *path)
{
    DEBUG_FAT32FS("fat32fs_mkdir begin\n");

    errval_t err;

    struct fs_mount *mount = st;
    struct fat32_fs *fs = mount->state;

    err = fat32fs_resolve_path(st, path, NULL);
    if (err_is_ok(err)) {
        return FS_ERR_EXISTS;
    } else if (err_is_fail(err) && err_no(err) != FS_ERR_NOTFOUND) {
        return err;
    }

    char *childname;
    char *parent_path;
    err = fat32fs_split_path(path, &parent_path, &childname);
    if (err_is_fail(err)) {
        return err;
    }

    // Resolve parent directory
    struct fs_handle *parent_fh = NULL;
    struct fat32fs_dirent *parent_dirent = NULL;
    err = fat32fs_resolve_path(st, parent_path, &parent_fh);
    if (err_is_fail(err)) {
        return err;
    }

    parent_dirent = parent_fh->state;
    if (!parent_dirent->is_dir) {
        fat32fs_close_handle(parent_fh);
        return FS_ERR_NOTDIR;
    }

    free(parent_path);

    uint32_t clus;
    err = fat32fs_get_free_clus(fs, &clus);
    if (err_is_fail(err)) {
        return err;
    }

    // FIXME: Instead of zeroing and depending on dir cluster to be zero, just ensure
    // entry after last used dir entry is zero (Saves us 7 sector writes) Ensure new
    // cluster of directory is zeroed
    err = fat32fs_zero_cluster(fs, clus);
    if (err_is_fail(err)) {
        return err;
    }

    char *dir_entry_name;
    err = fs_normal_name_to_dir_entry_name((const unsigned char *)childname,
                                           (unsigned char **)&dir_entry_name);
    if (err_is_fail(err)) {
        return err;
    }

    void *entry;
    err = fat32fs_add_to_dir(fs, parent_dirent, clus, dir_entry_name, true, 0, &entry);
    if (err_is_fail(err)) {
        return err;
    }

    free(dir_entry_name);

    struct fat32fs_dirent *dirent;
    err = fat32fs_create_dirent_from_entry(entry, &dirent, childname, parent_dirent->clus);
    if (err_is_fail(err)) {
        return err;
    }

    err = fat32fs_add_to_dir(fs, dirent, clus, DOT_DIR_ENT_NAME, true, 0, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    err = fat32fs_add_to_dir(fs, dirent, parent_dirent->clus, DOTDOT_DIR_ENT_NAME, true,
                             0, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    fat32fs_close_handle(parent_fh);
    fat32fs_close_dirent(dirent);

    DEBUG_FAT32FS("fat32fs_mkdir end\n");

    return SYS_ERR_OK;
}

errval_t fat32fs_readdir(void *handle, char **retname)
{
    errval_t err;
    struct fs_handle *fh = handle;
    struct fs_mount *mount = fh->mount;
    struct fat32_fs *fs = mount->state;
    struct fat32fs_dirent *dirent = fh->state;

    DEBUG_FAT32FS("fat32fs_readdir begin start_clus: 0x%" PRIx32 ", clus: 0x%" PRIx32
                  ", sec: 0x%" PRIx32 ", entry: 0x%" PRIx32 "\n",
                  dirent->clus, dirent->dir_state.clus, dirent->dir_state.sec,
                  dirent->dir_state.entry);

    if (!dirent->is_dir) {
        return FS_ERR_NOTDIR;
    }

    if (fat32fs_is_last_dir_entry(fs, &dirent->dir_state)) {
        return FS_ERR_INDEX_BOUNDS;
    }

    void *entry;
    do {
        DEBUG_FAT32FS("fat32fs_readdir getting next entry\n");

        bool end;
        err = fat32fs_next_dir_entry(fs, &dirent->dir_state, &entry, &end);
        if (err_is_fail(err)) {
            return err;
        }

        if (end) {
            break;
        }
    } while (*(uint8_t *)entry == FAT_32_HOLE_DIR_ENTRY);

    if (*(uint8_t *)entry == FAT_32_ONLY_FREE_DIR_ENTRY) {
        return FS_ERR_INDEX_BOUNDS;
    }

    char *normal_name = calloc(1, sizeof(char) * FAT_32_MAX_BYTES_NORMAL_NAME);
    if (normal_name == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    err = fs_dir_entry_name_to_normal_name(
        (unsigned char *)(entry + FAT_32_DIR_ENTRY_NAME_OFFSET),
        (unsigned char *)normal_name);
    if (err_is_fail(err)) {
        return err;
    }

    *retname = normal_name;

    DEBUG_FAT32FS("fat32fs_readdir end\n");

    return SYS_ERR_OK;
}

errval_t fat32fs_closedir(void *handle)
{
    struct fs_handle *fh = handle;
    struct fat32fs_dirent *dirent = fh->state;

    if (!dirent->is_dir) {
        return FS_ERR_NOTDIR;
    }

    fat32fs_close_handle(handle);

    return SYS_ERR_OK;
}

static errval_t fat32fs_check_if_dir_is_empty(struct fat32_fs *fs, uint32_t cluster)
{
    DEBUG_FAT32FS("fat32fs_check_if_dir_is_empty begin\n");

    errval_t err;

    // Check if dir is empty (except for ., ..)
    struct fat32fs_dir_state dir_state;
    dir_state.clus = cluster;
    dir_state.sec = 0;
    dir_state.entry = 0;
    dir_state.is_eof = false;

    void *entry;
    bool end;

    // The first two entries are defined to be "." and "..", and we are not in the root
    // directory
    err = fat32fs_next_dir_entry(fs, &dir_state, &entry, &end);
    if (err_is_fail(err)) {
        return err;
    }
    if (end) {
        return FS_ERR_INVAL;
    }

    if (strncmp(entry, DOT_DIR_ENT_NAME, FAT_32_MAX_BYTES_DIR_ENTRY_NAME)) {
        return FS_ERR_INVAL;
    }

    err = fat32fs_next_dir_entry(fs, &dir_state, &entry, &end);
    if (err_is_fail(err)) {
        return err;
    }
    if (strncmp(entry, DOTDOT_DIR_ENT_NAME, FAT_32_MAX_BYTES_DIR_ENTRY_NAME)) {
        return FS_ERR_INVAL;
    }

    while (!end) {
        err = fat32fs_next_dir_entry(fs, &dir_state, &entry, &end);

        if (*(uint8_t *)entry != FAT_32_ONLY_FREE_DIR_ENTRY
            && *(uint8_t *)entry != FAT_32_HOLE_DIR_ENTRY) {
            return FS_ERR_NOTEMPTY;
        }
    }

    DEBUG_FAT32FS("fat32fs_check_if_dir_is_empty end\n");

    return SYS_ERR_OK;
}

errval_t fat32fs_rmdir(void *st, const char *path)
{
    DEBUG_FAT32FS("fat32fs_rmdir begin\n");

    errval_t err;

    struct fs_mount *mount = st;
    struct fat32_fs *fs = mount->state;

    struct fs_handle *fh;
    err = fat32fs_resolve_path(st, path, &fh);
    if (err_is_fail(err)) {
        return err;
    }

    struct fat32fs_dirent *dirent = fh->state;
    if (!dirent->is_dir) {
        fat32fs_close_handle(fh);
        return FS_ERR_NOTDIR;
    }

    // Can't remove root directory
    if (dirent->clus == fs->root_clus) {
        fat32fs_close_handle(fh);
        return FS_ERR_BUSY;
    }

    // FIXME: Check if not is busy

    err = fat32fs_check_if_dir_is_empty(fs, dirent->clus);
    if (err_is_fail(err)) {
        return err;
    }

    // Remove dir
    char *parent_path;
    char *childname;
    err = fat32fs_split_path(path, &parent_path, &childname);
    if (err_is_fail(err)) {
    }

    struct fs_handle *parent_fh;
    err = fat32fs_resolve_path(st, parent_path, &parent_fh);
    if (err_is_fail(err)) {
        return err;
    }

    struct fat32fs_dirent *parent_dirent = parent_fh->state;
    void *entry;
    err = fat32fs_find_dirent_entry(fs, parent_dirent->clus, childname, &entry, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    // TODO: potentially coalesce holes
    *(uint8_t *)entry = FAT_32_HOLE_DIR_ENTRY;

    fs->data.dirty = true;

    err = fat32fs_free_clus(fs, dirent->clus);
    if (err_is_fail(err)) {
        return err;
    }

    free(parent_path);
    free(childname);
    fat32fs_close_handle(fh);
    fat32fs_close_handle(parent_fh);

    DEBUG_FAT32FS("fat32fs_rmdir end\n");

    return SYS_ERR_OK;
}

errval_t fat32fs_stat(void *handle, struct fs_fileinfo *info)
{
    USER_PANIC("NYI\n");
}


static errval_t fat32fs_unmount(void *st)
{
    DEBUG_FAT32FS("fat32fs_unmount begin\n");

    errval_t err;
    struct fs_mount *mount = st;
    struct fat32_fs *fs = mount->state;

    if (fs->fat.dirty) {
        err = fs_write_sector(fs->sd, &fs->fat);
        if (err_is_fail(err)) {
            return err;
        }
    }

    if (fs->data.dirty) {
        err = fs_write_sector(fs->sd, &fs->data);
        if (err_is_fail(err)) {
            return err;
        }
    }

    DEBUG_FAT32FS("fat32fs_unmount end\n");

    return SYS_ERR_OK;
}

errval_t fat32fs_init(fat32fs_mount_t *retst)
{
    errval_t err;

    struct fs_mount *mount = (struct fs_mount *)retst;
    err = fs_init(mount);
    if (err_is_fail(err)) {
        return err;
    }

    mount->opendir = fat32fs_opendir;
    mount->mkdir = fat32fs_mkdir;
    mount->readdir = fat32fs_readdir;
    mount->closedir = fat32fs_closedir;
    mount->rmdir = fat32fs_rmdir;
    mount->stat = fat32fs_stat;

    mount->open = fat32fs_open;
    mount->create = fat32fs_create;
    mount->read = fat32fs_read;
    mount->write = fat32fs_write;
    mount->seek = fat32fs_seek;
    mount->tell = fat32fs_tell;
    mount->remove = fat32fs_remove;
    mount->close = fat32fs_close;

    mount->unmount = fat32fs_unmount;

    return SYS_ERR_OK;
}
