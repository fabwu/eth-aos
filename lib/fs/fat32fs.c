#include <fs/fat32fs.h>
#include "fs_internal.h"
#include "fat32fs_internal.h"

#if 0
#    define DEBUG_FAT32FS(fmt...) debug_printf(fmt);
#else
#    define DEBUG_FAT32FS(fmt...) ((void)0)
#endif

#define FAT_32_DIR_ENTRY_FST_CLUS_LO_OFFSET 26
#define FAT_32_DIR_ENTRY_FST_CLUS_HI_OFFSET 20
#define FAT_32_DIR_ENTRY_FILE_SIZE_OFFSET 28
#define FAT_32_DIR_ENTRY_ATTR_OFFSET 11
#define FAT_32_DIR_ENTRY_ATTR_DIRECTORY 0x10

struct fat32fs_dir_state {
    uint32_t clus;
    uint32_t sec;
    // Position in between bytes, as need/defined by seek
    uint32_t des_pos;
    // How many clusters we dereferenced already
    uint32_t depth;
    uint16_t entry;
};

struct fat32fs_dirent {
    char *name;
    size_t size;
    uint32_t clus;

    uint32_t dir_clus;

    bool is_dir;
    struct fat32fs_dir_state dir_state;
};

static bool fat32fs_is_clus_eof(uint32_t clus)
{
    return clus == FAT_32_BAD_CLUSTER_ENTRY || clus >= FAT_32_MIN_EOF_CLUSTER_ENTRY;
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

static errval_t fat32fs_next_dir_entry(struct fat32_fs *fs,
                                       struct fat32fs_dir_state *state, void **entry,
                                       bool *end)
{
    errval_t err;

    if (fat32fs_is_clus_eof(state->clus)) {
        *end = 1;
        return SYS_ERR_OK;
    }

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

    state->entry += 32;

    if (state->entry >= fs->bytes_per_sec) {
        state->entry = 0;
        ++state->sec;
    }

    if (state->sec > fs->sec_per_clus) {
        state->sec = 0;

        err = fat32fs_get_next_clus(fs, state->clus, &state->clus);
        if (err_is_fail(err)) {
            return err;
        }
    }

    return SYS_ERR_OK;
}

static errval_t fat32fs_find_dirent(struct fat32_fs *fs, uint32_t cluster, char *name,
                                    struct fat32fs_dirent **ret_dirent, bool *found)
{
    errval_t err;
    void *entry;

    struct fat32fs_dir_state dir_state;
    dir_state.clus = cluster;
    dir_state.sec = 0;
    dir_state.entry = 0;

    bool end = 0;

    while (true) {
        err = fat32fs_next_dir_entry(fs, &dir_state, &entry, &end);
        if (err_is_fail(err)) {
            return err;
        }

        // FIXME: Is this the right idea?
        if (end) {
            *found = 0;
            return FS_ERR_NOTFOUND;
        }

        if (*(uint8_t *)entry == FAT_32_HOLE_DIR_ENTRY) {
            continue;
        }

        char *eff_name = calloc(1, sizeof(char) * FAT_32_MAX_BYTES_EFF_NAME);
        if (eff_name == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }

        fs_process_dir_entry_name((unsigned char *)entry, (unsigned char *)eff_name);

        if (strncmp(eff_name, name, FAT_32_MAX_BYTES_EFF_NAME) == 0) {
            struct fat32fs_dirent *dirent = calloc(1, sizeof(struct fat32fs_dirent));
            if (dirent == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }

            dirent->name = eff_name;
            dirent->clus = *(uint16_t *)(entry + FAT_32_DIR_ENTRY_FST_CLUS_LO_OFFSET);
            dirent->clus |= *(uint16_t *)(entry + FAT_32_DIR_ENTRY_FST_CLUS_HI_OFFSET)
                            << 16;

            uint8_t dir_attr = *(uint8_t *)(entry + FAT_32_DIR_ENTRY_ATTR_OFFSET);
            if (dir_attr & FAT_32_DIR_ENTRY_ATTR_DIRECTORY) {
                dirent->is_dir = 1;
            } else {
                dirent->is_dir = 0;
                dirent->size = *(uint32_t *)(entry + FAT_32_DIR_ENTRY_FILE_SIZE_OFFSET);
            }

            dirent->dir_state.clus = dirent->clus;
            dirent->dir_state.sec = 0;
            dirent->dir_state.entry = 0;

            dirent->dir_clus = cluster;

            *ret_dirent = dirent;

            *found = 1;

            return SYS_ERR_OK;
        }
    }
}

// TODO: Mostly duplicating resolve_path of ramfs
static errval_t fat32fs_resolve_path(struct fs_mount *mount, const char *path,
                                     struct fs_handle **ret_fh)
{
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
        next_dirent = calloc(1, sizeof(struct fat32fs_dirent));
        if (next_dirent == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }

        char *name = calloc(1, sizeof(char) * 1);
        if (name == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }

        name[0] = '\0';
        next_dirent->name = name;

        next_dirent->clus = fs->root_clus;

        next_dirent->is_dir = 1;
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

            bool found;
            err = fat32fs_find_dirent(fs, root, pathbuf, &next_dirent, &found);
            if (err_is_fail(err)) {
                return err;
            }

            if (!found) {
                DEBUG_FAT32FS("fat32fs_resolve_path not_found path_part: %s\n", pathbuf);
                return FS_ERR_NOTFOUND;
            }

            if (!next_dirent->is_dir && nextsep != NULL) {
                DEBUG_FAT32FS("fat32fs_resolve_path not_dir but next_sep path_part: %s\n",
                              pathbuf);

                free(next_dirent->name);
                free(next_dirent);

                return FS_ERR_NOTFOUND;
            }

            if (nextsep == NULL) {
                break;
            }

            DEBUG_FAT32FS("fat32fs_resolve_path path_part: %s clus: 0x%" PRIx32 "\n",
                          pathbuf, next_dirent->clus);

            root = next_dirent->clus;

            free(next_dirent->name);
            free(next_dirent);

            pos += nextlen + 1;
        }
    }

    if (ret_fh) {
        struct fs_handle *fh = calloc(1, sizeof(struct fs_handle));

        fh->mount = mount;
        fh->state = next_dirent;

        *ret_fh = fh;
    } else {
        free(next_dirent->name);
        free(next_dirent);
    }

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
        free(dirent->name);
        free(dirent);
        free(*ret_handle);
        return FS_ERR_NOTFILE;
    }

    return SYS_ERR_OK;
}

errval_t fat32fs_create(void *st, const char *path, fs_dirhandle_t *ret_handle)
{
    USER_PANIC("NYI\n");
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

    free(dirent->name);
    free(dirent);
    free(fh);

    return SYS_ERR_OK;
}

errval_t fat32fs_remove(void *st, const char *path)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_opendir(void *st, const char *path, fs_dirhandle_t *ret_handle)
{
    errval_t err;

    err = fat32fs_resolve_path(st, path, (struct fs_handle **)ret_handle);
    if (err_is_fail(err)) {
        return err;
    }

    struct fat32fs_dirent *dirent = (*(struct fs_handle **)ret_handle)->state;
    if (!dirent->is_dir) {
        free(dirent->name);
        free(dirent);
        free(*ret_handle);
        return FS_ERR_NOTDIR;
    }

    return SYS_ERR_OK;
}

errval_t fat32fs_mkdir(void *st, const char *path)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_readdir(void *handle, char **retname)
{
    DEBUG_FAT32FS("fat32fs_readdir begin\n");

    errval_t err;
    struct fs_handle *fh = handle;
    struct fs_mount *mount = fh->mount;
    struct fat32fs_dirent *dirent = fh->state;

    if (!dirent->is_dir) {
        return FS_ERR_NOTDIR;
    }

    void *entry;
    do {
        DEBUG_FAT32FS("fat32fs_readdir getting next entry\n");

        bool end;
        err = fat32fs_next_dir_entry(mount->state, &dirent->dir_state, &entry, &end);
        if (err_is_fail(err)) {
            return err;
        }

        if (end) {
            return FS_ERR_INDEX_BOUNDS;
        }
    } while (*(uint8_t *)entry == FAT_32_HOLE_DIR_ENTRY);

    char *eff_name = calloc(1, sizeof(char) * FAT_32_MAX_BYTES_EFF_NAME);
    if (eff_name == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    fs_process_dir_entry_name((unsigned char *)entry, (unsigned char *)eff_name);

    *retname = eff_name;

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

    free(dirent->name);
    free(dirent);
    free(fh);

    return SYS_ERR_OK;
}

errval_t fat32fs_rmdir(void *st, const char *path)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_stat(void *handle, struct fs_fileinfo *info)
{
    USER_PANIC("NYI\n");
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

    return SYS_ERR_OK;
}
