/*
 * Copyright (c) 2009, 2011, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <string.h>
#include <aos/aos.h>

#include <fs/fs.h>
#include <fs/ramfs.h>

#include "fs_internal.h"

#define BULK_MEM_SIZE (1U << 16)       // 64kB
#define BULK_BLOCK_SIZE BULK_MEM_SIZE  // (it's RPC)


/**
 * @brief an entry in the ramfs
 */
struct ramfs_dirent {
    char *name;                   ///< name of the file or directoyr
    size_t size;                  ///< the size of the direntry in bytes or files
    size_t refcount;              ///< reference count for open handles
    struct ramfs_dirent *parent;  ///< parent directory

    struct ramfs_dirent *next;  ///< parent directory
    struct ramfs_dirent *prev;  ///< parent directory

    bool is_dir;  ///< flag indicationg this is a dir

    bool is_mount;
    void *mount;

    union {
        void *data;                ///< file data pointer
        struct ramfs_dirent *dir;  ///< directory pointer
    };
};

/**
 * @brief a handle to the open
 */
struct ramfs_handle {
    struct fs_handle common;
    char *path;
    bool isdir;
    struct ramfs_dirent *dirent;
    union {
        off_t file_pos;
        struct ramfs_dirent *dir_pos;
    };
};

struct ramfs_mount {
    struct ramfs_dirent *root;
};

static struct fs_handle *handle_open(struct fs_mount *mount, struct ramfs_dirent *d)
{
    struct fs_handle *fh = calloc(1, sizeof(struct fs_handle));
    if (fh == NULL) {
        return NULL;
    }
    struct ramfs_handle *h = calloc(1, sizeof(*h));
    if (h == NULL) {
        return NULL;
    }

    d->refcount++;
    h->isdir = d->is_dir;
    h->dirent = d;

    fh->state = h;
    fh->mount = mount;

    return fh;
}

static inline void handle_close(struct fs_handle *fh)
{
    struct ramfs_handle *h = fh->state;
    assert(h->dirent->refcount > 0);
    h->dirent->refcount--;
    free(h->path);
    free(h);
    free(fh);
}


static void dirent_remove(struct ramfs_dirent *entry)
{
    if (entry->prev == NULL) {
        /* entry was the first in list, update parent pointer */
        if (entry->parent) {
            assert(entry->parent->is_dir);
            entry->parent->dir = entry->next;
        }
    } else {
        /* there are entries before that one */
        entry->prev->next = entry->next;
    }

    if (entry->next) {
        /* update prev pointer */
        entry->next->prev = entry->prev;
    }
}

static void dirent_remove_and_free(struct ramfs_dirent *entry)
{
    dirent_remove(entry);
    free(entry->name);
    if (!entry->is_dir) {
        free(entry->data);
    }

    memset(entry, 0x00, sizeof(*entry));
    free(entry);
}

static void dirent_insert(struct ramfs_dirent *parent, struct ramfs_dirent *entry)
{
    assert(parent);
    assert(parent->is_dir);

    entry->next = NULL;
    entry->prev = NULL;
    entry->parent = parent;
    if (parent->dir) {
        entry->next = parent->dir;
        parent->dir->prev = entry;
    }

    parent->dir = entry;
}

static struct ramfs_dirent *dirent_create(const char *name, bool is_dir)
{
    struct ramfs_dirent *d = calloc(1, sizeof(*d));
    if (d == NULL) {
        return NULL;
    }

    d->is_dir = is_dir;
    d->name = strdup(name);

    return d;
}

static errval_t find_dirent(struct ramfs_dirent *root, const char *name,
                            struct ramfs_dirent **ret_de)
{
    if (!root->is_dir) {
        return FS_ERR_NOTDIR;
    }

    struct ramfs_dirent *d = root->dir;

    while (d) {
        if (strcmp(d->name, name) == 0) {
            *ret_de = d;
            return SYS_ERR_OK;
        }

        d = d->next;
    }

    return FS_ERR_NOTFOUND;
}

static errval_t resolve_path(struct fs_mount *mount, struct ramfs_dirent *root,
                             const char *path, struct fs_handle **ret_fh,
                             struct fs_mount **ret_mount, const char **ret_path)
{
    errval_t err;

    // skip leading /
    size_t pos = 0;
    if (path[0] == FS_PATH_SEP) {
        pos++;
    }

    struct ramfs_dirent *next_dirent;

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

        err = find_dirent(root, pathbuf, &next_dirent);
        if (err_is_fail(err)) {
            return err;
        }

        if (next_dirent->is_mount) {
            *ret_mount = next_dirent->mount;
            // Want to have separator with us
            *ret_path = path + pos + nextlen;

            return SYS_ERR_OK;
        }

        if (!next_dirent->is_dir && nextsep != NULL) {
            return FS_ERR_NOTDIR;
        }

        root = next_dirent;
        if (nextsep == NULL) {
            break;
        }

        pos += nextlen + 1;
    }

    /* create the handle */

    if (ret_fh) {
        struct fs_handle *fh = handle_open(mount, root);
        if (fh == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        struct ramfs_handle *h = fh->state;

        h->path = strdup(path);
        // fh->common.mount = root;

        *ret_fh = fh;
    }

    return SYS_ERR_OK;
}

errval_t ramfs_open(void *st, const char *path, ramfs_handle_t *rethandle)
{
    errval_t err;

    struct fs_mount *reg_mount = st;
    struct ramfs_mount *mount = reg_mount->state;

    struct fs_handle *fh;
    struct ramfs_handle *handle;
    struct fs_mount *nest_mount = NULL;
    const char *nest_mount_path;
    err = resolve_path(reg_mount, mount->root, path, &fh, &nest_mount, &nest_mount_path);
    if (err_is_fail(err)) {
        return err;
    }

    if (nest_mount != NULL) {
        return nest_mount->open(nest_mount, nest_mount_path, rethandle);
    }

    handle = fh->state;
    if (handle->isdir) {
        handle_close(fh);
        return FS_ERR_NOTFILE;
    }

    *rethandle = fh;

    return SYS_ERR_OK;
}

errval_t ramfs_create(void *st, const char *path, ramfs_handle_t *rethandle)
{
    errval_t err;

    struct fs_mount *reg_mount = st;
    struct ramfs_mount *mount = reg_mount->state;
    struct fs_mount *nest_mount = NULL;
    const char *nest_mount_path;
    err = resolve_path(reg_mount, mount->root, path, NULL, &nest_mount, &nest_mount_path);
    if (err_is_ok(err)) {
        return FS_ERR_EXISTS;
    }

    if (nest_mount != NULL) {
        return nest_mount->create(nest_mount, nest_mount_path, rethandle);
    }

    struct fs_handle *parent_fh = NULL;
    struct ramfs_handle *parent = NULL;
    const char *childname;

    // find parent directory
    char *lastsep = strrchr(path, FS_PATH_SEP);
    if (lastsep != NULL) {
        childname = lastsep + 1;

        size_t pathlen = lastsep - path;
        char pathbuf[pathlen + 1];
        memcpy(pathbuf, path, pathlen);
        pathbuf[pathlen] = '\0';

        // resolve parent directory
        err = resolve_path(reg_mount, mount->root, pathbuf, &parent_fh, NULL, NULL);
        if (err_is_fail(err)) {
            return err;
        } else {
            parent = parent_fh->state;
            if (!parent->isdir) {
                return FS_ERR_NOTDIR;  // parent is not a directory
            }
        }
    } else {
        childname = path;
    }

    struct ramfs_dirent *dirent = dirent_create(childname, false);
    if (dirent == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    if (parent) {
        dirent_insert(parent->dirent, dirent);
        handle_close(parent_fh);
    } else {
        dirent_insert(mount->root, dirent);
    }

    if (rethandle) {
        struct fs_handle *fh = handle_open(reg_mount, dirent);
        if (fh == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        struct ramfs_handle *h = fh->state;
        h->path = strdup(path);
        *rethandle = fh;
    }

    return SYS_ERR_OK;
}

errval_t ramfs_remove(void *st, const char *path)
{
    errval_t err;

    struct fs_mount *reg_mount = st;
    struct ramfs_mount *mount = reg_mount->state;

    struct fs_handle *fh;
    struct ramfs_handle *handle;
    struct fs_mount *nest_mount = NULL;
    const char *nest_mount_path;
    err = resolve_path(reg_mount, mount->root, path, &fh, &nest_mount, &nest_mount_path);
    if (err_is_fail(err)) {
        return err;
    }

    if (nest_mount != NULL) {
        nest_mount->remove(nest_mount, nest_mount_path);
    }

    handle = fh->state;

    if (handle->isdir) {
        return FS_ERR_NOTFILE;
    }

    struct ramfs_dirent *dirent = handle->dirent;
    if (dirent->refcount != 1) {
        handle_close(fh);
        return FS_ERR_BUSY;
    }


    // FIXME: Where is handle closed?
    dirent_remove_and_free(dirent);

    return SYS_ERR_OK;
}

errval_t ramfs_read(void *handle, void *buffer, size_t bytes, size_t *bytes_read)
{
    struct fs_handle *fh = handle;
    struct ramfs_handle *h = fh->state;

    if (h->isdir) {
        return FS_ERR_NOTFILE;
    }

    assert(h->file_pos >= 0);

    if (h->dirent->data == NULL) {
        bytes = 0;
    } else if (h->dirent->size < h->file_pos) {
        bytes = 0;
    } else if (h->dirent->size < h->file_pos + bytes) {
        bytes = h->dirent->size - h->file_pos;
        assert(h->file_pos + bytes == h->dirent->size);
    }

    memcpy(buffer, h->dirent->data + h->file_pos, bytes);

    h->file_pos += bytes;

    *bytes_read = bytes;

    return SYS_ERR_OK;
}

errval_t ramfs_write(void *handle, const void *buffer, size_t bytes, size_t *bytes_written)
{
    struct fs_handle *fh = handle;
    struct ramfs_handle *h = fh->state;
    assert(h->file_pos >= 0);

    size_t offset = h->file_pos;

    if (h->isdir) {
        return FS_ERR_NOTFILE;
    }

    if (h->dirent->size < offset + bytes) {
        /* need to realloc the buffer */
        void *newbuf = realloc(h->dirent->data, offset + bytes);
        if (newbuf == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        h->dirent->data = newbuf;
    }

    memcpy(h->dirent->data + offset, buffer, bytes);

    if (bytes_written) {
        *bytes_written = bytes;
    }

    h->file_pos += bytes;
    h->dirent->size += bytes;

    return SYS_ERR_OK;
}


errval_t ramfs_truncate(void *st, ramfs_handle_t handle, size_t bytes)
{
    struct ramfs_handle *h = handle;

    if (h->isdir) {
        return FS_ERR_NOTFILE;
    }

    void *newdata = realloc(h->dirent->data, bytes);
    if (newdata == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    h->dirent->data = newdata;
    h->dirent->size = bytes;

    return SYS_ERR_OK;
}

errval_t ramfs_tell(void *handle, size_t *pos)
{
    struct fs_handle *fh = handle;
    struct ramfs_handle *h = fh->state;
    if (h->isdir) {
        *pos = 0;
    } else {
        *pos = h->file_pos;
    }
    return SYS_ERR_OK;
}

errval_t ramfs_stat(void *handle, struct fs_fileinfo *info)
{
    struct fs_handle *fh = handle;
    struct ramfs_handle *h = fh->state;

    assert(info != NULL);
    info->type = h->isdir ? FS_DIRECTORY : FS_FILE;
    info->size = h->dirent->size;

    return SYS_ERR_OK;
}

errval_t ramfs_seek(void *handle, enum fs_seekpos whence, off_t offset)
{
    struct fs_handle *fh = handle;
    struct ramfs_handle *h = fh->state;
    struct fs_fileinfo info;
    errval_t err;

    switch (whence) {
    case FS_SEEK_SET:
        assert(offset >= 0);
        if (h->isdir) {
            h->dir_pos = h->dirent->parent->dir;
            for (size_t i = 0; i < offset; i++) {
                if (h->dir_pos == NULL) {
                    break;
                }
                h->dir_pos = h->dir_pos->next;
            }
        } else {
            h->file_pos = offset;
        }
        break;

    case FS_SEEK_CUR:
        if (h->isdir) {
            assert(!"NYI");
        } else {
            assert(offset >= 0 || -offset <= h->file_pos);
            h->file_pos += offset;
        }

        break;

    case FS_SEEK_END:
        if (h->isdir) {
            assert(!"NYI");
        } else {
            err = ramfs_stat(fh, &info);
            if (err_is_fail(err)) {
                return err;
            }
            assert(offset >= 0 || -offset <= info.size);
            h->file_pos = info.size + offset;
        }
        break;

    default:
        USER_PANIC("invalid whence argument to ramfs seek");
    }

    return SYS_ERR_OK;
}

errval_t ramfs_close(void *handle)
{
    struct fs_handle *fh = handle;
    struct ramfs_handle *h = fh->state;
    if (h->isdir) {
        return FS_ERR_NOTFILE;
    }
    handle_close(fh);
    return SYS_ERR_OK;
}

errval_t ramfs_opendir(void *st, const char *path, ramfs_handle_t *rethandle)
{
    errval_t err;

    struct fs_mount *reg_mount = st;
    struct ramfs_mount *mount = reg_mount->state;

    struct fs_handle *fh;
    struct ramfs_handle *handle;
    struct fs_mount *nest_mount = NULL;
    const char *nest_mount_path;
    err = resolve_path(reg_mount, mount->root, path, &fh, &nest_mount, &nest_mount_path);
    if (err_is_fail(err)) {
        return err;
    }

    if (nest_mount != NULL) {
        return nest_mount->opendir(nest_mount, nest_mount_path, rethandle);
    }

    handle = fh->state;

    if (!handle->isdir) {
        handle_close(fh);
        return FS_ERR_NOTDIR;
    }

    handle->dir_pos = handle->dirent->dir;

    *rethandle = fh;

    return SYS_ERR_OK;
}

errval_t ramfs_dir_read_next(void *handle, char **retname)
{
    struct fs_handle *fh = handle;
    struct ramfs_handle *h = fh->state;

    if (!h->isdir) {
        return FS_ERR_NOTDIR;
    }

    struct ramfs_dirent *d = h->dir_pos;
    if (d == NULL) {
        return FS_ERR_INDEX_BOUNDS;
    }


    if (retname != NULL) {
        *retname = strdup(d->name);
    }

    h->dir_pos = d->next;

    return SYS_ERR_OK;
}

errval_t ramfs_closedir(void *handle)
{
    struct fs_handle *fh = handle;
    struct ramfs_handle *h = fh->state;
    if (!h->isdir) {
        return FS_ERR_NOTDIR;
    }

    // FIXME: Previously just called free
    handle_close(fh);

    return SYS_ERR_OK;
}

// fails if already present
errval_t ramfs_mkdir(void *st, const char *path)
{
    errval_t err;

    struct fs_mount *reg_mount = st;
    struct ramfs_mount *mount = reg_mount->state;
    struct fs_mount *nest_mount = NULL;
    const char *nest_mount_path;
    err = resolve_path(reg_mount, mount->root, path, NULL, &nest_mount, &nest_mount_path);
    if (nest_mount != NULL) {
        nest_mount->mkdir(nest_mount, nest_mount_path);
    } else if (err_is_ok(err)) {
        return FS_ERR_EXISTS;
    }


    struct fs_handle *parent_fh = NULL;
    struct ramfs_handle *parent = NULL;
    const char *childname;

    // find parent directory
    char *lastsep = strrchr(path, FS_PATH_SEP);
    if (lastsep != NULL) {
        childname = lastsep + 1;

        size_t pathlen = lastsep - path;
        char pathbuf[pathlen + 1];
        memcpy(pathbuf, path, pathlen);
        pathbuf[pathlen] = '\0';

        // resolve parent directory
        err = resolve_path(reg_mount, mount->root, pathbuf, &parent_fh, NULL, NULL);
        if (err_is_fail(err)) {
            handle_close(parent_fh);
            return err;
        } else {
            parent = parent_fh->state;
            if (!parent->isdir) {
                handle_close(parent_fh);
                return FS_ERR_NOTDIR;  // parent is not a directory
            }
        }
    } else {
        childname = path;
    }

    struct ramfs_dirent *dirent = dirent_create(childname, true);
    if (dirent == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    if (parent) {
        dirent_insert(parent->dirent, dirent);
        handle_close(parent_fh);
    } else {
        dirent_insert(mount->root, dirent);
    }

    return SYS_ERR_OK;
}


errval_t ramfs_rmdir(void *st, const char *path)
{
    errval_t err;

    struct fs_mount *reg_mount = st;
    struct ramfs_mount *mount = reg_mount->state;

    struct fs_handle *fh;
    struct ramfs_handle *handle;
    struct fs_mount *nest_mount = NULL;
    const char *nest_mount_path;
    err = resolve_path(reg_mount, mount->root, path, &fh, &nest_mount, &nest_mount_path);
    if (err_is_fail(err)) {
        return err;
    }

    if (nest_mount != NULL) {
        return nest_mount->rmdir(nest_mount, nest_mount_path);
    }

    handle = fh->state;

    if (!handle->isdir) {
        goto out;
        err = FS_ERR_NOTDIR;
    }

    if (handle->dirent->refcount != 1) {
        handle_close(fh);
        return FS_ERR_BUSY;
    }

    assert(handle->dirent->is_dir);

    if (handle->dirent->dir) {
        err = FS_ERR_NOTEMPTY;
        goto out;
    }

    dirent_remove_and_free(handle->dirent);

out:
    // FIXME: Previously free, but most probably an error
    handle_close(fh);

    return err;
}


errval_t ramfs_mount(const char *uri, ramfs_mount_t *retst)
{
    /* Setup channel and connect ot service */
    /* TODO: setup channel to init for multiboot files */

    struct fs_mount *reg_mount = calloc(1, sizeof(struct fs_mount));
    if (reg_mount == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    struct ramfs_mount *mount = calloc(1, sizeof(struct ramfs_mount));
    if (mount == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    struct ramfs_dirent *ramfs_root;

    ramfs_root = calloc(1, sizeof(*ramfs_root));
    if (ramfs_root == NULL) {
        free(ramfs_mount);
        return LIB_ERR_MALLOC_FAIL;
    }

    ramfs_root->size = 0;
    ramfs_root->is_dir = true;
    ramfs_root->name = "/";
    ramfs_root->parent = NULL;

    mount->root = ramfs_root;

    reg_mount->state = mount;
    reg_mount->opendir = ramfs_opendir;
    reg_mount->mkdir = ramfs_mkdir;
    reg_mount->readdir = ramfs_dir_read_next;
    reg_mount->closedir = ramfs_closedir;
    reg_mount->rmdir = ramfs_rmdir;
    reg_mount->stat = ramfs_stat;

    reg_mount->open = ramfs_open;
    reg_mount->create = ramfs_create;
    reg_mount->read = ramfs_read;
    reg_mount->write = ramfs_write;
    reg_mount->seek = ramfs_seek;
    reg_mount->tell = ramfs_tell;
    reg_mount->remove = ramfs_remove;
    reg_mount->close = ramfs_close;

    *retst = reg_mount;

    return SYS_ERR_OK;
}

errval_t ramfs_add_mount(void *st, const char *path, ramfs_mount_t *mount_to_add)
{
    errval_t err;
    err = ramfs_mkdir(st, path);
    if (err_is_fail(err)) {
        return err;
    }

    struct fs_mount *reg_mount = st;
    struct ramfs_mount *mount = reg_mount->state;
    struct fs_handle *fh;
    struct ramfs_handle *handle;
    struct fs_mount *nest_mount = NULL;
    const char *nest_mount_path;
    err = resolve_path(reg_mount, mount->root, path, &fh, &nest_mount, &nest_mount_path);
    if (err_is_fail(err)) {
        return err;
    }

    handle = fh->state;

    // TODO: Support nested mount on FAT32:)
    assert(nest_mount == NULL);
    assert(handle->isdir);

    handle->dirent->is_dir = 0;
    handle->dirent->is_mount = 1;

    handle->dirent->mount = mount_to_add;

    handle_close(fh);

    return SYS_ERR_OK;
}
