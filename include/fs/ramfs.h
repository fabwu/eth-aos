/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef FS_RAMFS_H_
#define FS_RAMFS_H_

#include <fs/fs.h>

typedef void *ramfs_handle_t;
typedef void *ramfs_mount_t;

errval_t ramfs_open(void *st, const char *path, ramfs_handle_t *rethandle);

errval_t ramfs_create(void *st, const char *path, ramfs_handle_t *rethandle);

errval_t ramfs_remove(void *st, const char *path);

errval_t ramfs_read(void *handle, void *buffer, size_t bytes,
                    size_t *bytes_read);

errval_t ramfs_write(void *handle, const void *buffer, size_t bytes,
                     size_t *bytes_written);

errval_t ramfs_truncate(void *st, ramfs_handle_t handle, size_t bytes);

errval_t ramfs_tell(void *handle, size_t *pos);

errval_t ramfs_stat(void *handle, struct fs_fileinfo *info);

errval_t ramfs_seek(void *handle, enum fs_seekpos whence, off_t offset);

errval_t ramfs_close(void *handle);

errval_t ramfs_opendir(void *st, const char *path, ramfs_handle_t *rethandle);

errval_t ramfs_dir_read_next(void *handle, char **retname);

errval_t ramfs_closedir(void *handle);

errval_t ramfs_mkdir(void *st, const char *path);

errval_t ramfs_rmdir(void *st, const char *path);

errval_t ramfs_mount(const char *uri, ramfs_mount_t *retst);

errval_t ramfs_add_mount(void *st, const char *path, ramfs_mount_t *mount);

#endif /* FS_RAMFS_H_ */
