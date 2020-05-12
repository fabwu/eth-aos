/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef FS_FAT32FS_H_
#define FS_FAT32FS_H_

#include <fs/fs.h>

typedef void *fat32fs_handle_t;
typedef void *fat32fs_mount_t;

errval_t fat32fs_open(void *st, const char *path, fat32fs_handle_t *rethandle);

errval_t fat32fs_create(void *st, const char *path, fat32fs_handle_t *rethandle);

errval_t fat32fs_remove(void *st, const char *path);

errval_t fat32fs_read(void *handle, void *buffer, size_t bytes,
                      size_t *bytes_read);

errval_t fat32fs_write(void *handle, const void *buffer,
                       size_t bytes, size_t *bytes_written);

errval_t fat32fs_truncate(void *handle, size_t bytes);

errval_t fat32fs_tell(void *handle, size_t *pos);

errval_t fat32fs_stat(void *handle, struct fs_fileinfo *info);

errval_t fat32fs_seek(void *handle, enum fs_seekpos whence,
                      off_t offset);

errval_t fat32fs_close(void *handle);

errval_t fat32fs_opendir(void *st, const char *path, fat32fs_handle_t *rethandle);

errval_t fat32fs_readdir(void *handle, char **retname);

errval_t fat32fs_closedir(void *handle);

errval_t fat32fs_mkdir(void *st, const char *path);

errval_t fat32fs_rmdir(void *st, const char *path);

errval_t fat32fs_init(fat32fs_mount_t *retst);

#endif /* FS_FAT32FS_H_ */
