/*
 * Copyright (c) 2009, 2010, 2011, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef FS_INTERNAL_H_
#define FS_INTERNAL_H_

#include <fs/dirent.h>

typedef errval_t (*fs_mount_opendir_fn_t)(void *mount, const char *, fs_dirhandle_t *);
typedef errval_t (*fs_mount_readdir_fn_t)(void *handle, char **retname);
typedef errval_t (*fs_mount_closedir_fn_t)(void *handle);
typedef errval_t (*fs_mount_mkdir_fn_t)(void *mount, const char *);
typedef errval_t (*fs_mount_rmdir_fn_t)(void *mount, const char *);
typedef errval_t (*fs_mount_stat_fn_t)(void *handle, struct fs_fileinfo *);

typedef errval_t (*fs_mount_open_fn_t)(void *mount, const char *, fs_dirhandle_t *);
typedef errval_t (*fs_mount_create_fn_t)(void *mount, const char *, fs_dirhandle_t *);
typedef errval_t (*fs_mount_read_fn_t)(void *handle, void *buffer, size_t bytes,
                                       size_t *bytes_read);
typedef errval_t (*fs_mount_write_fn_t)(void *handle, const void *buffer, size_t bytes,
                                        size_t *bytes_written);
typedef errval_t (*fs_mount_remove_fn_t)(void *mount, const char *);
typedef errval_t (*fs_mount_close_fn_t)(void *handle);
typedef errval_t (*fs_mount_seek_fn_t)(void *handle, enum fs_seekpos whence, off_t offset);
typedef errval_t (*fs_mount_tell_fn_t)(void *handle, size_t *);

struct fs_mount {
    void *state;
    fs_mount_opendir_fn_t opendir;
    fs_mount_mkdir_fn_t mkdir;
    fs_mount_readdir_fn_t readdir;
    fs_mount_closedir_fn_t closedir;
    fs_mount_rmdir_fn_t rmdir;
    fs_mount_stat_fn_t stat;

    fs_mount_open_fn_t open;
    fs_mount_create_fn_t create;
    fs_mount_read_fn_t read;
    fs_mount_write_fn_t write;
    fs_mount_seek_fn_t seek;
    fs_mount_tell_fn_t tell;
    fs_mount_remove_fn_t remove;
    fs_mount_close_fn_t close;
};

struct fs_handle {
    struct fs_mount *mount;
    void *state;
};


/*
 * fdtab
 */
#define MIN_FD 0
#ifndef MAX_FD
//#define MAX_FD  132
#    define MAX_FD 4096
#endif


enum fdtab_type {
    FDTAB_TYPE_AVAILABLE,
    FDTAB_TYPE_FILE,
    FDTAB_TYPE_UNIX_SOCKET,
    FDTAB_TYPE_STDIN,
    FDTAB_TYPE_STDOUT,
    FDTAB_TYPE_STDERR
};

#include <signal.h>
#include <sys/epoll.h>

struct fdtab_entry {
    enum fdtab_type type;
    //    union {
    struct fs_handle *handle;
    int fd;
    int inherited;
    //    };
    int epoll_fd;
};

/* for the newlib glue code */
void fs_libc_init(struct fs_mount *fs_state);

#endif
