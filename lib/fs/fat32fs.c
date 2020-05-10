#include <fs/fat32fs.h>
#include "fs_internal.h"
#include "fat32fs_internal.h"

errval_t fat32fs_open(void *st, const char *path, fs_dirhandle_t *ret_handle)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_create(void *st, const char *path, fs_dirhandle_t *ret_handle)
{
    USER_PANIC("NYI\n");
}
errval_t fat32fs_read(void *handle, void *buffer, size_t bytes, size_t *bytes_read)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_write(void *handle, const void *buffer, size_t bytes,
                       size_t *bytes_written)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_seek(void *handle, enum fs_seekpos whence, off_t offset)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_tell(void *handle, size_t *pos)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_close(void *handle)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_remove(void *st, const char *path)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_opendir(void *st, const char *path, fs_dirhandle_t *ret_handle)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_mkdir(void *st, const char *path)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_readdir(void *handle, char **retname, struct fs_fileinfo *info)
{
    USER_PANIC("NYI\n");
}

errval_t fat32fs_closedir(void *handle)
{
    USER_PANIC("NYI\n");
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
