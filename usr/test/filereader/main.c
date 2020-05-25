/**
 * \file
 * \brief file system test application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */


#include <stdio.h>

#include <aos/aos.h>
#include <aos/systime.h>
#include <fs/fs.h>
#include <fs/dirent.h>

static uint64_t systime_to_ms(systime_t time)
{
    return systime_to_us(time) / 1000;
}

#define ENABLE_LONG_FILENAME_TEST 0

/* reading */
#define MOUNTPOINT "/sdcard"
#define SUBDIR "/parent"
#define SUBDIR_LONG "/parent-directory"
#define DIR_NOT_EXIST "/not-exist"
#define FILENAME "/MYFILE2.TXT"
#define FILENAME_NESTED "/TEST/MYFILE2.TXT"
#define ORIG_FILENAME "/myfile2.txt"
#define TEST_DIRNAME "TESTDIR"
#define TEST_FILENAME "TESTFILE"
#define LONGFILENAME "/mylongfilenamefile.txt"
#define LONGFILENAME2 "/mylongfilenamefilesecond.txt"
#define FILE_NOT_EXIST "/not-exist.txt"

#define TEST_PREAMBLE(arg)                                                               \
    debug_printf("\n-------------------------------\n");                                 \
    debug_printf("%s(%s)\n", __FUNCTION__, arg);

#define TEST_END debug_printf("-------------------------------\n");

#define EXPECT_SUCCESS(err, test, _time)                                                 \
    do {                                                                                 \
        if (err_is_fail(err)) {                                                          \
            DEBUG_ERR(err, test);                                                        \
            debug_printf("\n");                                                          \
        } else {                                                                         \
            debug_printf("SUCCESS: " test " took %" PRIu64 " ms\n", _time);              \
        }                                                                                \
    } while (0);

#define EXPECT_FAILURE(err, _test, _time)                                                \
    do {                                                                                 \
        if (err_is_fail(err)) {                                                          \
            debug_printf("SUCCESS: failure expected " _test " took %" PRIu64 " ms\n",    \
                         _time);                                                         \
        } else {                                                                         \
            DEBUG_ERR(err, "FAILURE: failure expected, but test succeeded" _test);       \
        }                                                                                \
    } while (0);

#define run_test(fn, ...)                                                                \
    do {                                                                                 \
        tstart = systime_now();                                                          \
        err = fn(__VA_ARGS__);                                                           \
        tend = systime_now();                                                            \
        EXPECT_SUCCESS(err, #fn, systime_to_ms(tend - tstart));                          \
        TEST_END                                                                         \
    } while (0);

#define run_test_fail(fn, ...)                                                           \
    do {                                                                                 \
        tstart = systime_now();                                                          \
        err = fn(__VA_ARGS__);                                                           \
        tend = systime_now();                                                            \
        EXPECT_FAILURE(err, #fn, systime_to_ms(tend - tstart));                          \
        TEST_END                                                                         \
    } while (0);

static const char *dot = ".";
static const char *dotdot = "..";

static errval_t test_read_dir(char *dir)
{
    errval_t err;

    TEST_PREAMBLE(dir)

    fs_dirhandle_t dh;
    err = opendir(dir, &dh);
    if (err_is_fail(err)) {
        return err;
    }

    assert(dh);

    do {
        char *name;
        err = readdir(dh, &name);
        if (err_no(err) == FS_ERR_INDEX_BOUNDS) {
            break;
        } else if (err_is_fail(err)) {
            goto err_out;
        }
        printf("%s\n", name);
    } while (err_is_ok(err));

    return closedir(dh);
err_out:
    return err;
}

static errval_t test_fread(char *file)
{
    int res = 0;

    TEST_PREAMBLE(file)

    FILE *f = fopen(file, "r");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }

    // Bad code?, SEI CERT FIO19-C
    /* obtain the file size */
    res = fseek(f, 0, SEEK_END);
    if (res) {
        return FS_ERR_INVALID_FH;
    }

    size_t filesize = ftell(f);
    rewind(f);

    debug_printf("File size is %zu\n", filesize);

    char *buf = calloc(filesize + 2, sizeof(char));
    if (buf == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    size_t read = fread(buf, 1, filesize, f);

    *(buf + read) = '\0';
    debug_printf("bytes_read: %zx\n", read);
    debug_printf("read:\n%s\n", buf);

    if (read != filesize) {
        return FS_ERR_READ;
    }

    res = fseek(f, filesize / 2, SEEK_SET);
    if (res) {
        return FS_ERR_INVALID_FH;
    }
    read = fread(buf, 1, filesize, f);
    *(buf + read) = '\0';
    debug_printf("bytes_read: %zx\n", read);
    debug_printf("read:\n%s\n", buf);

    rewind(f);

    size_t nchars = 0;
    int c;
    do {
        c = fgetc(f);
        nchars++;
    } while (c != EOF);

    if (nchars < filesize) {
        return FS_ERR_READ;
    }

    free(buf);
    res = fclose(f);
    if (res) {
        return FS_ERR_CLOSE;
    }

    return SYS_ERR_OK;
}

static errval_t test_fwrite(char *file)
{
    int res = 0;
    TEST_PREAMBLE(file)

    FILE *f = fopen(file, "w");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }

    const char *inspirational_quote = "I love deadlines. I like the whooshing "
                                      "sound they make as they fly by.";

    size_t written = fwrite(inspirational_quote, 1, strlen(inspirational_quote), f);
    printf("wrote %zu bytes\n", written);

    if (written != strlen(inspirational_quote)) {
        return FS_ERR_READ;
    }

    res = fclose(f);
    if (res) {
        return FS_ERR_CLOSE;
    }

    return SYS_ERR_OK;
}

static errval_t test_check_dir_empty(const char *dir)
{
    errval_t err;

    fs_dirhandle_t dh;
    bool found_dot;
    bool found_dotdot;
    size_t files_found;

    err = opendir(dir, &dh);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_OPENDIR);
    }

    assert(dh);

    files_found = 0;
    found_dot = false;
    found_dotdot = false;
    do {
        char *name;
        err = readdir(dh, &name);
        if (err_no(err) == FS_ERR_INDEX_BOUNDS) {
            break;
        } else if (err_is_fail(err)) {
            return err_push(err, FS_ERR_READDIR);
        } else if (!strcmp(name, dot)) {
            found_dot = true;
        } else if (!strcmp(name, dotdot)) {
            found_dotdot = true;
        } else {
            debug_printf("test_file name doesn't match\n");
            return FS_ERR_RMDIR;
        }
        ++files_found;
        printf("%s\n", name);
    } while (err_is_ok(err));

    if (!(files_found == 0) || (files_found == 2 && found_dot && found_dotdot)) {
        debug_printf("test_file dir not empty\n");
        return FS_ERR_OPEN;
    }

    err = closedir(dh);
    if (err) {
        return err_push(err, FS_ERR_CLOSEDIR);
    }

    return SYS_ERR_OK;
}

static errval_t test_check_dir_contains_exactly(const char *dir, const char *filename)
{
    errval_t err;

    fs_dirhandle_t dh;
    bool found_dot;
    bool found_dotdot;
    bool found_file;
    size_t files_found;

    err = opendir(dir, &dh);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_OPENDIR);
    }

    assert(dh);

    files_found = 0;
    found_dot = false;
    found_dotdot = false;
    found_file = false;
    do {
        char *name;
        err = readdir(dh, &name);
        if (err_no(err) == FS_ERR_INDEX_BOUNDS) {
            break;
        } else if (err_is_fail(err)) {
            return err;
        } else if (!strcmp(name, dot)) {
            found_dot = true;
        } else if (!strcmp(name, dotdot)) {
            found_dotdot = true;
        } else if (!strcmp(name, filename)) {
            found_file = true;
        } else {
            debug_printf("test_dir name doesn't match\n");
            return FS_ERR_MKDIR;
        }
        ++files_found;
        printf("%s\n", name);
    } while (err_is_ok(err));

    if (!((files_found == 1 && found_file)
          || (files_found == 3 && found_dot && found_dotdot && found_file))) {
        if (found_file) {
            debug_printf("test_dir dir found multiple times\n");
            return FS_ERR_MKDIR;
        } else {
            debug_printf("test_dir dir not found\n");
            return FS_ERR_MKDIR;
        }
    }

    err = closedir(dh);
    if (err) {
        return err_push(err, FS_ERR_CLOSEDIR);
    }

    return SYS_ERR_OK;
}

static errval_t test_dir(char *parent_dir, char *dir, char *dirname)
{
    bool found_dot;
    bool found_dotdot;
    size_t files_found;
    errval_t err;
    fs_dirhandle_t dh;

    err = test_check_dir_empty(parent_dir);
    if (err_is_fail(err)) {
        return err;
    }

    err = mkdir(dir);
    if (err) {
        return err_push(err, FS_ERR_MKDIR);
    }

    err = test_check_dir_contains_exactly(parent_dir, dirname);
    if (err_is_fail(err)) {
        return err;
    }

    err = opendir(dir, &dh);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_OPENDIR);
    }

    assert(dh);

    files_found = 0;
    found_dot = false;
    found_dotdot = false;
    do {
        char *name;
        err = readdir(dh, &name);
        if (err_no(err) == FS_ERR_INDEX_BOUNDS) {
            break;
        } else if (err_is_fail(err)) {
            return err_push(err, FS_ERR_READDIR);
        } else if (!strcmp(name, dot)) {
            found_dot = true;
        } else if (!strcmp(name, dotdot)) {
            found_dotdot = true;
        } else {
            debug_printf("test_dir name doesn't match\n");
            return FS_ERR_MKDIR;
        }
        ++files_found;
        printf("%s\n", name);
    } while (err_is_ok(err));

    // We are not root_dir, so we always need to contain .. and . entries
    if (!(files_found == 2 && found_dot && found_dotdot)) {
        debug_printf("test_dir dir doesn't contain exactly only dot entries\n");
        return FS_ERR_MKDIR;
    }

    err = closedir(dh);
    if (err) {
        return err_push(err, FS_ERR_CLOSEDIR);
    }

    // FIXME: Open dot entries, verify they contain the same as parent_dir, dir

    err = rmdir(dir);
    if (err) {
        return err_push(err, FS_ERR_RMDIR);
    }

    err = test_check_dir_empty(parent_dir);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t test_file(char *parent_dir, char *dir, char *filename)
{
    errval_t err;

    FILE *f;

    err = test_check_dir_empty(parent_dir);
    if (err_is_fail(err)) {
        return err;
    }

    // Create file
    f = fopen(dir, "a");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }

    err = fclose(f);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_CLOSE);
    }

    err = test_check_dir_contains_exactly(parent_dir, filename);
    if (err_is_fail(err)) {
        return err;
    }

    // Remove file
    err = rm(dir);
    if (err_is_fail(err)) {
        return err_push(err, FS_ERR_REMOVE);
    }

    err = test_check_dir_empty(parent_dir);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

#define FS_TEST_READ_DIR 0
#define FS_TEST_READ 0
#define FS_TEST_DIR 0
#define FS_TEST_FILE 1
#define FS_TEST_WRITE 0

int main(int argc, char *argv[])
{
    errval_t err;
    uint64_t tstart, tend;

    printf("Filereader test\n");

    printf("initializing filesystem...\n");
    err = filesystem_init();
    EXPECT_SUCCESS(err, "fs init", 0);

    if (FS_TEST_READ_DIR) {
        run_test(test_read_dir, "/");

        run_test(test_read_dir, MOUNTPOINT "/");

        run_test_fail(test_read_dir, DIR_NOT_EXIST);
    }

    if (FS_TEST_READ) {
        run_test(test_fread, MOUNTPOINT FILENAME_NESTED);

        run_test(test_fread, MOUNTPOINT FILENAME);
    }

    if (FS_TEST_DIR) {
        run_test(test_dir, MOUNTPOINT, MOUNTPOINT "/" TEST_DIRNAME, TEST_DIRNAME);
    }

    if (FS_TEST_FILE) {
        run_test(test_file, MOUNTPOINT, MOUNTPOINT "/" TEST_FILENAME, TEST_FILENAME);
    }

    if (FS_TEST_WRITE) {
        run_test(test_fwrite, MOUNTPOINT ORIG_FILENAME);
    }

    err = filesystem_unmount();
    EXPECT_SUCCESS(err, "fs init", 0);

    return EXIT_SUCCESS;
}
