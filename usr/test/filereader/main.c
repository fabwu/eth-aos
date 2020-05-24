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
#define TEST_DIRNAME "/TESTDIR"
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

#define run_test(fn, arg)                                                                \
    do {                                                                                 \
        tstart = systime_now();                                                          \
        err = fn(arg);                                                                   \
        tend = systime_now();                                                            \
        EXPECT_SUCCESS(err, #fn, systime_to_ms(tend - tstart));                          \
        TEST_END                                                                         \
    } while (0);

#define run_test_fail(fn, arg)                                                           \
    do {                                                                                 \
        tstart = systime_now();                                                          \
        err = fn(arg);                                                                   \
        tend = systime_now();                                                            \
        EXPECT_FAILURE(err, #fn, systime_to_ms(tend - tstart));                          \
        TEST_END                                                                         \
    } while (0);


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

static errval_t test_fmkdir(char *file)
{
    int res;

    res = mkdir(file);
    if (res) {
        return FS_ERR_MKDIR;
    }

    errval_t err;
    fs_dirhandle_t dh;
    err = opendir(MOUNTPOINT, &dh);
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
            return err;
        }
        printf("%s\n", name);
    } while (err_is_ok(err));

    res = closedir(dh);
    if (res) {
        return FS_ERR_CLOSEDIR;
    }

    res = mkdir(file);
    if (res) {
        return FS_ERR_MKDIR;
    }

    return SYS_ERR_OK;
}

#define FS_TEST_READ_DIR 0
#define FS_TEST_READ 0
#define FS_TEST_MKDIR 1
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

    if (FS_TEST_MKDIR) {
        run_test(test_fmkdir, MOUNTPOINT TEST_DIRNAME);
    }

    if (FS_TEST_WRITE) {
        run_test(test_fwrite, MOUNTPOINT ORIG_FILENAME);
    }

    err = filesystem_unmount();
    EXPECT_SUCCESS(err, "fs init", 0);

    return EXIT_SUCCESS;
}
