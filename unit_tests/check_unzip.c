/*
 *  Unit tests for the ZIP parser.
 *
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <check.h>
#include <stdlib.h>
#include <string.h>

// libclamav
#include "clamav.h"
#include "others.h"

#define UNZIP_PRIVATE
#include "unzip.h"

#include "checks.h"

/*
 * The Zip64 Extended Information Extra Field (header ID 0x0001) is where a ZIP64 archive
 * keeps the real 64-bit sizes and offsets. Getting its field-presence rules wrong is the
 * easiest way to misparse a ZIP64 archive, so exercise them directly here.
 *
 * See APPNOTE.TXT section 4.5.3, and the ZIP64 notes in libclamav/unzip.h.
 */

/* Write one extra field record: header ID, the data size it *declares*, then the bytes that
 * actually follow. Passing a declared_size larger than data_len produces a truncated record. */
static size_t append_extra_field_record(
    uint8_t *buf,
    size_t offset,
    uint16_t header_id,
    uint16_t declared_size,
    const uint8_t *data,
    size_t data_len)
{
    buf[offset++] = (uint8_t)(header_id & 0xff);
    buf[offset++] = (uint8_t)((header_id >> 8) & 0xff);
    buf[offset++] = (uint8_t)(declared_size & 0xff);
    buf[offset++] = (uint8_t)((declared_size >> 8) & 0xff);

    if (0 != data_len) {
        memcpy(buf + offset, data, data_len);
        offset += data_len;
    }

    return offset;
}

static void put_u64(uint8_t *p, uint64_t value)
{
    int i;
    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)(value >> (8 * i));
    }
}

static void put_u32(uint8_t *p, uint32_t value)
{
    int i;
    for (i = 0; i < 4; i++) {
        p[i] = (uint8_t)(value >> (8 * i));
    }
}

START_TEST(test_zip64_extra_field_local_header)
{
    uint8_t buf[64];
    uint8_t data[16];
    size_t len;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    /* In a local file header both sizes are mandatory and always present, in this order. */
    put_u64(data, 0x44);
    put_u64(data + 8, 0x46);
    len = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 16, data, 16);

    ret = cli_zip_parse_zip64_extra_field(
        buf, len, false /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, 0, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(zip64_info.have_usize, "uncompressed size not found");
    ck_assert_msg(0x44 == zip64_info.usize, "usize: %" PRIu64 " != 0x44", zip64_info.usize);
    ck_assert_msg(zip64_info.have_csize, "compressed size not found");
    ck_assert_msg(0x46 == zip64_info.csize, "csize: %" PRIu64 " != 0x46", zip64_info.csize);
    ck_assert_msg(!zip64_info.have_local_header_offset,
                  "a local file header record must not yield a local header offset");
    ck_assert_msg(!zip64_info.have_disk_num,
                  "a local file header record must not yield a disk number");
}
END_TEST

/*
 * The exact 20 extra field bytes that Python's `ZipFile.open(..., force_zip64=True)` emits.
 * This is the archive shape from https://github.com/Cisco-Talos/clamav/issues/1527.
 */
START_TEST(test_zip64_extra_field_issue_1527)
{
    const uint8_t extra_field[20] = {
        0x01, 0x00, 0x10, 0x00,                                     /* id 0x0001, 16 bytes */
        0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             /* usize 0x44 */
        0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             /* csize 0x46 */
    };
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    ret = cli_zip_parse_zip64_extra_field(
        extra_field, sizeof(extra_field), false /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, 0, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(0x44 == zip64_info.usize, "usize: %" PRIu64 " != 0x44", zip64_info.usize);
    ck_assert_msg(0x46 == zip64_info.csize, "csize: %" PRIu64 " != 0x46", zip64_info.csize);
}
END_TEST

START_TEST(test_zip64_extra_field_local_header_too_short)
{
    uint8_t buf[64];
    uint8_t data[8] = {0};
    size_t len;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    /* Only 8 bytes, but a local file header record must carry both sizes. */
    len = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 8, data, 8);

    ret = cli_zip_parse_zip64_extra_field(
        buf, len, false /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, 0, 0, &zip64_info);

    ck_assert_msg(CL_EFORMAT == ret, "expected CL_EFORMAT, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(!zip64_info.have_usize && !zip64_info.have_csize,
                  "a malformed record must not yield partial values");
}
END_TEST

START_TEST(test_zip64_extra_field_central_all_fields)
{
    uint8_t buf[64];
    uint8_t data[28];
    size_t len;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    put_u64(data, 0x1111);
    put_u64(data + 8, 0x2222);
    put_u64(data + 16, 0x3333);
    put_u32(data + 24, 0x7);
    len = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 28, data, 28);

    ret = cli_zip_parse_zip64_extra_field(
        buf, len, true /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_16,
        &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(0x1111 == zip64_info.usize, "usize: %" PRIu64, zip64_info.usize);
    ck_assert_msg(0x2222 == zip64_info.csize, "csize: %" PRIu64, zip64_info.csize);
    ck_assert_msg(0x3333 == zip64_info.local_header_offset, "offset: %" PRIu64,
                  zip64_info.local_header_offset);
    ck_assert_msg(0x7 == zip64_info.disk_num, "disk: %u", zip64_info.disk_num);
}
END_TEST

/*
 * The subtle case: in a central directory file header only the fields whose 32-bit
 * counterpart holds the placeholder are stored. Here that is the local header offset alone,
 * so the record's first 8 bytes are the *offset* and not the uncompressed size.
 */
START_TEST(test_zip64_extra_field_central_only_offset)
{
    uint8_t buf[64];
    uint8_t data[8];
    size_t len;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    put_u64(data, 0xDEADBEEF);
    len = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 8, data, 8);

    ret = cli_zip_parse_zip64_extra_field(
        buf, len, true /* is_central_directory */,
        0x46 /* csize32 */, 0x44 /* usize32 */, ZIP64_PLACEHOLDER_32, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(!zip64_info.have_usize, "usize must not be claimed; it was not a placeholder");
    ck_assert_msg(!zip64_info.have_csize, "csize must not be claimed; it was not a placeholder");
    ck_assert_msg(zip64_info.have_local_header_offset, "local header offset not found");
    ck_assert_msg(0xDEADBEEF == zip64_info.local_header_offset, "offset: %" PRIu64,
                  zip64_info.local_header_offset);
}
END_TEST

START_TEST(test_zip64_extra_field_central_no_placeholders)
{
    uint8_t buf[64];
    uint8_t data[28] = {0};
    size_t len;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    len = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 28, data, 28);

    ret = cli_zip_parse_zip64_extra_field(
        buf, len, true /* is_central_directory */, 0x46, 0x44, 0x0, 0x0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(!zip64_info.have_usize && !zip64_info.have_csize &&
                      !zip64_info.have_local_header_offset && !zip64_info.have_disk_num,
                  "no field held a placeholder, so nothing should be claimed");
}
END_TEST

START_TEST(test_zip64_extra_field_central_missing_field)
{
    uint8_t buf[64];
    uint8_t data[8];
    size_t len;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    /* Both sizes are placeholders but only one 8-byte value is present. */
    put_u64(data, 0x1111);
    len = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 8, data, 8);

    ret = cli_zip_parse_zip64_extra_field(
        buf, len, true /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, 0, 0, &zip64_info);

    ck_assert_msg(CL_EFORMAT == ret, "expected CL_EFORMAT, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(!zip64_info.have_usize && !zip64_info.have_csize,
                  "a malformed record must not yield partial values");
}
END_TEST

START_TEST(test_zip64_extra_field_truncated_record)
{
    uint8_t buf[64];
    uint8_t data[8] = {0};
    size_t len;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    /* Declares 16 bytes of data but only 8 follow. */
    len = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 16, data, 8);

    ret = cli_zip_parse_zip64_extra_field(
        buf, len, false /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, 0, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret,
                  "a record claiming more data than the extra field has should just be skipped, got %s (%d)",
                  cl_strerror(ret), ret);
    ck_assert_msg(!zip64_info.have_usize && !zip64_info.have_csize, "nothing should be claimed");
}
END_TEST

START_TEST(test_zip64_extra_field_record_size_overflow)
{
    uint8_t buf[64];
    size_t len;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    len = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 0xFFFF, NULL, 0);

    ret = cli_zip_parse_zip64_extra_field(
        buf, len, false /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, 0, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(!zip64_info.have_usize && !zip64_info.have_csize, "nothing should be claimed");
}
END_TEST

/* A long run of zero-length records must terminate, not spin forever. */
START_TEST(test_zip64_extra_field_zero_length_records)
{
    uint8_t buf[4096];
    size_t offset = 0;
    int i;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    for (i = 0; i < 1000; i++) {
        offset = append_extra_field_record(buf, offset, 0x5455 /* extended timestamp */, 0, NULL, 0);
    }

    ret = cli_zip_parse_zip64_extra_field(
        buf, offset, false /* is_central_directory */, 0, 0, 0, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(!zip64_info.have_usize, "nothing should be claimed");
}
END_TEST

START_TEST(test_zip64_extra_field_other_record_ids)
{
    uint8_t buf[128];
    uint8_t timestamp[5] = {1, 2, 3, 4, 5};
    uint8_t unix_ids[11] = {0};
    uint8_t data[16];
    size_t offset;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    put_u64(data, 0xAAAA);
    put_u64(data + 8, 0xBBBB);

    offset = append_extra_field_record(buf, 0, 0x5455 /* extended timestamp */, 5, timestamp, 5);
    offset = append_extra_field_record(buf, offset, ZIP_EXTRA_FIELD_ID_ZIP64, 16, data, 16);
    offset = append_extra_field_record(buf, offset, 0x7875 /* unix uid/gid */, 11, unix_ids, 11);

    ret = cli_zip_parse_zip64_extra_field(
        buf, offset, false /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, 0, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(0xAAAA == zip64_info.usize, "usize: %" PRIu64, zip64_info.usize);
    ck_assert_msg(0xBBBB == zip64_info.csize, "csize: %" PRIu64, zip64_info.csize);
}
END_TEST

START_TEST(test_zip64_extra_field_duplicate_records)
{
    uint8_t buf[128];
    uint8_t first[16];
    uint8_t second[16];
    size_t offset;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    put_u64(first, 1);
    put_u64(first + 8, 2);
    put_u64(second, 3);
    put_u64(second + 8, 4);

    offset = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 16, first, 16);
    offset = append_extra_field_record(buf, offset, ZIP_EXTRA_FIELD_ID_ZIP64, 16, second, 16);

    ret = cli_zip_parse_zip64_extra_field(
        buf, offset, false /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, 0, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(1 == zip64_info.usize && 2 == zip64_info.csize,
                  "the first record should win; got usize %" PRIu64 " csize %" PRIu64,
                  zip64_info.usize, zip64_info.csize);
}
END_TEST

START_TEST(test_zip64_extra_field_empty_and_null)
{
    uint8_t buf[16] = {0};
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    /* No extra field at all is not an error. */
    ret = cli_zip_parse_zip64_extra_field(NULL, 0, false, 0, 0, 0, 0, &zip64_info);
    ck_assert_msg(CL_SUCCESS == ret, "an empty extra field should succeed, got %s (%d)",
                  cl_strerror(ret), ret);
    ck_assert_msg(!zip64_info.have_usize && !zip64_info.have_csize, "nothing should be claimed");

    ret = cli_zip_parse_zip64_extra_field(NULL, 16, false, 0, 0, 0, 0, &zip64_info);
    ck_assert_msg(CL_ENULLARG == ret, "expected CL_ENULLARG, got %s (%d)", cl_strerror(ret), ret);

    ret = cli_zip_parse_zip64_extra_field(buf, sizeof(buf), false, 0, 0, 0, 0, NULL);
    ck_assert_msg(CL_ENULLARG == ret, "expected CL_ENULLARG, got %s (%d)", cl_strerror(ret), ret);
}
END_TEST

/* Fewer bytes than an extra field header. */
START_TEST(test_zip64_extra_field_runt)
{
    uint8_t buf[3] = {0x01, 0x00, 0x10};
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    ret = cli_zip_parse_zip64_extra_field(
        buf, sizeof(buf), false, 0, 0, 0, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(!zip64_info.have_usize, "nothing should be claimed");
}
END_TEST

/* The whole point of ZIP64: values that do not fit in 32 bits. */
START_TEST(test_zip64_extra_field_large_values)
{
    uint8_t buf[64];
    uint8_t data[16];
    size_t len;
    cl_error_t ret;
    struct zip64_extra_info zip64_info;

    put_u64(data, 0x1234ABCDEULL);     /* ~4.8 GiB uncompressed */
    put_u64(data + 8, 0x100000000ULL); /* exactly 4 GiB compressed */
    len = append_extra_field_record(buf, 0, ZIP_EXTRA_FIELD_ID_ZIP64, 16, data, 16);

    ret = cli_zip_parse_zip64_extra_field(
        buf, len, false /* is_central_directory */,
        ZIP64_PLACEHOLDER_32, ZIP64_PLACEHOLDER_32, 0, 0, &zip64_info);

    ck_assert_msg(CL_SUCCESS == ret, "expected CL_SUCCESS, got %s (%d)", cl_strerror(ret), ret);
    ck_assert_msg(0x1234ABCDEULL == zip64_info.usize, "usize: %" PRIu64, zip64_info.usize);
    ck_assert_msg(0x100000000ULL == zip64_info.csize, "csize: %" PRIu64, zip64_info.csize);
}
END_TEST

Suite *test_unzip_suite(void)
{
    Suite *s = suite_create("unzip");
    TCase *tc_zip64_extra_field;

    tc_zip64_extra_field = tcase_create("zip64 extra field");
    suite_add_tcase(s, tc_zip64_extra_field);

    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_local_header);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_issue_1527);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_local_header_too_short);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_central_all_fields);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_central_only_offset);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_central_no_placeholders);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_central_missing_field);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_truncated_record);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_record_size_overflow);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_zero_length_records);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_other_record_ids);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_duplicate_records);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_empty_and_null);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_runt);
    tcase_add_test(tc_zip64_extra_field, test_zip64_extra_field_large_values);

    return s;
}
