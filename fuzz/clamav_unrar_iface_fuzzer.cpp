/*
 * Fuzz target for the libclamunrar_iface functions:
 * unrar_open(), unrar_peek_file_header(), unrar_extract_file(),
 * unrar_skip_file() and unrar_close(), driven as cli_scanrar_file() drives them.
 *
 * The input is one archive file, possibly with a prefix before its first RAR
 * signature as in a self-extracting archive. If it holds further RAR signatures
 * after the first, each piece from a signature onward is written as the next
 * volume of the set (fuzz.part1.rar, fuzz.part2.rar, ...), so volume handling is
 * reached. Each later volume is also written under the old-style name that a
 * RAR 2.9 set without new numbering asks for (fuzz.part1.r00, fuzz.part1.r01, ...).
 *
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {
#include "unrar_iface.h"
}

namespace
{

constexpr size_t kMaxVolumes        = 8;
constexpr uint64_t kMaxExtractSize  = 64ull * 1024 * 1024;
constexpr unsigned kMaxHeaders      = 256;
constexpr size_t kPathMax           = 512;
constexpr uint8_t kRar4Signature[7] = {0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00};
constexpr uint8_t kRar5Signature[8] = {0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00};

char g_dir[kPathMax];
char g_extract_path[kPathMax];

bool write_file(const char *path, const uint8_t *data, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return false;
    }
    while (size > 0) {
        ssize_t n = write(fd, data, size);
        if (n <= 0) {
            close(fd);
            return false;
        }
        data += n;
        size -= static_cast<size_t>(n);
    }
    return close(fd) == 0;
}

bool is_signature_at(const uint8_t *data, size_t size, size_t offset)
{
    if (offset + sizeof(kRar5Signature) <= size && memcmp(data + offset, kRar5Signature, sizeof(kRar5Signature)) == 0) {
        return true;
    }
    return offset + sizeof(kRar4Signature) <= size && memcmp(data + offset, kRar4Signature, sizeof(kRar4Signature)) == 0;
}

uint32_t fnv1a(const uint8_t *data, size_t size)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < size; i++) {
        h = (h ^ data[i]) * 16777619u;
    }
    return h;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    const char *tmp = getenv("TMPDIR");
    snprintf(g_dir, sizeof(g_dir), "%s/unrar-iface-fuzz-XXXXXX", tmp != nullptr ? tmp : "/tmp");
    if (mkdtemp(g_dir) == nullptr) {
        perror("mkdtemp");
        abort();
    }
    snprintf(g_extract_path, sizeof(g_extract_path), "%s/fuzz.extracted", g_dir);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char volumes[kMaxVolumes][kPathMax];
    char old_style_names[kMaxVolumes][kPathMax];
    size_t volume_count = 0;
    size_t begin        = 0;

    size_t first_signature = 0;
    while (first_signature < size && !is_signature_at(data, size, first_signature)) {
        first_signature++;
    }

    while (volume_count < kMaxVolumes) {
        size_t end          = size;
        size_t search_start = (volume_count == 0 ? first_signature : begin) + 1;
        for (size_t i = search_start; i < size && volume_count + 1 < kMaxVolumes; i++) {
            if (is_signature_at(data, size, i)) {
                end = i;
                break;
            }
        }
        snprintf(volumes[volume_count], kPathMax, "%s/fuzz.part%zu.rar", g_dir, volume_count + 1);
        if (!write_file(volumes[volume_count], data + begin, end - begin)) {
            perror("write_file");
            abort();
        }
        if (volume_count > 0) {
            snprintf(old_style_names[volume_count], kPathMax, "%s/fuzz.part1.r%02zu", g_dir, volume_count - 1);
            if (!write_file(old_style_names[volume_count], data + begin, end - begin)) {
                perror("write_file");
                abort();
            }
        }
        volume_count++;
        if (end == size) {
            break;
        }
        begin = end;
    }

    uint32_t choices = fnv1a(data, size);

    void *archive         = nullptr;
    char *comment         = nullptr;
    uint32_t comment_size = 0;

    cl_unrar_error_t ret = unrar_open(volumes[0], &archive, &comment, &comment_size, 0);
    if (ret == UNRAR_OK) {
        if (comment != nullptr && comment_size > 0) {
            volatile char sink = comment[comment_size - 1];
            (void)sink;
        }

        for (unsigned count = 0; count < kMaxHeaders; count++) {
            unrar_metadata_t metadata;
            memset(&metadata, 0, sizeof(metadata));

            ret = unrar_peek_file_header(archive, &metadata);
            if (ret == UNRAR_ENCRYPTED) {
                if (unrar_skip_file(archive) != UNRAR_OK) {
                    break;
                }
                continue;
            }
            if (ret != UNRAR_OK) {
                break;
            }
            if (memchr(metadata.filename, '\0', sizeof(metadata.filename)) == nullptr) {
                abort();
            }

            bool extract = (choices >> (count % 32)) & 1;
            if (metadata.is_dir || metadata.encrypted || metadata.unpack_size > kMaxExtractSize || !extract) {
                if (unrar_skip_file(archive) != UNRAR_OK) {
                    break;
                }
                continue;
            }
            (void)unrar_extract_file(archive, g_extract_path, nullptr);
            unlink(g_extract_path);
        }
    }

    unrar_close(archive);
    free(comment);

    for (size_t i = 0; i < volume_count; i++) {
        unlink(volumes[i]);
        if (i > 0) {
            unlink(old_style_names[i]);
        }
    }
    return 0;
}
