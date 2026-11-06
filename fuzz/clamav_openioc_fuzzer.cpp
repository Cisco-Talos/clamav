/*
 * Fuzz target for ClamAV OpenIOC (`.ioc`) database loading and evaluation.
 *
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * Rationale (OSS-Fuzz coverage pipeline, 2026-11):
 * readdb.c dispatches `.ioc` files to `cli_loadopenioc` -> `openioc_parse`
 * (openioc.c), an XML-based indicator parser that feeds the hash matcher
 * (`engine->hm_hdb`). None of the OSS-Fuzz fuzz targets loads `.ioc`
 * databases -- the `clamav_dbload_<TYPE>_fuzzer` matrix covers CDB..YARA but
 * has no IOC variant -- so openioc.c (streaming xmlTextReader parse, hash
 * element extraction, hash-matcher insertion and the scan-time evaluation)
 * is dark project-wide.
 *
 * Threat model: IOC databases are remote-controlled XML (indicator feeds /
 * compromised update source); the parser runs xmlTextReader over attacker
 * bytes and copies attacker-controlled strings into matcher structures.
 * Expected bug classes: memory safety in the streaming XML parse loop and
 * string handling, plus matcher integration during scan.
 *
 * Input shape: [OpenIOC XML bytes][separator][file to scan].
 * The separator is `\n;;CFDB;;\n`; the XML part is written to a temporary
 * `.ioc` file and loaded into a fresh engine, the engine is compiled, and
 * the remainder is scanned so loaded IOC indicators are evaluated against
 * attacker-controlled content. Seeds pair crafted IOC XMLs (md5/sha1/sha256
 * of the paired sample, plus nested/malformed variants) with their samples,
 * so hash-match detection paths are exercised from the start.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define _GNU_SOURCE /* memmem() */
#include <string.h>

#include "clamav.h"

/* Apple does not define __pid_t */
#ifdef __APPLE__
typedef pid_t __pid_t;
#endif

static const char kSep[] = "\n;;CFDB;;\n";

static void clamav_message_callback(enum cl_msg severity, const char* fullmsg,
                                    const char* msg, void* context)
{
    (void)severity;
    (void)fullmsg;
    (void)msg;
    (void)context;
}

class ClamAVInit
{
  public:
    ClamAVInit()
    {
        /* The compiled-in CERTSDIR does not exist in the fuzzing environment,
         * so codesign_verifier_new() fails and every cl_load() returns CL_ECVD
         * before a single byte of database is parsed (this is why the existing
         * clamav_dbload_* targets have never loaded a signature on OSS-Fuzz).
         * Point the verifier at the working directory so database loading
         * works: .cld containers skip verification entirely, and verification
         * failures on crafted .cvd inputs are exactly the error paths this
         * harness wants covered. */
        setenv("CVD_CERTS_DIR", ".", 1);
        cl_set_clcb_msg(clamav_message_callback);
        cl_init(CL_INIT_DEFAULT);
    }
};

// Global static initializer, run once.
static ClamAVInit kClamAVInit;

static int write_tmp_file(const char* name, const uint8_t* data, size_t size)
{
    FILE* f = fopen(name, "wb");
    if (NULL == f) {
        return -1;
    }
    if (size > 0) {
        fwrite(data, 1, size, f);
    }
    fclose(f);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Split the input into an OpenIOC database and a scan file. */
    const uint8_t* sep = (const uint8_t*)memmem(data, size, kSep, sizeof(kSep) - 1);
    if (NULL == sep) {
        return 0;
    }
    size_t ioc_size  = (size_t)(sep - data);
    size_t file_size = size - ioc_size - (sizeof(kSep) - 1);
    if (0 == ioc_size || 0 == file_size || ioc_size > 200000) {
        return 0;
    }

    __pid_t pid = getpid();
    char ioc_name[200], file_name[200];
    snprintf(ioc_name, sizeof(ioc_name), "tmp.openioc.%d.ioc", pid);
    snprintf(file_name, sizeof(file_name), "tmp.openioc.%d.fuzz", pid);

    if (0 != write_tmp_file(ioc_name, data, ioc_size)) {
        return 0;
    }
    if (0 != write_tmp_file(file_name, sep + (sizeof(kSep) - 1), file_size)) {
        unlink(ioc_name);
        return 0;
    }

    struct cl_engine* engine = cl_engine_new();
    if (NULL != engine) {
        unsigned int sigs = 0;
        unsigned int dboptions =
            CL_DB_PHISHING | CL_DB_PHISHING_URLS |
            CL_DB_BYTECODE | CL_DB_PUA | CL_DB_ENHANCED;

        if (CL_SUCCESS == cl_load(ioc_name, engine, &sigs, dboptions)) {
            if (CL_SUCCESS == cl_engine_compile(engine)) {
                struct cl_scan_options scanopts;
                memset(&scanopts, 0, sizeof(scanopts));
                scanopts.parse |= ~0u;
                scanopts.heuristic |= ~0u;
                scanopts.general |= CL_SCAN_GENERAL_HEURISTICS |
                                    CL_SCAN_GENERAL_COLLECT_METADATA |
                                    CL_SCAN_GENERAL_ALLMATCHES;

                const char* virus_name = nullptr;
                unsigned long scanned  = 0;
                cl_scanfile(file_name, &virus_name, &scanned, engine, &scanopts);
            }
        }
        cl_engine_free(engine);
    }

    unlink(ioc_name);
    unlink(file_name);
    return 0;
}
