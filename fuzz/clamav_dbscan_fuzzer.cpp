/*
 * Fuzz target for ClamAV signature-database loading + scanning.
 *
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * Rationale (OSS-Fuzz coverage pipeline, 2026-11):
 * The existing OSS-Fuzz targets split the pipeline in half and never connect
 * it: `clamav_scanfile/_map_fuzzer` scan attacker files with an EMPTY engine
 * (no `cl_load` at all), and `clamav_dbload_fuzzer` loads attacker signature
 * databases but never compiles the engine or scans with it. Consequently the
 * signature-dependent half of libclamav -- per-type database parsers beyond
 * the load step (`cli_loadldb`/`cli_loadndb`/`cli_loadyara`/`cli_loadwdb`/
 * `cli_loadftm`/hash-database loading in readdb.c), the matcher construction
 * at engine compile time (Aho-Corasick/boyer-moore/regex builds in
 * matcher*.c), and matching during scan with signatures loaded -- is dark
 * project-wide. Signature matching is ClamAV's untrusted-input evaluator:
 * signature databases are remote-controlled data (compromised mirror /
 * update channel), so the parser -> matcher -> scan pipeline is exactly the
 * attacker's path.
 *
 * Input shape: [signature database bytes][separator][file to scan].
 * The separator is `\n;;CFDB;;\n`; everything before it is written to a
 * temporary database file with the per-variant extension and loaded into a
 * fresh engine (`cl_load`), the engine is compiled (`cl_engine_compile`,
 * building the matchers), and the remainder is scanned (`cl_scanfile`) with
 * all parse flags enabled so database entries are actually evaluated against
 * attacker-controlled file content. Per-type compile definitions mirror the
 * existing `clamav_dbload_<TYPE>_fuzzer` pattern:
 *   LDB: logical signatures (subsignatures, logical expressions)
 *   NDB: hex byte signatures (wildcards, alternates)
 *   HDB: file/section hash signatures (md5/sha1/sha256 computed during scan)
 *   YARA: YARA rule loading and matching (HAVE_YARA builds)
 *   WDB: phishing URL whitelist regexes (dual regex engine compile)
 *   FTM: file-type magic signatures (type detection overrides)
 * Seeds pair real signature files from the clamav-fuzz-corpus database
 * directories (plus ClamAV's in-tree unit-test signatures) with scan inputs
 * crafted to match them (e.g. a file containing the unit-test signature
 * string), so detection paths are exercised from the start.
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

#if defined(CLAMAV_FUZZ_LDB)
#define CLAMAV_FUZZ_DB_EXT ".ldb"
#elif defined(CLAMAV_FUZZ_NDB)
#define CLAMAV_FUZZ_DB_EXT ".ndb"
#elif defined(CLAMAV_FUZZ_HDB)
#define CLAMAV_FUZZ_DB_EXT ".hdb"
#elif defined(CLAMAV_FUZZ_YARA)
#define CLAMAV_FUZZ_DB_EXT ".yara"
#elif defined(CLAMAV_FUZZ_WDB)
#define CLAMAV_FUZZ_DB_EXT ".wdb"
#elif defined(CLAMAV_FUZZ_FTM)
#define CLAMAV_FUZZ_DB_EXT ".ftm"
#else
#define CLAMAV_FUZZ_DB_EXT ".db"
#endif

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
    /* Split the input into a signature database and a scan file. */
    const uint8_t* sep = (const uint8_t*)memmem(data, size, kSep, sizeof(kSep) - 1);
    if (NULL == sep) {
        return 0;
    }
    size_t db_size   = (size_t)(sep - data);
    size_t file_size = size - db_size - (sizeof(kSep) - 1);
    if (0 == db_size || 0 == file_size || db_size > 200000) {
        return 0;
    }

    __pid_t pid = getpid();
    char db_name[200], file_name[200];
    snprintf(db_name, sizeof(db_name), "tmp.dbscan.%d" CLAMAV_FUZZ_DB_EXT, pid);
    snprintf(file_name, sizeof(file_name), "tmp.dbscan.%d.fuzz", pid);

    if (0 != write_tmp_file(db_name, data, db_size)) {
        return 0;
    }
    if (0 != write_tmp_file(file_name, sep + (sizeof(kSep) - 1), file_size)) {
        unlink(db_name);
        return 0;
    }

    struct cl_engine* engine = cl_engine_new();
    if (NULL != engine) {
        unsigned int sigs = 0;
        unsigned int dboptions =
            CL_DB_PHISHING | CL_DB_PHISHING_URLS |
            CL_DB_BYTECODE | CL_DB_PUA | CL_DB_ENHANCED;

        if (CL_SUCCESS == cl_load(db_name, engine, &sigs, dboptions)) {
            /* Engine compile builds the matchers from the loaded database. */
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

    unlink(db_name);
    unlink(file_name);
    return 0;
}
