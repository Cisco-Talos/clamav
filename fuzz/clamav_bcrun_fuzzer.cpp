/*
 * Fuzz target for ClamAV bytecode signatures: load -> prepare -> execute.
 *
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * Rationale (OSS-Fuzz coverage pipeline, 2026-11):
 * The existing OSS-Fuzz targets cover two halves of the bytecode pipeline but
 * never connect them: `clamav_dbload_fuzzer` loads signature databases but
 * never compiles the engine or scans with it, and `clamav_scanfile/_map_fuzzer`
 * scan with an empty engine (no `cl_load` at all). As a result the bytecode
 * signature pipeline -- `cli_loadcbc` (bytecode.c), the engine-compile prepare
 * pass (`cli_bytecode_prepare2`), and the bytecode VM during scan
 * (`run_builtin_or_loaded` / `cli_bytecode_run`) -- is unreachable by any
 * OSS-Fuzz target; the OSS-Fuzz Fuzz Introspector profile for clamav lists
 * `cli_bytecode_prepare2` and `run_builtin_or_loaded` among the highest-
 * complexity functions of interest with 0% coverage.
 *
 * Threat model: signature databases are remote-controlled data (compromised
 * mirror / TLS-stripped update channel). A bytecode signature is attacker-
 * authored logic executed inside libclamav's VM; memory-safety bugs in the
 * bytecode loader/verifier/interpreter are remotely triggerable. Loading is
 * done with CL_DB_BYTECODE_UNSIGNED (the documented "run untrusted bytecode"
 * API option) so mutated bytecode reaches the loader and VM; production setups
 * verify signatures, but the VM must not be exploitable by malformed bytecode
 * regardless (historical ClamAV CVEs include bytecode VM issues).
 *
 * Input shape: [bytecode signature bytes][separator][file to scan].
 * The separator is `\n;;CFDB;;\n`; everything before it is written to a
 * temporary `.cbc` database file and loaded into a fresh engine; the remainder
 * is written to a temporary file and scanned with all parse flags enabled so
 * bytecode hooks (LSIG-attached, PDF hooks, etc.) can fire during the scan.
 * Seeds pair the in-tree unit-test bytecode signatures
 * (`unit_tests/input/bytecode_sigs/*.cbc`) with matching scan inputs.
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
    /* Split the input into a bytecode database and a scan file. */
    const uint8_t* sep = (const uint8_t*)memmem(data, size, kSep, sizeof(kSep) - 1);
    if (NULL == sep) {
        return 0;
    }
    size_t bc_size   = (size_t)(sep - data);
    size_t file_size = size - bc_size - (sizeof(kSep) - 1);
    if (0 == bc_size || 0 == file_size || bc_size > 200000) {
        return 0;
    }

    __pid_t pid = getpid();
    char bc_name[200], file_name[200];
    snprintf(bc_name, sizeof(bc_name), "tmp.bcrun.%d.cbc", pid);
    snprintf(file_name, sizeof(file_name), "tmp.bcrun.%d.fuzz", pid);

    if (0 != write_tmp_file(bc_name, data, bc_size)) {
        return 0;
    }
    if (0 != write_tmp_file(file_name, sep + (sizeof(kSep) - 1), file_size)) {
        unlink(bc_name);
        return 0;
    }

    struct cl_engine* engine = cl_engine_new();
    if (NULL != engine) {
        unsigned int sigs = 0;
        unsigned int dboptions =
            CL_DB_PHISHING | CL_DB_PHISHING_URLS |
            CL_DB_BYTECODE | CL_DB_PUA | CL_DB_ENHANCED |
            CL_DB_BYTECODE_UNSIGNED; /* fuzz the loader+VM on untrusted bytecode */

        if (CL_SUCCESS == cl_load(bc_name, engine, &sigs, dboptions)) {
            /* Engine compile runs the bytecode prepare pass. */
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

    unlink(bc_name);
    unlink(file_name);
    return 0;
}
