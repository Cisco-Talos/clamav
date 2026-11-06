/*
 * Fuzz target for ClamAV database container (`.cld`/`.cvd`) loading.
 *
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * Rationale (OSS-Fuzz coverage pipeline, 2026-11):
 * No OSS-Fuzz target exercises the signed-database container path at all:
 * `clamav_dbload_<TYPE>_fuzzer` only loads raw single-type files, while the
 * container path in cvd.c -- `cl_cvdparse` (512-byte header field parsing),
 * `cvd_open`, and `cli_tgzload` (the custom tar reader + gzip stream over the
 * payload, feeding every contained file back through `cli_load`) -- is dark
 * project-wide. `cli_cvdload` is how daily.cvd/.cld updates are loaded: a
 * compromised mirror or TLS-stripped update channel hands the scanner an
 * attacker-built container, whose payload is a tar.gz of arbitrary
 * signature files (and, historically, bytecode signatures).
 *
 * Threat model: attacker-controlled database container. For `.cld` files
 * `cli_cvdload` skips `cvd_verify` entirely (CVD_TYPE_CLD does not call it),
 * so a crafted container is unpacked and its contents loaded without any
 * signature check -- the same trust level as the fuzzed `.cld` update path.
 * `.cvd` inputs additionally exercise `cvd_verify` and its error paths.
 * Expected bug classes: memory safety in the header/tar/gzip parse loops,
 * multi-file engine accumulation, and per-file database parsing under the
 * OFFICIAL/SIGNED option set.
 *
 * Input shape: single blob, written to a temporary `.cld` file and loaded
 * (`.cld` = container without entry-point signature verification; the
 * header, tar reader, gzip stream, and all contained signature parsing are
 * fully exercised). On success the engine is compiled, building matchers
 * from every signature the container contained. Seeds: the in-tree
 * unit-test `bytecode.cvd` (a real container holding a compiled bytecode
 * signature) plus generated containers built by `gen_cvdload_seeds.py`.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "clamav.h"

/* Apple does not define __pid_t */
#ifdef __APPLE__
typedef pid_t __pid_t;
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (0 == size || size > 2000000) {
        return 0;
    }

    __pid_t pid = getpid();
    char db_name[200];
    snprintf(db_name, sizeof(db_name), "tmp.cvdload.%d.cld", pid);

    FILE* f = fopen(db_name, "wb");
    if (NULL == f) {
        return 0;
    }
    fwrite(data, 1, size, f);
    fclose(f);

    struct cl_engine* engine = cl_engine_new();
    if (NULL != engine) {
        unsigned int sigs = 0;
        unsigned int dboptions =
            CL_DB_PHISHING | CL_DB_PHISHING_URLS |
            CL_DB_BYTECODE | CL_DB_PUA | CL_DB_ENHANCED;

        if (CL_SUCCESS == cl_load(db_name, engine, &sigs, dboptions)) {
            /* Compile builds matchers/bytecode prepare from the container. */
            cl_engine_compile(engine);
        }
        cl_engine_free(engine);
    }

    unlink(db_name);
    return 0;
}
