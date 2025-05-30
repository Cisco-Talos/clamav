/*
 * Fuzz target for cl_load()
 *
 * Copyright (C) 2018-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * Authors: Micah Snyder
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "clamav.h"

/* Apple does not define __pid_t */
#ifdef __APPLE__
typedef pid_t __pid_t;
#endif

void clamav_message_callback(enum cl_msg severity, const char* fullmsg,
                             const char* msg, void* context)
{
}

class ClamAVState
{
  public:
    ClamAVState()
    {
        // Silence all the log messages, none of them are meaningful.
        cl_set_clcb_msg(clamav_message_callback);

        cl_init(CL_INIT_DEFAULT);
    }

    ~ClamAVState()
    {
    }
};

// Global with static initializer to setup an engine so we don't need to do
// that on each execution.
ClamAVState kClamAVState;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    cl_error_t ret;
    char tmp_file_name[200]  = {0};
    unsigned int sigs        = 0;
    FILE* fuzzdb             = NULL;
    struct cl_engine* engine = NULL;
    unsigned int dboptions;

    __pid_t pid = getpid();

    dboptions =
        CL_DB_PHISHING | CL_DB_PHISHING_URLS |
        CL_DB_BYTECODE | CL_DB_PUA | CL_DB_ENHANCED;

#if defined(CLAMAV_FUZZ_CDB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.cdb", pid);
#elif defined(CLAMAV_FUZZ_CFG)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.cfg", pid);
#elif defined(CLAMAV_FUZZ_CRB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.crb", pid);
#elif defined(CLAMAV_FUZZ_FP)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.fp", pid);
#elif defined(CLAMAV_FUZZ_FTM)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.ftm", pid);
#elif defined(CLAMAV_FUZZ_HDB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.hdb", pid);
#elif defined(CLAMAV_FUZZ_HSB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.hsb", pid);
#elif defined(CLAMAV_FUZZ_IDB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.idb", pid);
#elif defined(CLAMAV_FUZZ_IGN)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.ign", pid);
#elif defined(CLAMAV_FUZZ_IGN2)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.ign2", pid);
#elif defined(CLAMAV_FUZZ_LDB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.ldb", pid);
#elif defined(CLAMAV_FUZZ_MDB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.mdb", pid);
#elif defined(CLAMAV_FUZZ_MSB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.msb", pid);
#elif defined(CLAMAV_FUZZ_NDB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.ndb", pid);
#elif defined(CLAMAV_FUZZ_PDB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.pdb", pid);
#elif defined(CLAMAV_FUZZ_WDB)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.wdb", pid);
#elif defined(CLAMAV_FUZZ_YARA)
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d.yara", pid);
#else
    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.dbload.%d", pid);
#endif

    fuzzdb = fopen(tmp_file_name, "w");
    fwrite(data, size, 1, fuzzdb);
    fclose(fuzzdb);

    /* need new engine each time. can't add sigs to compiled engine */
    engine = cl_engine_new();

    /* load the fuzzer-generated sig db */
    if (CL_SUCCESS != (ret = cl_load(tmp_file_name,
                                     engine,
                                     &sigs,
                                     dboptions))) {
        printf("cl_load: %s\n", cl_strerror(ret));
        goto done;
    }

    /* build engine */
    if (CL_SUCCESS != (ret = cl_engine_compile(engine))) {
        printf("cl_engine_compile: %s\n", cl_strerror(ret));
        goto done;
    }

done:

    /* Clean up for the next round */
    if (NULL != engine) {
        cl_engine_free(engine);
    }

    unlink(tmp_file_name);

    return 0;
}
