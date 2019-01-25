/*
 * Fuzz target for cl_load()
 *
 * Copyright (C) 2018-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
        engine = cl_engine_new();
        cl_engine_compile(engine);

        tmp_db_name = NULL;
    }

    ~ClamAVState()
    {
        cl_engine_free(engine);

        if (NULL != tmp_db_name) {
            unlink(tmp_db_name);
        }
    }

    struct cl_engine* engine;
    const char* tmp_db_name;
};

// Global with static initializer to setup an engine so we don't need to do
// that on each execution.
ClamAVState kClamAVState;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    unsigned int sigs = 0;
    FILE* fuzzdb      = NULL;

    unsigned int dboptions =
        CL_DB_PHISHING | CL_DB_PHISHING_URLS |
        CL_DB_BYTECODE | CL_DB_BYTECODE_UNSIGNED |
        CL_DB_PUA | CL_DB_ENHANCED;

#if defined(CLAMAV_FUZZ_CDB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.cdb";
#elif defined(CLAMAV_FUZZ_CFG)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.cfg";
#elif defined(CLAMAV_FUZZ_CRB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.crb";
#elif defined(CLAMAV_FUZZ_FP)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.fp";
#elif defined(CLAMAV_FUZZ_FTM)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.ftm";
#elif defined(CLAMAV_FUZZ_HDB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.hdb";
#elif defined(CLAMAV_FUZZ_HSB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.hsb";
#elif defined(CLAMAV_FUZZ_IDB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.idb";
#elif defined(CLAMAV_FUZZ_IGN)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.ign";
#elif defined(CLAMAV_FUZZ_IGN2)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.ign2";
#elif defined(CLAMAV_FUZZ_LDB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.ldb";
#elif defined(CLAMAV_FUZZ_MDB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.mdb";
#elif defined(CLAMAV_FUZZ_MSB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.msb";
#elif defined(CLAMAV_FUZZ_NDB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.ndb";
#elif defined(CLAMAV_FUZZ_PDB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.pdb";
#elif defined(CLAMAV_FUZZ_WDB)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.wdb";
#elif defined(CLAMAV_FUZZ_YARA)
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz.yara";
#else
    kClamAVState.tmp_db_name = "dbload_tmp_fuzz";
#endif

    fuzzdb = fopen(kClamAVState.tmp_db_name, "w");
    fwrite(data, size, 1, fuzzdb);
    fclose(fuzzdb);

    cl_load(
        kClamAVState.tmp_db_name,
        kClamAVState.engine,
        &sigs,
        dboptions);

    return 0;
}
