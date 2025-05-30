/*
 * Fuzz target for cl_scanfile()
 *
 * Copyright (C) 2018-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * Authors: Micah Snyder, Alex Gaynor
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
#include <string.h>

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
        engine = cl_engine_new();
        cl_engine_compile(engine);

        memset(&scanopts, 0, sizeof(struct cl_scan_options));

#if defined(CLAMAV_FUZZ_ARCHIVE)
        scanopts.parse |= CL_SCAN_PARSE_ARCHIVE;
#elif defined(CLAMAV_FUZZ_MAIL)
        scanopts.parse |= CL_SCAN_PARSE_MAIL;
#elif defined(CLAMAV_FUZZ_OLE2)
        scanopts.parse |= CL_SCAN_PARSE_OLE2;
#elif defined(CLAMAV_FUZZ_PDF)
        scanopts.parse |= CL_SCAN_PARSE_PDF;
#elif defined(CLAMAV_FUZZ_HTML)
        scanopts.parse |= CL_SCAN_PARSE_HTML;
#elif defined(CLAMAV_FUZZ_PE)
        scanopts.parse |= CL_SCAN_PARSE_PE;
#elif defined(CLAMAV_FUZZ_ELF)
        scanopts.parse |= CL_SCAN_PARSE_ELF;
#elif defined(CLAMAV_FUZZ_SWF)
        scanopts.parse |= CL_SCAN_PARSE_SWF;
#elif defined(CLAMAV_FUZZ_XMLDOCS)
        scanopts.parse |= CL_SCAN_PARSE_XMLDOCS;
#elif defined(CLAMAV_FUZZ_HWP3)
        scanopts.parse |= CL_SCAN_PARSE_HWP3;
#else
        scanopts.parse |= ~(0);
#endif
        scanopts.general |= CL_SCAN_GENERAL_HEURISTICS;
        scanopts.general |= CL_SCAN_GENERAL_COLLECT_METADATA; /* Enable the gen-json feature */
        scanopts.heuristic |= ~(0);                           /* Enable all heuristic code */
        scanopts.general |= CL_SCAN_GENERAL_ALLMATCHES;       /* Enable all-match, so heuristic alerts don't end the scan early */
    }

    ~ClamAVState()
    {
        cl_engine_free(engine);
    }

    struct cl_engine* engine;
    struct cl_scan_options scanopts;
};

// Global with static initializer to setup an engine so we don't need to do
// that on each execution.
ClamAVState kClamAVState;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FILE* fuzzfile          = NULL;
    char tmp_file_name[200] = {0};

    __pid_t pid = getpid();

    snprintf(tmp_file_name, sizeof(tmp_file_name), "tmp.scanfile.%d", pid);

    fuzzfile = fopen(tmp_file_name, "w");
    fwrite(data, size, 1, fuzzfile);
    fclose(fuzzfile);

    const char* virus_name = nullptr;
    unsigned long scanned  = 0;

    cl_scanfile(
        tmp_file_name,
        &virus_name,
        &scanned,
        kClamAVState.engine,
        &kClamAVState.scanopts);

    unlink(tmp_file_name);

    return 0;
}
