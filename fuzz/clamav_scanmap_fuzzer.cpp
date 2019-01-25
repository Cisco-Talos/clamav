/*
 * Fuzz target for cl_scanmap_callback()
 *
 * Copyright (C) 2018-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <string.h>

#include "clamav.h"


void clamav_message_callback(enum cl_msg severity, const char *fullmsg,
                             const char *msg, void *context) {
}

class ClamAVState {
public:
    ClamAVState() {
        // Silence all the log messages, none of them are meaningful.
        cl_set_clcb_msg(clamav_message_callback);

        cl_init(CL_INIT_DEFAULT);
        engine = cl_engine_new();
        cl_engine_compile(engine);
    }

    ~ClamAVState() {
        cl_engine_free(engine);
    }

    struct cl_engine *engine;
};

// Global with static initializer to setup an engine so we don't need to do
// that on each execution.
ClamAVState kClamAVState;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    
    struct cl_scan_options scanopts = {0};
    
    cl_fmap_t *clamav_data = cl_fmap_open_memory(data, size);

    memset(&scanopts, 0, sizeof(struct cl_scan_options));

    scanopts.parse |= 
#if defined(CLAMAV_FUZZ_ARCHIVE)
        CL_SCAN_PARSE_ARCHIVE;
#elif defined(CLAMAV_FUZZ_MAIL)
        CL_SCAN_PARSE_MAIL;
#elif defined(CLAMAV_FUZZ_OLE2)
        CL_SCAN_PARSE_OLE2;
#elif defined(CLAMAV_FUZZ_PDF)
        CL_SCAN_PARSE_PDF;
#elif defined(CLAMAV_FUZZ_HTML)
        CL_SCAN_PARSE_HTML;
#elif defined(CLAMAV_FUZZ_PE)
        CL_SCAN_PARSE_PE;
#elif defined(CLAMAV_FUZZ_ELF)
        CL_SCAN_PARSE_ELF;
#elif defined(CLAMAV_FUZZ_SWF)
        CL_SCAN_PARSE_SWF;
#elif defined(CLAMAV_FUZZ_XMLDOCS)
        CL_SCAN_PARSE_XMLDOCS;
#elif defined(CLAMAV_FUZZ_HWP3)
        CL_SCAN_PARSE_HWP3;
#else
        ~(0);
#endif

    scanopts.general |= CL_SCAN_GENERAL_HEURISTICS;

    const char *virus_name = nullptr;
    unsigned long scanned = 0;
    cl_scanmap_callback(
        clamav_data,
        NULL,
        &virus_name,
        &scanned,
        kClamAVState.engine,
        &scanopts,
        nullptr
    );

    cl_fmap_close(clamav_data);

    return 0;
}
