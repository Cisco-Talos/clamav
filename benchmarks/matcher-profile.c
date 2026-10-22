/* SPDX-License-Identifier: GPL-2.0-only
 * LD_PRELOAD timing probe for the three exported matcher entry points.
 * Compile with the same libclamav headers/configuration as the profiled build.
 * CPU time includes callees. Counters are atomic for concurrent scan workers.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher-pcre.h"

struct counter {
    _Atomic unsigned long long calls, bytes, ns;
};
static struct counter counters[3][32];
static __typeof__(cli_bm_scanbuff) *real_bm;
static __typeof__(cli_ac_scanbuff) *real_ac;
static __typeof__(cli_pcre_scanbuf) *real_pcre;
static __typeof__(cl_engine_compile) *real_compile;
static _Atomic int ready;
/* Linux profil(): one 16-bit counter per 16 bytes of the first 16 MiB of
 * libclamav. Collect only after engine compilation; startup is excluded. */
static unsigned short samples[1024 * 1024];

static unsigned long long now(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t)) abort();
    return (unsigned long long)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

static void record(unsigned matcher, const struct cli_matcher *root,
                   uint32_t bytes, unsigned long long start)
{
    unsigned long long elapsed = now() - start;
    unsigned target = root && root->type < 32 ? root->type : 31;
    struct counter *c = &counters[matcher][target];
    atomic_fetch_add_explicit(&c->calls, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&c->bytes, bytes, memory_order_relaxed);
    atomic_fetch_add_explicit(&c->ns, elapsed, memory_order_relaxed);
}

__attribute__((constructor)) static void init(void)
{
    real_bm = dlsym(RTLD_NEXT, "cli_bm_scanbuff");
    real_ac = dlsym(RTLD_NEXT, "cli_ac_scanbuff");
    real_pcre = dlsym(RTLD_NEXT, "cli_pcre_scanbuf");
    real_compile = dlsym(RTLD_NEXT, "cl_engine_compile");
    if (!real_bm || !real_ac || !real_pcre || !real_compile) abort();
}

cl_error_t cl_engine_compile(struct cl_engine *engine)
{
    cl_error_t result = real_compile(engine);
    Dl_info info;
    if (result == CL_SUCCESS && dladdr(real_ac, &info)) {
        if (profil(samples, sizeof(samples), (size_t)info.dli_fbase, 8192))
            perror("profil");
        atomic_store(&ready, 1);
    }
    return result;
}

__attribute__((destructor)) static void report(void)
{
    const char *names[] = {"BM", "AC", "PCRE"};
    profil(samples, 0, 0, 0);
    for (unsigned m = 0; m < 3; ++m) {
        for (unsigned t = 0; t < 32; ++t) {
            struct counter *c = &counters[m][t];
            if (c->calls) fprintf(stderr, "matcher_profile\t%s\t%u\t%llu\t%llu\t%.9f\n",
                names[m], t, (unsigned long long)c->calls,
                (unsigned long long)c->bytes, (double)c->ns / 1e9);
        }
    }
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i)
        if (samples[i]) fprintf(stderr, "matcher_samples\t%zx\t%u\n", i * 16, samples[i]);
}

cl_error_t cli_bm_scanbuff(const unsigned char *buffer, uint32_t length,
    const char **virname, const struct cli_bm_patt **patt, const struct cli_matcher *root,
    uint32_t offset, const struct cli_target_info *info, struct cli_bm_off *offdata, cli_ctx *ctx)
{
    if (!atomic_load(&ready)) return real_bm(buffer, length, virname, patt, root, offset, info, offdata, ctx);
    unsigned long long start = now();
    cl_error_t result = real_bm(buffer, length, virname, patt, root, offset, info, offdata, ctx);
    record(0, root, length, start);
    return result;
}

cl_error_t cli_ac_scanbuff(const unsigned char *buffer, uint32_t length,
    const char **virname, void **customdata, struct cli_ac_result **res,
    const struct cli_matcher *root, struct cli_ac_data *mdata, uint32_t offset,
    cli_file_t ftype, struct cli_matched_type **ftoffset, unsigned int mode, cli_ctx *ctx)
{
    if (!atomic_load(&ready)) return real_ac(buffer, length, virname, customdata, res, root, mdata,
                                           offset, ftype, ftoffset, mode, ctx);
    unsigned long long start = now();
    cl_error_t result = real_ac(buffer, length, virname, customdata, res, root, mdata,
                              offset, ftype, ftoffset, mode, ctx);
    record(1, root, length, start);
    return result;
}

cl_error_t cli_pcre_scanbuf(const unsigned char *buffer, uint32_t length,
    const char **virname, struct cli_ac_result **res, const struct cli_matcher *root,
    struct cli_ac_data *mdata, const struct cli_pcre_off *data, cli_ctx *ctx)
{
    if (!atomic_load(&ready)) return real_pcre(buffer, length, virname, res, root, mdata, data, ctx);
    unsigned long long start = now();
    cl_error_t result = real_pcre(buffer, length, virname, res, root, mdata, data, ctx);
    record(2, root, length, start);
    return result;
}
