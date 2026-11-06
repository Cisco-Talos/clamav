/* SPDX-License-Identifier: GPL-2.0-only
 * Isolate the allocation pattern in cli_pcre_scanbuf's global-match loop.
 * This is a synthetic PCRE2 benchmark, not a ClamAV throughput benchmark.
 * Build: cc -O2 -std=c99 -Wall -Wextra -Werror pcre-match-data.c -lpcre2-8 -o pcre-match-data
 */
#define _POSIX_C_SOURCE 200809L
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TOKENS 1024
#define ROUNDS 500
#define REPETITIONS 5

struct measurement {
    uint64_t matches;
    uint64_t checksum;
    uint64_t allocations;
    double seconds;
};

static void fail(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

static double now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        fail("clock_gettime failed");
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static struct measurement run(pcre2_code *code, const unsigned char *subject,
                              size_t length, int reuse)
{
    struct measurement result = {0, 0, 0, 0};
    double start = now();
    unsigned int round;
    for (round = 0; round < ROUNDS; round++) {
        /* Scope scratch storage to one pattern in one file, not the engine. */
        pcre2_match_data *data = NULL;
        PCRE2_SIZE offset = 0;
        do {
            PCRE2_SIZE *ovector;
            int rc, group;
            if (!reuse || !data) {
                pcre2_match_data_free(data);
                data = pcre2_match_data_create_from_pattern(code, NULL);
                if (!data)
                    fail("match data allocation failed");
                result.allocations++;
            }
            rc = pcre2_match(code, subject, length, offset, 0, data, NULL);
            if (rc == PCRE2_ERROR_NOMATCH)
                break;
            if (rc <= 0)
                fail("unexpected match error or insufficient capture storage");
            ovector = pcre2_get_ovector_pointer(data);
            if (ovector[1] <= offset)
                fail("benchmark requires forward progress");
            result.matches++;
            for (group = 0; group < rc; group++) {
                result.checksum = result.checksum * UINT64_C(33) + ovector[2 * group];
                result.checksum = result.checksum * UINT64_C(33) + ovector[2 * group + 1];
            }
            offset = ovector[1];
        } while (offset < length);
        pcre2_match_data_free(data);
    }
    result.seconds = now() - start;
    return result;
}

int main(void)
{
    const char token[] = "item=1234;";
    const char *patterns[] = {"item=[0-9]{4};", "(item)=([0-9]{4});", "absent=[0-9]+;"};
    const char *names[] = {"repeated", "captures", "no_match"};
    unsigned char subject[TOKENS * (sizeof(token) - 1)];
    char version[64];
    size_t i, p;
    unsigned int repetition;

    if (pcre2_config(PCRE2_CONFIG_VERSION, version) < 0)
        fail("cannot get PCRE2 version");
    fprintf(stderr, "PCRE2 %s; %d tokens/file; %d files/sample; JIT disabled\n",
            version, TOKENS, ROUNDS);
    for (i = 0; i < TOKENS; i++)
        memcpy(subject + i * (sizeof(token) - 1), token, sizeof(token) - 1);
    puts("case,repetition,mode,seconds,matches,allocations,checksum");
    for (p = 0; p < sizeof(patterns) / sizeof(patterns[0]); p++) {
        int error;
        PCRE2_SIZE error_offset;
        pcre2_code *code = pcre2_compile((PCRE2_SPTR)patterns[p], PCRE2_ZERO_TERMINATED,
                                        0, &error, &error_offset, NULL);
        if (!code)
            fail("pattern compilation failed");
        for (repetition = 0; repetition < REPETITIONS; repetition++) {
            struct measurement results[2];
            unsigned int order, mode;
            /* Alternate order to reduce systematic warmup/order bias. */
            for (order = 0; order < 2; order++) {
                mode = (order + repetition) % 2;
                results[mode] = run(code, subject, sizeof(subject), mode);
                printf("%s,%u,%s,%.9f,%llu,%llu,%llu\n", names[p], repetition,
                       mode ? "reuse_per_file" : "allocate_per_match", results[mode].seconds,
                       (unsigned long long)results[mode].matches,
                       (unsigned long long)results[mode].allocations,
                       (unsigned long long)results[mode].checksum);
            }
            if (results[0].matches != results[1].matches ||
                results[0].checksum != results[1].checksum ||
                results[0].matches != (p == 2 ? 0 : (uint64_t)TOKENS * ROUNDS))
                fail("results differ or unexpected match count");
        }
        pcre2_code_free(code);
    }
    return EXIT_SUCCESS;
}
