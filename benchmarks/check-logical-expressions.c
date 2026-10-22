/* SPDX-License-Identifier: GPL-2.0-only
 * Validate compiled logical expressions against the interpreter using a loaded
 * database. Build against the same internal headers as the candidate library.
 * Also report the exact counter/offset allocation sizes, excluding other state.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matcher.h"
#include "others.h"

static void compare(const struct cli_matcher *root, uint32_t lsid, uint32_t *counts)
{
    const char *expr   = root->ac_lsigtable[lsid]->u.logic;
    unsigned old_count = 7, new_count = 7;
    uint64_t old_ids = (uint64_t)1 << 62, new_ids = old_ids;
    int old_result = cli_ac_chklsig(expr, expr + strlen(expr), counts, &old_count, &old_ids, 0);
    int new_result = cli_ac_eval_lsig(root, lsid, counts, &new_count, &new_ids);
    if (old_result != new_result || old_count != new_count || old_ids != new_ids) {
        fprintf(stderr, "Expression mismatch: target=%u signature=%u expression=%s\n", root->type, lsid, expr);
        exit(3);
    }
}

int main(int argc, char **argv)
{
    struct cl_engine *engine;
    unsigned signatures = 0, state = 0x62421abc;
    size_t old_slots = 0, new_slots = 0, plans = 0, compiled = 0, checks = 0;
    size_t pe_old = 0, pe_new = 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s DATABASE CERTS_DIRECTORY\n", argv[0]);
        return 2;
    }
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS || !(engine = cl_engine_new()))
        return 2;
    if (cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, argv[2]) != CL_SUCCESS ||
        cl_load(argv[1], engine, &signatures, CL_DB_STDOPT) != CL_SUCCESS ||
        cl_engine_compile(engine) != CL_SUCCESS)
        return 2;
    printf("signatures=%u lsig_struct_bytes=%zu\n", signatures, sizeof(struct cli_ac_lsig));
    for (unsigned target = 0; target < CLI_MTARGETS; target++) {
        struct cli_matcher *root = engine->root[target];
        if (!root || !root->ac_lsigs)
            continue;
        unsigned char *seen = calloc((size_t)root->ac_lsig_expr_count + 1, 1);
        if (!seen)
            return 2;
        size_t root_compiled = 0;
        for (uint32_t i = 0; i < root->ac_lsigs; i++) {
            const struct cli_ac_lsig *sig = root->ac_lsigtable[i];
            uint32_t counts[64]           = {0};
            if (sig->type != CLI_LSIG_NORMAL)
                continue;
            /* Check every mapping, and many counter vectors per shared plan. */
            compare(root, i, counts);
            checks++;
            if (!sig->expr_id)
                continue;
            root_compiled++;
            if (seen[sig->expr_id])
                continue;
            seen[sig->expr_id] = 1;
            for (unsigned vector = 0; vector < 1024; vector++) {
                for (unsigned k = 0; k < 64; k++) {
                    state     = state * 1664525u + 1013904223u;
                    counts[k] = vector == 0 ? 1 : vector == 1 ? UINT32_MAX
                                              : vector == 2   ? UINT32_MAX - k
                                                              : (state >> 24) % 8;
                }
                compare(root, i, counts);
                checks++;
            }
        }
        printf("target=%u lsigs=%u old_slots=%zu new_slots=%zu compiled=%zu shared_plans=%u\n",
               target, root->ac_lsigs, (size_t)root->ac_lsigs * 64,
               root->ac_lsig_slots, root_compiled, root->ac_lsig_expr_count);
        old_slots += (size_t)root->ac_lsigs * 64;
        new_slots += root->ac_lsig_slots;
        plans += root->ac_lsig_expr_count;
        compiled += root_compiled;
        if (target == TARGET_GENERIC || target == TARGET_PE) {
            pe_old += (size_t)root->ac_lsigs * 64;
            pe_new += root->ac_lsig_slots;
        }
        free(seen);
    }
    printf("total old_state_bytes=%zu new_state_bytes=%zu compiled=%zu shared_plans=%zu comparisons=%zu\n",
           old_slots * 3 * sizeof(uint32_t), new_slots * 3 * sizeof(uint32_t), compiled, plans, checks);
    printf("pe_and_generic old_state_bytes=%zu new_state_bytes=%zu\n",
           pe_old * 3 * sizeof(uint32_t), pe_new * 3 * sizeof(uint32_t));
    cl_engine_free(engine);
    return 0;
}
