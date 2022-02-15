/*
 * YARA parser for ClamAV: back-end functions
 *
 * Copyright (C) 2014-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * Authors: Steven Morgan
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stddef.h>
#include <string.h>

#ifdef REAL_YARA
#include <yara/ahocorasick.h>
#include <yara/arena.h>
#include <yara/re.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/object.h>
#include <yara/utils.h>
#include <yara/modules.h>
#include <yara/parser.h>
#include <yara/mem.h>
#else
#include <stdint.h>
#include <stdio.h>
#include "yara_clam.h"
#include "yara_grammar.h"
#include "yara_lexer.h"
#include "yara_exec.h"
#include "others.h"
#endif

#define todigit(x) ((x) >= 'A' && (x) <= 'F')      \
                       ? ((uint8_t)(x - 'A' + 10)) \
                       : ((uint8_t)(x - '0'))

int yr_parser_emit(
    yyscan_t yyscanner,
    int8_t instruction,
    int8_t** instruction_address)
{
    return yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &instruction,
        sizeof(int8_t),
        (void**)instruction_address);
}

int yr_parser_emit_with_arg(
    yyscan_t yyscanner,
    int8_t instruction,
    int64_t argument,
    int8_t** instruction_address)
{
    int result = yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &instruction,
        sizeof(int8_t),
        (void**)instruction_address);

    if (result == ERROR_SUCCESS)
        result = yr_arena_write_data(
            yyget_extra(yyscanner)->code_arena,
            &argument,
            sizeof(int64_t),
            NULL);

    return result;
}

int yr_parser_emit_with_arg_reloc(
    yyscan_t yyscanner,
    int8_t instruction,
    int64_t argument,
    int8_t** instruction_address)
{
    void* ptr;

    int result = yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &instruction,
        sizeof(int8_t),
        (void**)instruction_address);

    if (result == ERROR_SUCCESS)
        result = yr_arena_write_data(
            yyget_extra(yyscanner)->code_arena,
            &argument,
            sizeof(int64_t),
            &ptr);

    if (result == ERROR_SUCCESS)
        result = yr_arena_make_relocatable(
            yyget_extra(yyscanner)->code_arena,
            ptr,
            0,
            EOL);

    return result;
}

int yr_parser_emit_pushes_for_strings(
    yyscan_t yyscanner,
    const char* identifier)
{
    YR_COMPILER* compiler = yyget_extra(yyscanner);
    YR_STRING* string     = compiler->current_rule_strings;

    const char* string_identifier;
    const char* target_identifier;

    int matching = 0;

    while (!STRING_IS_NULL(string)) {
        // Don't generate pushes for strings chained to another one, we are
        // only interested in non-chained strings or the head of the chain.

        if (string->chained_to == NULL) {
            string_identifier = string->identifier;
            target_identifier = identifier;

            while (*target_identifier != '\0' &&
                   *string_identifier != '\0' &&
                   *target_identifier == *string_identifier) {
                target_identifier++;
                string_identifier++;
            }

            if ((*target_identifier == '\0' && *string_identifier == '\0') ||
                *target_identifier == '*') {
                yr_parser_emit_with_arg_reloc(
                    yyscanner,
                    OP_PUSH,
                    PTR_TO_UINT64(string),
                    NULL);

                string->g_flags |= STRING_GFLAGS_REFERENCED;
                matching++;
            }
        }

        string = yr_arena_next_address(
            compiler->strings_arena,
            string,
            sizeof(YR_STRING));
    }

    if (matching == 0) {
        yr_compiler_set_error_extra_info(compiler, identifier);
        compiler->last_result = ERROR_UNDEFINED_STRING;
    }

    return compiler->last_result;
}

int yr_parser_check_types(
    YR_COMPILER* compiler,
    YR_OBJECT_FUNCTION* function,
    const char* actual_args_fmt)
{
    int i;

    char message[MAX_COMPILER_ERROR_EXTRA_INFO];

    const char* expected = function->arguments_fmt;
    const char* actual   = actual_args_fmt;

    i = 0;

    while (*expected != '\0' || *actual != '\0') {
        i++;

        if (*expected != *actual) {
            if (*expected == '\0' || *actual == '\0') {
                snprintf(
                    message,
                    sizeof(message),
                    "wrong number of arguments for \"%s\"",
                    function->identifier);

                compiler->last_result = ERROR_WRONG_NUMBER_OF_ARGUMENTS;
            } else {
                snprintf(
                    message,
                    sizeof(message),
                    "wrong type for argument %i of \"%s\"",
                    i,
                    function->identifier);

                compiler->last_result = ERROR_WRONG_TYPE;
            }

            yr_compiler_set_error_extra_info(compiler, message);
            break;
        }

        expected++;
        actual++;
    }

    return compiler->last_result;
}

YR_STRING* yr_parser_lookup_string(
    yyscan_t yyscanner,
    const char* identifier)
{
    YR_STRING* string;
    YR_COMPILER* compiler = yyget_extra(yyscanner);

    string = compiler->current_rule_strings;

    while (!STRING_IS_NULL(string)) {
        // If some string $a gets fragmented into multiple chained
        // strings, all those fragments have the same $a identifier
        // but we are interested in the heading fragment, which is
        // that with chained_to == NULL

        if (strcmp(string->identifier, identifier) == 0 &&
            string->chained_to == NULL) {
            return string;
        }

        string = yr_arena_next_address(
            compiler->strings_arena,
            string,
            sizeof(YR_STRING));
    }

    yr_compiler_set_error_extra_info(compiler, identifier);
    compiler->last_result = ERROR_UNDEFINED_STRING;

    return NULL;
}

int yr_parser_lookup_loop_variable(
    yyscan_t yyscanner,
    const char* identifier)
{
    YR_COMPILER* compiler = yyget_extra(yyscanner);
    int i;

    for (i = 0; i < compiler->loop_depth; i++) {
        if (compiler->loop_identifier[i] != NULL &&
            strcmp(identifier, compiler->loop_identifier[i]) == 0)
            return i;
    }

    return -1;
}

int _yr_parser_write_string(
    const char* identifier,
    int flags,
    YR_COMPILER* compiler,
    SIZED_STRING* str,
    RE* re,
    YR_STRING** string,
    int* min_atom_length)
{
    SIZED_STRING* literal_string;
#ifdef REAL_YARA
    YR_AC_MATCH* new_match;

    YR_ATOM_LIST_ITEM* atom;
    YR_ATOM_LIST_ITEM* atom_list = NULL;
#endif

    int result;
#if REAL_YARA
    int max_string_len;
    int free_literal = FALSE;
#endif

#if !REAL_YARA
    UNUSEDPARAM(re);
    UNUSEDPARAM(min_atom_length);
#endif

    *string = NULL;

    result = yr_arena_allocate_struct(
        compiler->strings_arena,
        sizeof(YR_STRING),
        (void**)string,
        offsetof(YR_STRING, identifier),
        offsetof(YR_STRING, string),
        offsetof(YR_STRING, chained_to),
        EOL);

    if (result != ERROR_SUCCESS)
        return result;

    result = yr_arena_write_string(
        compiler->sz_arena,
        identifier,
        &(*string)->identifier);

    if (result != ERROR_SUCCESS)
        return result;

#if REAL_YARA
    if (flags & STRING_GFLAGS_HEXADECIMAL ||
        flags & STRING_GFLAGS_REGEXP) {
        literal_string = yr_re_extract_literal(re);

        if (literal_string != NULL) {
            flags |= STRING_GFLAGS_LITERAL;
            free_literal = TRUE;
        }
    } else {
        literal_string = str;
        flags |= STRING_GFLAGS_LITERAL;
    }
#else
    literal_string    = str;
#endif

    (*string)->g_flags    = flags;
    (*string)->chained_to = NULL;

#ifdef PROFILING_ENABLED
    (*string)->clock_ticks = 0;
#endif

#if REAL_YARA
    memset((*string)->matches, 0,
           sizeof((*string)->matches));

    memset((*string)->unconfirmed_matches, 0,
           sizeof((*string)->unconfirmed_matches));

    if (flags & STRING_GFLAGS_LITERAL) {
        (*string)->length = literal_string->length;

        result = yr_arena_write_data(
            compiler->sz_arena,
            literal_string->c_string,
            literal_string->length,
            (void*)&(*string)->string);

        if (result == ERROR_SUCCESS) {
            result = yr_atoms_extract_from_string(
                (uint8_t*)literal_string->c_string,
                literal_string->length,
                flags,
                &atom_list);
        }
    } else {
        result = yr_re_emit_code(re, compiler->re_code_arena);

        if (result == ERROR_SUCCESS)
            result = yr_atoms_extract_from_re(re, flags, &atom_list);
    }

    if (result == ERROR_SUCCESS) {
        // Add the string to Aho-Corasick automaton.

        if (atom_list != NULL) {
            result = yr_ac_add_string(
                compiler->automaton_arena,
                compiler->automaton,
                *string,
                atom_list);
        } else {
            result = yr_arena_allocate_struct(
                compiler->automaton_arena,
                sizeof(YR_AC_MATCH),
                (void**)&new_match,
                offsetof(YR_AC_MATCH, string),
                offsetof(YR_AC_MATCH, forward_code),
                offsetof(YR_AC_MATCH, backward_code),
                offsetof(YR_AC_MATCH, next),
                EOL);

            if (result == ERROR_SUCCESS) {
                new_match->backtrack               = 0;
                new_match->string                  = *string;
                new_match->forward_code            = re->root_node->forward_code;
                new_match->backward_code           = NULL;
                new_match->next                    = compiler->automaton->root->matches;
                compiler->automaton->root->matches = new_match;
            }
        }
    }

    atom = atom_list;

    if (atom != NULL)
        *min_atom_length = MAX_ATOM_LENGTH;
    else
        *min_atom_length = 0;

    while (atom != NULL) {
        if (atom->atom_length < *min_atom_length)
            *min_atom_length = atom->atom_length;
        atom = atom->next;
    }

    if (flags & STRING_GFLAGS_LITERAL) {
        if (flags & STRING_GFLAGS_WIDE)
            max_string_len = (*string)->length * 2;
        else
            max_string_len = (*string)->length;

        if (max_string_len == *min_atom_length)
            (*string)->g_flags |= STRING_GFLAGS_FITS_IN_ATOM;
    }

    if (free_literal)
        yr_free(literal_string);

    if (atom_list != NULL)
        yr_atoms_list_destroy(atom_list);
#else
    (*string)->length = literal_string->length;

    result = yr_arena_write_data(
        compiler->sz_arena,
        literal_string->c_string,
        literal_string->length,
        (void*)&(*string)->string);

#endif
    return result;
}

#include <stdint.h>
#include <limits.h>

YR_STRING* yr_parser_reduce_string_declaration(
    yyscan_t yyscanner,
    int32_t string_flags,
    const char* identifier,
    SIZED_STRING* str)
{
    int min_atom_length;
    int re_flags = 0;

    YR_COMPILER* compiler = yyget_extra(yyscanner);
    YR_STRING* string     = NULL;

#if REAL_YARA
    int min_atom_length_aux;
    char message[512];
    int32_t min_gap;
    int32_t max_gap;
    YR_STRING* aux_string;
    YR_STRING* prev_string;

    RE* re = NULL;
    RE* remainder_re;
    RE_ERROR re_error;
#endif

    if (str->flags & SIZED_STRING_FLAGS_NO_CASE)
        string_flags |= STRING_GFLAGS_NO_CASE;

    if (str->flags & SIZED_STRING_FLAGS_DOT_ALL)
        re_flags |= RE_FLAGS_DOT_ALL;

    if (strcmp(identifier, "$") == 0)
        string_flags |= STRING_GFLAGS_ANONYMOUS;

    if (!(string_flags & STRING_GFLAGS_WIDE))
        string_flags |= STRING_GFLAGS_ASCII;

    if (string_flags & STRING_GFLAGS_NO_CASE)
        re_flags |= RE_FLAGS_NO_CASE;

    // The STRING_GFLAGS_SINGLE_MATCH flag indicates that finding
    // a single match for the string is enough. This is true in
    // most cases, except when the string count (#) and string offset (@)
    // operators are used. All strings are marked STRING_FLAGS_SINGLE_MATCH
    // initially, and unmarked later if required.

    string_flags |= STRING_GFLAGS_SINGLE_MATCH;

#if REAL_YARA
    if (string_flags & STRING_GFLAGS_HEXADECIMAL ||
        string_flags & STRING_GFLAGS_REGEXP) {
        if (string_flags & STRING_GFLAGS_HEXADECIMAL)
            compiler->last_result = yr_re_parse_hex(
                str->c_string, re_flags, &re, &re_error);
        else
            compiler->last_result = yr_re_parse(
                str->c_string, re_flags, &re, &re_error);

        if (compiler->last_result != ERROR_SUCCESS) {
            snprintf(
                message,
                sizeof(message),
                "invalid %s \"%s\": %s",
                (string_flags & STRING_GFLAGS_HEXADECIMAL) ? "hex string" : "regular expression",
                identifier,
                re_error.message);

            yr_compiler_set_error_extra_info(
                compiler, message);

            goto _exit;
        }

        if (re->flags & RE_FLAGS_FAST_HEX_REGEXP)
            string_flags |= STRING_GFLAGS_FAST_HEX_REGEXP;

        compiler->last_result = yr_re_split_at_chaining_point(
            re, &re, &remainder_re, &min_gap, &max_gap);

        if (compiler->last_result != ERROR_SUCCESS)
            goto _exit;

        compiler->last_result = _yr_parser_write_string(
            identifier,
            string_flags,
            compiler,
            NULL,
            re,
            &string,
            &min_atom_length);

        if (compiler->last_result != ERROR_SUCCESS)
            goto _exit;

        if (remainder_re != NULL) {
            string->g_flags |= STRING_GFLAGS_CHAIN_TAIL | STRING_GFLAGS_CHAIN_PART;
            string->chain_gap_min = min_gap;
            string->chain_gap_max = max_gap;

            // Use "aux_string" from now on, we want to keep the value of "string"
            // because it will returned.

            aux_string = string;

            while (remainder_re != NULL) {
                // Destroy regexp pointed by 're' before yr_re_split_at_jmp
                // overwrites 're' with another value.

                yr_re_destroy(re);

                compiler->last_result = yr_re_split_at_chaining_point(
                    remainder_re, &re, &remainder_re, &min_gap, &max_gap);

                if (compiler->last_result != ERROR_SUCCESS)
                    goto _exit;

                prev_string = aux_string;

                compiler->last_result = _yr_parser_write_string(
                    identifier,
                    string_flags,
                    compiler,
                    NULL,
                    re,
                    &aux_string,
                    &min_atom_length_aux);

                if (compiler->last_result != ERROR_SUCCESS)
                    goto _exit;

                if (min_atom_length_aux < min_atom_length)
                    min_atom_length = min_atom_length_aux;

                aux_string->g_flags |= STRING_GFLAGS_CHAIN_PART;
                aux_string->chain_gap_min = min_gap;
                aux_string->chain_gap_max = max_gap;

                prev_string->chained_to = aux_string;
            }
        } else {
#endif
            compiler->last_result = _yr_parser_write_string(
                identifier,
                string_flags,
                compiler,
                str,
                NULL,
                &string,
                &min_atom_length);

            if (compiler->last_result != ERROR_SUCCESS)
                goto _exit;
#if REAL_YARA
        }
#endif

        if (string == NULL) {
            cli_errmsg("yara_parser: no mem for struct _yc_string.\n");
            compiler->last_result = CL_EMEM;
            return NULL;
        }

        STAILQ_INSERT_TAIL(&compiler->current_rule_string_q, string, link);

#if REAL_YARA
        if (min_atom_length < 2 && compiler->callback != NULL) {
            snprintf(
                message,
                sizeof(message),
                "%s is slowing down scanning%s",
                string->identifier,
                min_atom_length == 0 ? " (critical!)" : "");

            yywarning(yyscanner, message);
        }
#endif

    _exit:

#if REAL_YARA
        if (re != NULL)
            yr_re_destroy(re);
#endif

        if (compiler->last_result != ERROR_SUCCESS)
            return NULL;

        return string;
    }

    int yr_parser_reduce_rule_declaration(
        yyscan_t yyscanner,
        int32_t flags,
        const char* identifier,
        char* tags,
        YR_STRING* strings,
        YR_META* metas)
    {
        YR_COMPILER* compiler = yyget_extra(yyscanner);

        YR_RULE* rule;
        YR_STRING* string;
        uint8_t halt = OP_HALT;

#if !REAL_YARA
        UNUSEDPARAM(tags);
        UNUSEDPARAM(strings);
        UNUSEDPARAM(metas);
#endif

        if (yr_hash_table_lookup(
                compiler->rules_table,
                identifier,
                compiler->current_namespace->name) != NULL ||
            yr_hash_table_lookup(
                compiler->objects_table,
                identifier,
                compiler->current_namespace->name) != NULL) {
            // A rule or variable with the same identifier already exists, return the
            // appropriate error.

            yr_compiler_set_error_extra_info(compiler, identifier);
            compiler->last_result = ERROR_DUPLICATE_IDENTIFIER;
            return compiler->last_result;
        }

        // Check for unreferenced (unused) strings.

        string = compiler->current_rule_strings;

        while (!STRING_IS_NULL(string)) {
            // Only the heading fragment in a chain of strings (the one with
            // chained_to == NULL) must be referenced. All other fragments
            // are never marked as referenced.

            if (!STRING_IS_REFERENCED(string) &&
                string->chained_to == NULL) {
                yr_compiler_set_error_extra_info(compiler, string->identifier);
                compiler->last_result = ERROR_UNREFERENCED_STRING;
                break;
            }

            string = yr_arena_next_address(
                compiler->strings_arena,
                string,
                sizeof(YR_STRING));
        }

        if (compiler->last_result != ERROR_SUCCESS)
            return compiler->last_result;

        FAIL_ON_COMPILER_ERROR(yr_arena_allocate_struct(
            compiler->rules_arena,
            sizeof(YR_RULE),
            (void**)&rule,
            offsetof(YR_RULE, identifier),
            //      offsetof(YR_RULE, tags), ClamAV - later
            offsetof(YR_RULE, strings),
            //      offsetof(YR_RULE, metas), ClamAV - later
            //      offsetof(YR_RULE, ns), ClamAV - later
            EOL));

        if (rule == NULL) {
            cli_errmsg("yara_parser: no mem for struct _yc_rule.\n");
            return CL_EMEM;
        }
        STAILQ_INIT(&rule->strings);
        STAILQ_CONCAT(&rule->strings, &compiler->current_rule_string_q);
        STAILQ_INIT(&compiler->current_rule_string_q);

        rule->g_flags = flags | compiler->current_rule_flags;
#if REAL_YARA
        rule->tags    = tags;
        rule->strings = strings;
        rule->metas   = metas;
        rule->ns      = compiler->current_namespace;

#ifdef PROFILING_ENABLED
        rule->clock_ticks = 0;
#endif
#endif
        FAIL_ON_COMPILER_ERROR(yr_arena_write_string(
            compiler->sz_arena,
            identifier,
            (char**)&rule->identifier));

        FAIL_ON_COMPILER_ERROR(yr_parser_emit_with_arg_reloc(
            yyscanner,
            OP_MATCH_RULE,
            PTR_TO_UINT64(rule),
            NULL));

        FAIL_ON_COMPILER_ERROR(yr_hash_table_add(
            compiler->rules_table,
            identifier,
            compiler->current_namespace->name,
            (void*)rule));

        compiler->current_rule_flags = 0;
#if REAL_YARA
        compiler->current_rule_strings = NULL;
#else
    rule->cl_flags                 = compiler->current_rule_clflags;
    compiler->current_rule_clflags = 0;
    // Write halt instruction at the end of code.
    yr_arena_write_data(
        compiler->code_arena,
        &halt,
        sizeof(int8_t),
        NULL);
    // TBD: seems like we will need the following yr_arena_coalesce, but it is not working.
    // Yara condition code will work OK as long as it is less than 64K.
    // FAIL_ON_COMPILER_ERROR(yr_arena_coalesce(compiler->code_arena));
    rule->code_start = yr_arena_base_address(compiler->code_arena);
    yr_arena_append(compiler->the_arena, compiler->code_arena);
    FAIL_ON_COMPILER_ERROR(yr_arena_create(65536, 0, &compiler->code_arena));
    STAILQ_INSERT_TAIL(&compiler->rule_q, rule, link);
#endif
        return compiler->last_result;
    }

    int yr_parser_reduce_string_identifier(
        yyscan_t yyscanner,
        const char* identifier,
        int8_t instruction)
    {
        YR_STRING* string;
        YR_COMPILER* compiler = yyget_extra(yyscanner);

        if (strcmp(identifier, "$") == 0) {
            if (compiler->loop_for_of_mem_offset >= 0) {
                yr_parser_emit_with_arg(
                    yyscanner,
                    OP_PUSH_M,
                    compiler->loop_for_of_mem_offset,
                    NULL);

                yr_parser_emit(yyscanner, instruction, NULL);

                if (instruction != OP_STR_FOUND) {
                    string = compiler->current_rule_strings;

                    while (!STRING_IS_NULL(string)) {
                        string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;
                        string = yr_arena_next_address(
                            compiler->strings_arena,
                            string,
                            sizeof(YR_STRING));
                    }
                }
            } else {
                compiler->last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
            }
        } else {
            string = yr_parser_lookup_string(yyscanner, identifier);

            if (string != NULL) {
                yr_parser_emit_with_arg_reloc(
                    yyscanner,
                    OP_PUSH,
                    PTR_TO_UINT64(string),
                    NULL);

                if (instruction != OP_STR_FOUND)
                    string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;

                yr_parser_emit(yyscanner, instruction, NULL);

                string->g_flags |= STRING_GFLAGS_REFERENCED;
            }
        }
        return compiler->last_result;
    }

    YR_META* yr_parser_reduce_meta_declaration(
        yyscan_t yyscanner,
        int32_t type,
        const char* identifier,
        const char* string,
        int32_t integer)
    {
        YR_COMPILER* compiler = yyget_extra(yyscanner);
        YR_META* meta;
        compiler->last_result = yr_arena_allocate_struct(
            compiler->metas_arena,
            sizeof(YR_META),
            (void**)&meta,
            offsetof(YR_META, identifier),
            offsetof(YR_META, string),
            EOL);

        if (compiler->last_result != ERROR_SUCCESS)
            return NULL;

        compiler->last_result = yr_arena_write_string(
            compiler->sz_arena,
            identifier,
            (char**)&meta->identifier);

        if (compiler->last_result != ERROR_SUCCESS)
            return NULL;

        if (string != NULL)
            compiler->last_result = yr_arena_write_string(
                compiler->sz_arena,
                string,
                &meta->string);
        else
            meta->string = NULL;

        if (compiler->last_result != ERROR_SUCCESS)
            return NULL;

        meta->integer = integer;
        meta->type    = type;

        return meta;
#if 0 // meta w.i.p.
  meta = cli_calloc(1, sizeof(YR_META));
  if (meta == NULL) {
      cli_errmsg("yara_parser: no mem for YR_META.\n");
      compiler->last_result = CL_EMEM;
      return NULL;
  }

  if (identifier != NULL) {
      meta->identifier = cli_strdup(identifier);
      if (meta->identifier == NULL) {
          cli_errmsg("yara_parser: no mem for meta->identifier.\n");
          compiler->last_result = CL_EMEM;
          return NULL;
      }
  }
  if (string != NULL) {
      meta->string = cli_strdup(string);
      if (meta->string == NULL) {
          cli_errmsg("yara_parser: no mem for meta->string.\n");
          compiler->last_result = CL_EMEM;
          return NULL;
      }
  }
  meta->integer = integer;
  meta->type = type;

  STAILQ_INSERT_TAIL(&compiler->current_meta, meta, link);

  return meta;
#endif
    }

    int yr_parser_reduce_import(
        yyscan_t yyscanner,
        SIZED_STRING * module_name)
    {
#if REAL_YARA
        YR_COMPILER* compiler = NULL;
        ///  YR_OBJECT* module_structure;
        char* name;

        compiler = yyget_extra(yyscanner);

        module_structure = yr_hash_table_lookup(
            compiler->objects_table,
            module_name->c_string,
            compiler->current_namespace->name);

        // if module already imported, do nothing

        if (module_structure != NULL)
            return ERROR_SUCCESS;

        compiler->last_result = yr_object_create(
            OBJECT_TYPE_STRUCTURE,
            module_name->c_string,
            NULL,
            &module_structure);

        if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_hash_table_add(
                compiler->objects_table,
                module_name->c_string,
                compiler->current_namespace->name,
                module_structure);

        if (compiler->last_result == ERROR_SUCCESS) {
            compiler->last_result = yr_modules_do_declarations(
                module_name->c_string,
                module_structure);

            if (compiler->last_result == ERROR_UNKNOWN_MODULE)
                yr_compiler_set_error_extra_info(compiler, module_name->c_string);
        }

        if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_arena_write_string(
                compiler->sz_arena,
                module_name->c_string,
                &name);

        if (compiler->last_result == ERROR_SUCCESS)
            compiler->last_result = yr_parser_emit_with_arg_reloc(
                yyscanner,
                OP_IMPORT,
                PTR_TO_UINT64(name),
                NULL);

        return compiler->last_result;
#else
    UNUSEDPARAM(yyscanner);
    UNUSEDPARAM(module_name);

    return ERROR_SUCCESS;
#endif
    }
