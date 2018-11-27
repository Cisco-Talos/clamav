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

#include <string.h>
#include <assert.h>
#include <time.h>

#if REAL_YARA
#include <yara/exec.h>
#include <yara/limits.h>
#include <yara/error.h>
#include <yara/object.h>
#include <yara/modules.h>
#include <yara/re.h>


#include <yara.h>
#else
#include <stdint.h>
//Temp for ClamAV compilation
typedef struct _YR_MATCH
{
  int64_t base;
  int64_t offset;
  int32_t length;

  union {
    uint8_t* data;           // Confirmed matches use "data",
    int32_t chain_length;    // unconfirmed ones use "chain_length"
  };

  struct _YR_MATCH*  prev;
  struct _YR_MATCH*  next;

} YR_MATCH;

// End of temp for clamAV
#include "matcher.h"
#include "matcher-ac.h"
#include "yara_clam.h"
#include "yara_exec.h"
#endif

#define STACK_SIZE 16384
#define MEM_SIZE   MAX_LOOP_NESTING * LOOP_LOCAL_VARS


#define push(x)  \
    do { \
      if (sp < STACK_SIZE) stack[sp++] = (x); \
      else return ERROR_EXEC_STACK_OVERFLOW; \
    } while(0)


#define pop(x)  x = stack[--sp]


#define operation(operator, op1, op2) \
    (IS_UNDEFINED(op1) || IS_UNDEFINED(op2)) ? (UNDEFINED) : (op1 operator op2)


#define comparison(operator, op1, op2) \
    (IS_UNDEFINED(op1) || IS_UNDEFINED(op2)) ? (0) : (op1 operator op2)


#if REAL_YARA
#define function_read(type) \
    int64_t read_##type(YR_MEMORY_BLOCK* block, size_t offset) \
    { \
      while (block != NULL) \
      { \
        if (offset >= block->base && \
            block->size >= sizeof(type) && \
            offset <= block->base + block->size - sizeof(type)) \
        { \
          return *((type *) (block->data + offset - block->base)); \
        } \
        block = block->next; \
      } \
      return UNDEFINED; \
    };
#else
#define function_read(type) \
    int64_t read_##type(fmap_t * fmap, size_t offset) \
    { \
      const void *data;                                         \
      if (offset + sizeof(type) >= fmap->len)                   \
          return UNDEFINED;                                     \
      data = fmap_need_off_once(fmap, offset, sizeof(type));    \
      if (!data)                                                \
          return UNDEFINED;                                     \
      return *((type *) data);                                  \
    };
#endif

function_read(uint8_t)
function_read(uint16_t)
function_read(uint32_t)
function_read(int8_t)
function_read(int16_t)
function_read(int32_t)

int yr_execute_code(
#if REAL_YARA
    YR_RULES* rules,
#else
    struct cli_ac_lsig * aclsig,
    struct cli_ac_data * acdata,
#endif
    YR_SCAN_CONTEXT* context,
    int timeout,
    time_t start_time)
{
  int64_t r1;
  int64_t r2;
  int64_t r3;
  int64_t mem[MEM_SIZE];
  int64_t stack[STACK_SIZE];
  int64_t args[MAX_FUNCTION_ARGS];
  int32_t sp = 0;
#if REAL_YARA
  uint8_t* ip = rules->code_start;
#else
  uint8_t* ip = aclsig->u.code_start;
  uint32_t lsig_id;
  uint32_t rule_matches = 0;
  struct cli_lsig_matches * ls_matches;
  struct cli_subsig_matches * ss_matches;
  uint32_t * offs;
#endif

  YR_RULE* rule;
  YR_STRING* string;
  YR_MATCH* match;
  YR_OBJECT* object;
  YR_OBJECT_FUNCTION* function;

  char* identifier;

  int i;
  int found;
  int count;
  int result = -1;
  int cycle = 0;
#if REAL_YARA
  int tidx = yr_get_tidx();
#else

  cli_dbgmsg("yara_exec: beginning execution for lsig %i\n", aclsig->id);
#endif

  #ifdef PROFILING_ENABLED
  clock_t start = clock();
  #endif

  while(1)
  {
    cli_dbgmsg("yara_exec: executing %i\n", *ip);
    switch(*ip)
    {
      case OP_HALT:
        // When the halt instruction is reached the stack
        // should be empty.
        assert(sp == 0);
#if REAL_YARA
        return ERROR_SUCCESS;
#else
        if (rule_matches != 0)
            return CL_VIRUS;
        return CL_SUCCESS;
#endif

      case OP_PUSH:
        memcpy(&r1, ip + 1, sizeof(uint64_t));
        ip += sizeof(uint64_t);
        push(r1);
        break;

      case OP_POP:
        pop(r1);
        break;

      case OP_CLEAR_M:
        memcpy(&r1, ip + 1, sizeof(uint64_t));
        ip += sizeof(uint64_t);
        mem[r1] = 0;
        break;

      case OP_ADD_M:
        memcpy(&r1, ip + 1, sizeof(uint64_t));
        ip += sizeof(uint64_t);
        pop(r2);
        mem[r1] += r2;
        break;

      case OP_INCR_M:
        memcpy(&r1, ip + 1, sizeof(uint64_t));
        ip += sizeof(uint64_t);
        mem[r1]++;
        break;

      case OP_PUSH_M:
        memcpy(&r1, ip + 1, sizeof(uint64_t));
        ip += sizeof(uint64_t);
        push(mem[r1]);
        break;

      case OP_POP_M:
        memcpy(&r1, ip + 1, sizeof(uint64_t));
        ip += sizeof(uint64_t);
        pop(mem[r1]);
        break;

      case OP_SWAPUNDEF:
        memcpy(&r1, ip + 1, sizeof(uint64_t));
        ip += sizeof(uint64_t);
        pop(r2);
        if (r2 != UNDEFINED)
          push(r2);
        else
          push(mem[r1]);
        break;

      case OP_JNUNDEF:
        pop(r1);
        push(r1);

        if (r1 != UNDEFINED)
        {
          ip = *(uint8_t**)(ip + 1);
          // ip will be incremented at the end of the loop,
          // decrement it here to compensate.
          ip--;
        }
        else
        {
          ip += sizeof(uint64_t);
        }
        break;

      case OP_JLE:
        pop(r2);
        pop(r1);
        push(r1);
        push(r2);

        if (r1 <= r2)
        {
          ip = *(uint8_t**)(ip + 1);
          // ip will be incremented at the end of the loop,
          // decrement it here to compensate.
          ip--;
        }
        else
        {
          ip += sizeof(uint64_t);
        }
        break;

      case OP_AND:
        pop(r2);
        pop(r1);
        if (IS_UNDEFINED(r1) || IS_UNDEFINED(r2))
          push(0);
        else
          push(r1 & r2);
        break;

      case OP_OR:
        pop(r2);
        pop(r1);
        if (IS_UNDEFINED(r1))
          push(r2);
        else if (IS_UNDEFINED(r2))
          push(r1);
        else
          push(r1 | r2);
        break;

      case OP_NOT:
        pop(r1);
        if (IS_UNDEFINED(r1))
          push(UNDEFINED);
        else
          push(!r1);
        break;

      case OP_LT:
        pop(r2);
        pop(r1);
        push(comparison(<, r1, r2));
        break;

      case OP_GT:
        pop(r2);
        pop(r1);
        push(comparison(>, r1, r2));
        break;

      case OP_LE:
        pop(r2);
        pop(r1);
        push(comparison(<=, r1, r2));
        break;

      case OP_GE:
        pop(r2);
        pop(r1);
        push(comparison(>=, r1, r2));
        break;

      case OP_EQ:
        pop(r2);
        pop(r1);
        push(comparison(==, r1, r2));
        break;

      case OP_NEQ:
        pop(r2);
        pop(r1);
        push(comparison(!=, r1, r2));
        break;

      case OP_SZ_EQ:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1) || IS_UNDEFINED(r2))
          push(UNDEFINED);
        else
          push(strcmp(UINT64_TO_PTR(char*, r1),
                      UINT64_TO_PTR(char*, r2)) == 0);
        break;

      case OP_SZ_NEQ:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1) || IS_UNDEFINED(r2))
          push(UNDEFINED);
        else
          push(strcmp(UINT64_TO_PTR(char*, r1),
                      UINT64_TO_PTR(char*, r2)) != 0);
        break;

      case OP_SZ_TO_BOOL:
        pop(r1);

        if (IS_UNDEFINED(r1))
          push(UNDEFINED);
        else
          push(strlen(UINT64_TO_PTR(char*, r1)) > 0);

        break;

      case OP_ADD:
        pop(r2);
        pop(r1);
        push(operation(+, r1, r2));
        break;

      case OP_SUB:
        pop(r2);
        pop(r1);
        push(operation(-, r1, r2));
        break;

      case OP_MUL:
        pop(r2);
        pop(r1);
        push(operation(*, r1, r2));
        break;

      case OP_DIV:
        pop(r2);
        pop(r1);
        push(operation(/, r1, r2));
        break;

      case OP_MOD:
        pop(r2);
        pop(r1);
        push(operation(%, r1, r2));
        break;

      case OP_NEG:
        pop(r1);
        push(IS_UNDEFINED(r1) ? UNDEFINED : ~r1);
        break;

      case OP_SHR:
        pop(r2);
        pop(r1);
        push(operation(>>, r1, r2));
        break;

      case OP_SHL:
        pop(r2);
        pop(r1);
        push(operation(<<, r1, r2));
        break;

      case OP_XOR:
        pop(r2);
        pop(r1);
        push(operation(^, r1, r2));
        break;

      case OP_PUSH_RULE:
        rule = *(YR_RULE**)(ip + 1);
        ip += sizeof(uint64_t);
#if REAL_YARA
        push(rule->t_flags[tidx] & RULE_TFLAGS_MATCH ? 1 : 0);
#else
        push(acdata->yr_matches[rule->lsigid]);
#endif
        break;

      case OP_MATCH_RULE:
        pop(r1);
        rule = *(YR_RULE**)(ip + 1);
        ip += sizeof(uint64_t);

        if (!IS_UNDEFINED(r1) && r1)
#if REAL_YARA
          rule->t_flags[tidx] |= RULE_TFLAGS_MATCH;
#else
        {
            rule_matches++;
            acdata->yr_matches[aclsig->id] = 1;
        }
#endif

        #ifdef PROFILING_ENABLED
        rule->clock_ticks += clock() - start;
        start = clock();
        #endif
        break;

      case OP_OBJ_LOAD:
        identifier = *(char**)(ip + 1);
        ip += sizeof(uint64_t);

        object = (YR_OBJECT*) yr_hash_table_lookup(
            context->objects_table,
            identifier,
            NULL);

        assert(object != NULL);
        push(PTR_TO_UINT64(object));
        break;

#if REAL_YARA
      case OP_OBJ_FIELD:
        pop(r1);

        identifier = *(char**)(ip + 1);
        ip += sizeof(uint64_t);

        if (IS_UNDEFINED(r1))
        {
          push(UNDEFINED);
          break;
        }

        object = UINT64_TO_PTR(YR_OBJECT*, r1);
        object = yr_object_lookup_field(object, identifier);
        assert(object != NULL);
        push(PTR_TO_UINT64(object));
        break;
#endif

      case OP_OBJ_VALUE:
        pop(r1);

        if (IS_UNDEFINED(r1))
        {
          push(UNDEFINED);
          break;
        }

        object = UINT64_TO_PTR(YR_OBJECT*, r1);

        switch(object->type)
        {
          case OBJECT_TYPE_INTEGER:
            push(((YR_OBJECT_INTEGER*) object)->value);
            break;

          case OBJECT_TYPE_STRING:
            if (((YR_OBJECT_STRING*) object)->value != NULL)
              push(PTR_TO_UINT64(((YR_OBJECT_STRING*) object)->value));
            else
              push(UNDEFINED);
            break;

          default:
            assert(FALSE);
        }

        break;

#if REAL_YARA
      case OP_INDEX_ARRAY:
        pop(r1);
        pop(r2);

        if (r1 == UNDEFINED)
        {
          push(UNDEFINED);
          break;
        }

        object = UINT64_TO_PTR(YR_OBJECT*, r2);
        assert(object->type == OBJECT_TYPE_ARRAY);
        object = yr_object_array_get_item(object, 0, r1);

        if (object != NULL)
          push(PTR_TO_UINT64(object));
        else
          push(UNDEFINED);

        break;
#endif

      case OP_CALL:

        // r1 = number of arguments

        memcpy(&r1, ip + 1, sizeof(uint64_t));
        ip += sizeof(uint64_t);

        // pop arguments from stack and copy them to args array

        while (r1 > 0)
        {
          pop(args[r1 - 1]);
          r1--;
        }

        pop(r2);

        function = UINT64_TO_PTR(YR_OBJECT_FUNCTION*, r2);
        result = function->code((void*) args, context, function);

        if (result == ERROR_SUCCESS)
          push(PTR_TO_UINT64(function->return_obj));
        else
          return result;

        break;

      case OP_STR_FOUND:
        pop(r1);
        string = UINT64_TO_PTR(YR_STRING*, r1);
#if REAL_YARA
        push(string->matches[tidx].tail != NULL ? 1 : 0);
#else
        push(acdata->lsigsuboff_first[aclsig->id][string->subsig_id] != CLI_OFF_NONE ? 1 : 0);
#endif
        break;

      case OP_STR_FOUND_AT:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1))
        {
          push(0);
          break;
        }

        string = UINT64_TO_PTR(YR_STRING*, r2);
#if REAL_YARA
        match = string->matches[tidx].head;
        found = 0;

        while (match != NULL)
        {
          if (r1 == match->base + match->offset)
          {
            push(1);
            found = 1;
            break;
          }

          if (r1 < match->base + match->offset)
            break;

          match = match->next;
        }
#else
        found = 0;
        ls_matches = acdata->lsig_matches[aclsig->id];
        if (ls_matches != NULL) {
            ss_matches = ls_matches->matches[string->subsig_id];
            if (ss_matches != NULL) {
                offs = ss_matches->offsets;
                for (i = 0; i < ss_matches->next; i++) {
                    if (offs[i] == r1) {
                        push(1);
                        found = 1;
                        break;
                    }
                    if (r1 < offs[i])
                        break;
                }
            }
        }
#endif
        if (!found)
          push(0);

        break;

      case OP_STR_FOUND_IN:
        pop(r3);
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1) || IS_UNDEFINED(r2))
        {
          push(0);
          break;
        }

        string = UINT64_TO_PTR(YR_STRING*, r3);
#if REAL_YARA
        match = string->matches[tidx].head;
        found = FALSE;

        while (match != NULL && !found)
        {
          if (match->base + match->offset >= r1 &&
              match->base + match->offset <= r2)
          {
            push(1);
            found = TRUE;
          }

          if (match->base + match->offset > r2)
            break;

          match = match->next;
        }
#else
        found = FALSE;
        ls_matches = acdata->lsig_matches[aclsig->id];
        if (ls_matches != NULL) {
            ss_matches = ls_matches->matches[string->subsig_id];
            if (ss_matches != NULL) {
                offs = ss_matches->offsets;
                for (i = 0; i < ss_matches->next; i++) {
                    if (offs[i] >= r1 &&
                        offs[i] <= r2) {
                        push(1);
                        found = TRUE;
                        break;
                    }
                    if (r2 < offs[i])
                        break;
                }
            }
        }        
#endif

        if (!found)
          push(0);

        break;

      case OP_STR_COUNT:
        pop(r1);
        string = UINT64_TO_PTR(YR_STRING*, r1);
#if REAL_YARA
        push(string->matches[tidx].count);
#else
        push(acdata->lsigcnt[aclsig->id][string->subsig_id]);
#endif
        break;

      case OP_STR_OFFSET:
        pop(r2);
        pop(r1);

        if (IS_UNDEFINED(r1))
        {
          push(UNDEFINED);
          break;
        }

        string = UINT64_TO_PTR(YR_STRING*, r2);
#if REAL_YARA
        match = string->matches[tidx].head;
        i = 1;
        found = FALSE;

        while (match != NULL && !found)
        {
          if (r1 == i)
          {
            push(match->base + match->offset);
            found = TRUE;
          }

          i++;
          match = match->next;
        }
#else
        i = r1 - 1;
        found = FALSE;
        ls_matches = acdata->lsig_matches[aclsig->id];
        if (ls_matches != NULL && i >= 0) {
            ss_matches = ls_matches->matches[string->subsig_id];
            if (ss_matches != NULL) {
                if (i < ss_matches->next) {
                    push(ss_matches->offsets[i]);
                    found = TRUE;
                }
            }
        }
#endif

        if (!found)
          push(UNDEFINED);

        break;

      case OP_OF:
        found = 0;
        count = 0;
        pop(r1);

#if REAL_YARA
        while (r1 != UNDEFINED)
        {
          string = UINT64_TO_PTR(YR_STRING*, r1);
          if (string->matches[tidx].tail != NULL)
            found++;
          count++;
          pop(r1);
        }
#else
        while (r1 != UNDEFINED)
        {
          string = UINT64_TO_PTR(YR_STRING*, r1);
          lsig_id = string->subsig_id;
          if (acdata->lsigsuboff_first[aclsig->id][lsig_id] != CLI_OFF_NONE)
            found++;
          count++;
          pop(r1);
        }
#endif

        pop(r2);

        if (r2 != UNDEFINED)
          push(found >= r2 ? 1 : 0);
        else
          push(found >= count ? 1 : 0);

        break;

      case OP_FILESIZE:
        push(context->file_size);
        break;

      case OP_ENTRYPOINT:
        push(context->entry_point);
        break;

#if REAL_YARA
      case OP_INT8:
        pop(r1);
        push(read_int8_t(context->mem_block, r1));
        break;

      case OP_INT16:
        pop(r1);
        push(read_int16_t(context->mem_block, r1));
        break;

      case OP_INT32:
        pop(r1);
        push(read_int32_t(context->mem_block, r1));
        break;

      case OP_UINT8:
        pop(r1);
        push(read_uint8_t(context->mem_block, r1));
        break;

      case OP_UINT16:
        pop(r1);
        push(read_uint16_t(context->mem_block, r1));
        break;

      case OP_UINT32:
        pop(r1);
        push(read_uint32_t(context->mem_block, r1));
        break;
#else
      case OP_INT8:
        pop(r1);
        push(read_int8_t(context->fmap, r1));
        break;

      case OP_INT16:
        pop(r1);
        push(read_int16_t(context->fmap, r1));
        break;

      case OP_INT32:
        pop(r1);
        push(read_int32_t(context->fmap, r1));
        break;

      case OP_UINT8:
        pop(r1);
        push(read_uint8_t(context->fmap, r1));
        break;

      case OP_UINT16:
        pop(r1);
        push(read_uint16_t(context->fmap, r1));
        break;

      case OP_UINT32:
        pop(r1);
        push(read_uint32_t(context->fmap, r1));
        break;
#endif

      case OP_CONTAINS:
        pop(r2);
        pop(r1);
        push(strstr(UINT64_TO_PTR(char*, r1),
                    UINT64_TO_PTR(char*, r2)) != NULL);
        break;


#if REAL_YARA //not supported ClamAV
      case OP_IMPORT:
        memcpy(&r1, ip + 1, sizeof(uint64_t));
        ip += sizeof(uint64_t);

        FAIL_ON_ERROR(yr_modules_load(
            UINT64_TO_PTR(char*, r1),
            context));

        break;
#endif

      case OP_MATCHES:
        pop(r2);
        pop(r1);

        count = strlen(UINT64_TO_PTR(char*, r1));

        if (count == 0)
        {
          push(FALSE);
          break;
        }

#if REAL_YARA
        result = yr_re_exec(
          UINT64_TO_PTR(uint8_t*, r2),
          UINT64_TO_PTR(uint8_t*, r1),
          count,
          RE_FLAGS_SCAN,
          NULL,
          NULL);
#else
        result = -1;  //matches not currently supported in ClamAV. push(FALSE).
#endif

        push(result >= 0);
        break;

      default:
        // Unknown instruction, this shouldn't happen.
        assert(FALSE);
    }

    if (timeout > 0)  // timeout == 0 means no timeout
    {
      // Check for timeout every 10 instruction cycles.

      if (++cycle == 10)
      {
        if (difftime(time(NULL), start_time) > timeout)
          return ERROR_SCAN_TIMEOUT;

        cycle = 0;
      }
    }

    ip++;
  }

  // After executing the code the stack should be empty.
  assert(sp == 0);

  return ERROR_SUCCESS;
}
