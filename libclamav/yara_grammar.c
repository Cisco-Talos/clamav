/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Substitute the variable and function names.  */
#define yyparse yara_yyparse
#define yylex yara_yylex
#define yyerror yara_yyerror
#define yydebug yara_yydebug
#define yynerrs yara_yynerrs

/* First part of user prologue.  */
#line 43 "yara_grammar.y"

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>

#ifdef REAL_YARA
#include <yara/utils.h>
#include <yara/compiler.h>
#include <yara/object.h>
#include <yara/sizedstr.h>
#include <yara/exec.h>
#include <yara/error.h>
#include <yara/mem.h>
#include <yara/lexer.h>
#include <yara/parser.h>
#else
#include "yara_clam.h"
#include "yara_compiler.h"
#include "clamav-config.h"
#include "yara_grammar.h"
#include "yara_lexer.h"
#include "yara_parser.h"
#include "yara_exec.h"
#endif

#define YYERROR_VERBOSE

#define INTEGER_SET_ENUMERATION 1
#define INTEGER_SET_RANGE 2

#define EXPRESSION_TYPE_BOOLEAN 1
#define EXPRESSION_TYPE_INTEGER 2
#define EXPRESSION_TYPE_STRING 3
#define EXPRESSION_TYPE_REGEXP 4

#define ERROR_IF(x)                         \
    if (x) {                                \
        yyerror(yyscanner, compiler, NULL); \
        YYERROR;                            \
    }

#define CHECK_TYPE_WITH_CLEANUP(actual_type, expected_type, op, cleanup)        \
    if (actual_type != expected_type) {                                         \
        switch (actual_type) {                                                  \
            case EXPRESSION_TYPE_INTEGER:                                       \
                yr_compiler_set_error_extra_info(                               \
                    compiler, "wrong type \"integer\" for " op " operator");    \
                break;                                                          \
            case EXPRESSION_TYPE_STRING:                                        \
                yr_compiler_set_error_extra_info(                               \
                    compiler, "wrong type \"string\" for \"" op "\" operator"); \
                break;                                                          \
        }                                                                       \
        compiler->last_result = ERROR_WRONG_TYPE;                               \
        cleanup;                                                                \
        yyerror(yyscanner, compiler, NULL);                                     \
        YYERROR;                                                                \
    }

#define CHECK_TYPE(actual_type, expected_type, op) \
    CHECK_TYPE_WITH_CLEANUP(actual_type, expected_type, op, )

#define MSG(op) "wrong type \"string\" for \"" op "\" operator"

#define UNSUPPORTED_STRING_MODIFIER(modifier)                          \
    do {                                                               \
        yr_compiler_set_error_extra_info(                              \
            compiler, "unsupported string modifier \"" modifier "\""); \
        compiler->last_result = ERROR_INVALID_MODIFIER;                \
        yyerror(yyscanner, compiler, NULL);                            \
        YYERROR;                                                       \
    } while (0)

#line 160 "yara_grammar.c"

#ifndef YY_CAST
#ifdef __cplusplus
#define YY_CAST(Type, Val) static_cast<Type>(Val)
#define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type>(Val)
#else
#define YY_CAST(Type, Val) ((Type)(Val))
#define YY_REINTERPRET_CAST(Type, Val) ((Type)(Val))
#endif
#endif
#ifndef YY_NULLPTR
#if defined __cplusplus
#if 201103L <= __cplusplus
#define YY_NULLPTR nullptr
#else
#define YY_NULLPTR 0
#endif
#else
#define YY_NULLPTR ((void*)0)
#endif
#endif

#include "yara_grammar.h"
/* Symbol kind.  */
enum yysymbol_kind_t {
    YYSYMBOL_YYEMPTY                           = -2,
    YYSYMBOL_YYEOF                             = 0,   /* "end of file"  */
    YYSYMBOL_YYerror                           = 1,   /* error  */
    YYSYMBOL_YYUNDEF                           = 2,   /* "invalid token"  */
    YYSYMBOL__RULE_                            = 3,   /* _RULE_  */
    YYSYMBOL__PRIVATE_                         = 4,   /* _PRIVATE_  */
    YYSYMBOL__GLOBAL_                          = 5,   /* _GLOBAL_  */
    YYSYMBOL__META_                            = 6,   /* _META_  */
    YYSYMBOL__STRINGS_                         = 7,   /* _STRINGS_  */
    YYSYMBOL__CONDITION_                       = 8,   /* _CONDITION_  */
    YYSYMBOL__IDENTIFIER_                      = 9,   /* _IDENTIFIER_  */
    YYSYMBOL__STRING_IDENTIFIER_               = 10,  /* _STRING_IDENTIFIER_  */
    YYSYMBOL__STRING_COUNT_                    = 11,  /* _STRING_COUNT_  */
    YYSYMBOL__STRING_OFFSET_                   = 12,  /* _STRING_OFFSET_  */
    YYSYMBOL__STRING_IDENTIFIER_WITH_WILDCARD_ = 13,  /* _STRING_IDENTIFIER_WITH_WILDCARD_  */
    YYSYMBOL__NUMBER_                          = 14,  /* _NUMBER_  */
    YYSYMBOL__TEXT_STRING_                     = 15,  /* _TEXT_STRING_  */
    YYSYMBOL__HEX_STRING_                      = 16,  /* _HEX_STRING_  */
    YYSYMBOL__REGEXP_                          = 17,  /* _REGEXP_  */
    YYSYMBOL__ASCII_                           = 18,  /* _ASCII_  */
    YYSYMBOL__WIDE_                            = 19,  /* _WIDE_  */
    YYSYMBOL__XOR_                             = 20,  /* _XOR_  */
    YYSYMBOL__BASE64_                          = 21,  /* _BASE64_  */
    YYSYMBOL__BASE64_WIDE_                     = 22,  /* _BASE64_WIDE_  */
    YYSYMBOL__NOCASE_                          = 23,  /* _NOCASE_  */
    YYSYMBOL__FULLWORD_                        = 24,  /* _FULLWORD_  */
    YYSYMBOL__AT_                              = 25,  /* _AT_  */
    YYSYMBOL__FILESIZE_                        = 26,  /* _FILESIZE_  */
    YYSYMBOL__ENTRYPOINT_                      = 27,  /* _ENTRYPOINT_  */
    YYSYMBOL__ALL_                             = 28,  /* _ALL_  */
    YYSYMBOL__ANY_                             = 29,  /* _ANY_  */
    YYSYMBOL__IN_                              = 30,  /* _IN_  */
    YYSYMBOL__OF_                              = 31,  /* _OF_  */
    YYSYMBOL__FOR_                             = 32,  /* _FOR_  */
    YYSYMBOL__THEM_                            = 33,  /* _THEM_  */
    YYSYMBOL__INT8_                            = 34,  /* _INT8_  */
    YYSYMBOL__INT16_                           = 35,  /* _INT16_  */
    YYSYMBOL__INT32_                           = 36,  /* _INT32_  */
    YYSYMBOL__UINT8_                           = 37,  /* _UINT8_  */
    YYSYMBOL__UINT16_                          = 38,  /* _UINT16_  */
    YYSYMBOL__UINT32_                          = 39,  /* _UINT32_  */
    YYSYMBOL__MATCHES_                         = 40,  /* _MATCHES_  */
    YYSYMBOL__CONTAINS_                        = 41,  /* _CONTAINS_  */
    YYSYMBOL__IMPORT_                          = 42,  /* _IMPORT_  */
    YYSYMBOL__TRUE_                            = 43,  /* _TRUE_  */
    YYSYMBOL__FALSE_                           = 44,  /* _FALSE_  */
    YYSYMBOL__OR_                              = 45,  /* _OR_  */
    YYSYMBOL__AND_                             = 46,  /* _AND_  */
    YYSYMBOL_47_                               = 47,  /* '&'  */
    YYSYMBOL_48_                               = 48,  /* '|'  */
    YYSYMBOL_49_                               = 49,  /* '^'  */
    YYSYMBOL__LT_                              = 50,  /* _LT_  */
    YYSYMBOL__LE_                              = 51,  /* _LE_  */
    YYSYMBOL__GT_                              = 52,  /* _GT_  */
    YYSYMBOL__GE_                              = 53,  /* _GE_  */
    YYSYMBOL__EQ_                              = 54,  /* _EQ_  */
    YYSYMBOL__NEQ_                             = 55,  /* _NEQ_  */
    YYSYMBOL__IS_                              = 56,  /* _IS_  */
    YYSYMBOL__SHIFT_LEFT_                      = 57,  /* _SHIFT_LEFT_  */
    YYSYMBOL__SHIFT_RIGHT_                     = 58,  /* _SHIFT_RIGHT_  */
    YYSYMBOL_59_                               = 59,  /* '+'  */
    YYSYMBOL_60_                               = 60,  /* '-'  */
    YYSYMBOL_61_                               = 61,  /* '*'  */
    YYSYMBOL_62_                               = 62,  /* '\\'  */
    YYSYMBOL_63_                               = 63,  /* '%'  */
    YYSYMBOL__NOT_                             = 64,  /* _NOT_  */
    YYSYMBOL_65_                               = 65,  /* '~'  */
    YYSYMBOL_66_include_                       = 66,  /* "include"  */
    YYSYMBOL_67_                               = 67,  /* '{'  */
    YYSYMBOL_68_                               = 68,  /* '}'  */
    YYSYMBOL_69_                               = 69,  /* ':'  */
    YYSYMBOL_70_                               = 70,  /* '='  */
    YYSYMBOL_71_                               = 71,  /* '('  */
    YYSYMBOL_72_                               = 72,  /* ')'  */
    YYSYMBOL_73_                               = 73,  /* '.'  */
    YYSYMBOL_74_                               = 74,  /* '['  */
    YYSYMBOL_75_                               = 75,  /* ']'  */
    YYSYMBOL_76_                               = 76,  /* ','  */
    YYSYMBOL_YYACCEPT                          = 77,  /* $accept  */
    YYSYMBOL_rules                             = 78,  /* rules  */
    YYSYMBOL_import                            = 79,  /* import  */
    YYSYMBOL_rule                              = 80,  /* rule  */
    YYSYMBOL_meta                              = 81,  /* meta  */
    YYSYMBOL_strings                           = 82,  /* strings  */
    YYSYMBOL_condition                         = 83,  /* condition  */
    YYSYMBOL_rule_modifiers                    = 84,  /* rule_modifiers  */
    YYSYMBOL_rule_modifier                     = 85,  /* rule_modifier  */
    YYSYMBOL_tags                              = 86,  /* tags  */
    YYSYMBOL_tag_list                          = 87,  /* tag_list  */
    YYSYMBOL_meta_declarations                 = 88,  /* meta_declarations  */
    YYSYMBOL_meta_declaration                  = 89,  /* meta_declaration  */
    YYSYMBOL_string_declarations               = 90,  /* string_declarations  */
    YYSYMBOL_string_declaration                = 91,  /* string_declaration  */
    YYSYMBOL_92_1                              = 92,  /* $@1  */
    YYSYMBOL_string_modifiers                  = 93,  /* string_modifiers  */
    YYSYMBOL_string_modifier                   = 94,  /* string_modifier  */
    YYSYMBOL_hex_modifiers                     = 95,  /* hex_modifiers  */
    YYSYMBOL_hex_modifier                      = 96,  /* hex_modifier  */
    YYSYMBOL_identifier                        = 97,  /* identifier  */
    YYSYMBOL_arguments_list                    = 98,  /* arguments_list  */
    YYSYMBOL_regexp                            = 99,  /* regexp  */
    YYSYMBOL_boolean_expression                = 100, /* boolean_expression  */
    YYSYMBOL_expression                        = 101, /* expression  */
    YYSYMBOL_102_2                             = 102, /* $@2  */
    YYSYMBOL_103_3                             = 103, /* $@3  */
    YYSYMBOL_104_4                             = 104, /* $@4  */
    YYSYMBOL_integer_set                       = 105, /* integer_set  */
    YYSYMBOL_range                             = 106, /* range  */
    YYSYMBOL_integer_enumeration               = 107, /* integer_enumeration  */
    YYSYMBOL_string_set                        = 108, /* string_set  */
    YYSYMBOL_109_5                             = 109, /* $@5  */
    YYSYMBOL_string_enumeration                = 110, /* string_enumeration  */
    YYSYMBOL_string_enumeration_item           = 111, /* string_enumeration_item  */
    YYSYMBOL_for_expression                    = 112, /* for_expression  */
    YYSYMBOL_primary_expression                = 113  /* primary_expression  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;

#ifdef short
#undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
#include <limits.h> /* INFRINGES ON USER NAME SPACE */
#if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#define YY_STDINT_H
#endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants. See Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
#undef UINT_LEAST8_MAX
#undef UINT_LEAST16_MAX
#define UINT_LEAST8_MAX 255
#define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
#if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#define YYPTRDIFF_T __PTRDIFF_TYPE__
#define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
#elif defined PTRDIFF_MAX
#ifndef ptrdiff_t
#include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#endif
#define YYPTRDIFF_T ptrdiff_t
#define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
#else
#define YYPTRDIFF_T long
#define YYPTRDIFF_MAXIMUM LONG_MAX
#endif
#endif

#ifndef YYSIZE_T
#ifdef __SIZE_TYPE__
#define YYSIZE_T __SIZE_TYPE__
#elif defined size_t
#define YYSIZE_T size_t
#elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#define YYSIZE_T size_t
#else
#define YYSIZE_T unsigned
#endif
#endif

#define YYSIZE_MAXIMUM                                 \
    YY_CAST(YYPTRDIFF_T,                               \
            (YYPTRDIFF_MAXIMUM < YY_CAST(YYSIZE_T, -1) \
                 ? YYPTRDIFF_MAXIMUM                   \
                 : YY_CAST(YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST(YYPTRDIFF_T, sizeof(X))

/* Stored state numbers (used for stacks). */
typedef yytype_uint8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
#if defined YYENABLE_NLS && YYENABLE_NLS
#if ENABLE_NLS
#include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#define YY_(Msgid) dgettext("bison-runtime", Msgid)
#endif
#endif
#ifndef YY_
#define YY_(Msgid) Msgid
#endif
#endif

#ifndef YY_ATTRIBUTE_PURE
#if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#define YY_ATTRIBUTE_PURE __attribute__((__pure__))
#else
#define YY_ATTRIBUTE_PURE
#endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
#if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#define YY_ATTRIBUTE_UNUSED __attribute__((__unused__))
#else
#define YY_ATTRIBUTE_UNUSED
#endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if !defined lint || defined __GNUC__
#define YY_USE(E) ((void)(E))
#else
#define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && !defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
#if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma("GCC diagnostic push")          \
        _Pragma("GCC diagnostic ignored \"-Wuninitialized\"")
#else
#define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                   \
    _Pragma("GCC diagnostic push")                            \
        _Pragma("GCC diagnostic ignored \"-Wuninitialized\"") \
            _Pragma("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
#endif
#define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma("GCC diagnostic pop")
#else
#define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
#define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
#define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
#define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && !defined __ICC && 6 <= __GNUC__
#define YY_IGNORE_USELESS_CAST_BEGIN \
    _Pragma("GCC diagnostic push")   \
        _Pragma("GCC diagnostic ignored \"-Wuseless-cast\"")
#define YY_IGNORE_USELESS_CAST_END \
    _Pragma("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
#define YY_IGNORE_USELESS_CAST_BEGIN
#define YY_IGNORE_USELESS_CAST_END
#endif

#define YY_ASSERT(E) ((void)(0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

#ifdef YYSTACK_USE_ALLOCA
#if YYSTACK_USE_ALLOCA
#ifdef __GNUC__
#define YYSTACK_ALLOC __builtin_alloca
#elif defined __BUILTIN_VA_ARG_INCR
#include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#elif defined _AIX
#define YYSTACK_ALLOC __alloca
#elif defined _MSC_VER
#include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#define alloca _alloca
#else
#define YYSTACK_ALLOC alloca
#if !defined _ALLOCA_H && !defined EXIT_SUCCESS
#include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
/* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif
#endif
#endif
#endif
#endif

#ifdef YYSTACK_ALLOC
/* Pacify GCC's 'empty if-body' warning.  */
#define YYSTACK_FREE(Ptr) \
    do { /* empty */      \
        ;                 \
    } while (0)
#ifndef YYSTACK_ALLOC_MAXIMUM
/* The OS might guarantee only one guard page at the bottom of the stack,
   and a page size can be as small as 4096 bytes.  So we cannot safely
   invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
   to allow for a few compiler-allocated temporary stack slots.  */
#define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#endif
#else
#define YYSTACK_ALLOC YYMALLOC
#define YYSTACK_FREE YYFREE
#ifndef YYSTACK_ALLOC_MAXIMUM
#define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#endif
#if (defined __cplusplus && !defined EXIT_SUCCESS && !((defined YYMALLOC || defined malloc) && (defined YYFREE || defined free)))
#include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif
#endif
#ifndef YYMALLOC
#define YYMALLOC malloc
#if !defined malloc && !defined EXIT_SUCCESS
void *malloc(YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#endif
#endif
#ifndef YYFREE
#define YYFREE free
#if !defined free && !defined EXIT_SUCCESS
void free(void *);      /* INFRINGES ON USER NAME SPACE */
#endif
#endif
#endif
#endif /* !defined yyoverflow */

#if (!defined yyoverflow && (!defined __cplusplus || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc {
    yy_state_t yyss_alloc;
    YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
#define YYSTACK_GAP_MAXIMUM (YYSIZEOF(union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
#define YYSTACK_BYTES(N) \
    ((N) * (YYSIZEOF(yy_state_t) + YYSIZEOF(YYSTYPE)) + YYSTACK_GAP_MAXIMUM)

#define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
#define YYSTACK_RELOCATE(Stack_alloc, Stack)                               \
    do {                                                                   \
        YYPTRDIFF_T yynewbytes;                                            \
        YYCOPY(&yyptr->Stack_alloc, Stack, yysize);                        \
        Stack      = &yyptr->Stack_alloc;                                  \
        yynewbytes = yystacksize * YYSIZEOF(*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF(*yyptr);                            \
    } while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
#ifndef YYCOPY
#if defined __GNUC__ && 1 < __GNUC__
#define YYCOPY(Dst, Src, Count) \
    __builtin_memcpy(Dst, Src, YY_CAST(YYSIZE_T, (Count)) * sizeof(*(Src)))
#else
#define YYCOPY(Dst, Src, Count)             \
    do {                                    \
        YYPTRDIFF_T yyi;                    \
        for (yyi = 0; yyi < (Count); yyi++) \
            (Dst)[yyi] = (Src)[yyi];        \
    } while (0)
#endif
#endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL 2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST 440

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS 77
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS 37
/* YYNRULES -- Number of rules.  */
#define YYNRULES 126
/* YYNSTATES -- Number of states.  */
#define YYNSTATES 235

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK 312

/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                              \
    (0 <= (YYX) && (YYX) <= YYMAXUTOK                 \
         ? YY_CAST(yysymbol_kind_t, yytranslate[YYX]) \
         : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
    {
        0, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 63, 47, 2,
        71, 72, 61, 59, 76, 60, 73, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 69, 2,
        2, 70, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 74, 62, 75, 49, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 67, 48, 68, 65, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
        45, 46, 50, 51, 52, 53, 54, 55, 56, 57,
        58, 64, 66};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
    {
        0, 247, 247, 248, 249, 250, 251, 256, 268, 287,
        290, 320, 324, 352, 357, 358, 363, 364, 370, 373,
        393, 410, 449, 450, 455, 471, 484, 497, 514, 515,
        520, 534, 533, 550, 567, 568, 582, 583, 584, 585,
        586, 587, 588, 593, 598, 603, 609, 614, 624, 625,
        639, 644, 729, 779, 802, 842, 845, 867, 900, 947,
        965, 974, 983, 998, 1012, 1025, 1042, 1058, 1092, 1057,
        1203, 1202, 1278, 1284, 1290, 1296, 1304, 1313, 1322, 1331,
        1340, 1367, 1394, 1421, 1425, 1433, 1434, 1439, 1461, 1473,
        1489, 1488, 1494, 1506, 1507, 1512, 1517, 1526, 1527, 1534,
        1545, 1549, 1558, 1573, 1584, 1595, 1606, 1617, 1628, 1639,
        1648, 1675, 1688, 1703, 1725, 1760, 1769, 1778, 1787, 1796,
        1805, 1814, 1823, 1832, 1840, 1849, 1858};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST(yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char* yysymbol_name(yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char* const yytname[] =
    {
        "\"end of file\"", "error", "\"invalid token\"", "_RULE_", "_PRIVATE_",
        "_GLOBAL_", "_META_", "_STRINGS_", "_CONDITION_", "_IDENTIFIER_",
        "_STRING_IDENTIFIER_", "_STRING_COUNT_", "_STRING_OFFSET_",
        "_STRING_IDENTIFIER_WITH_WILDCARD_", "_NUMBER_", "_TEXT_STRING_",
        "_HEX_STRING_", "_REGEXP_", "_ASCII_", "_WIDE_", "_XOR_", "_BASE64_",
        "_BASE64_WIDE_", "_NOCASE_", "_FULLWORD_", "_AT_", "_FILESIZE_",
        "_ENTRYPOINT_", "_ALL_", "_ANY_", "_IN_", "_OF_", "_FOR_", "_THEM_",
        "_INT8_", "_INT16_", "_INT32_", "_UINT8_", "_UINT16_", "_UINT32_",
        "_MATCHES_", "_CONTAINS_", "_IMPORT_", "_TRUE_", "_FALSE_", "_OR_",
        "_AND_", "'&'", "'|'", "'^'", "_LT_", "_LE_", "_GT_", "_GE_", "_EQ_",
        "_NEQ_", "_IS_", "_SHIFT_LEFT_", "_SHIFT_RIGHT_", "'+'", "'-'", "'*'",
        "'\\\\'", "'%'", "_NOT_", "'~'", "\"include\"", "'{'", "'}'", "':'",
        "'='", "'('", "')'", "'.'", "'['", "']'", "','", "$accept", "rules",
        "import", "rule", "meta", "strings", "condition", "rule_modifiers",
        "rule_modifier", "tags", "tag_list", "meta_declarations",
        "meta_declaration", "string_declarations", "string_declaration", "$@1",
        "string_modifiers", "string_modifier", "hex_modifiers", "hex_modifier",
        "identifier", "arguments_list", "regexp", "boolean_expression",
        "expression", "$@2", "$@3", "$@4", "integer_set", "range",
        "integer_enumeration", "string_set", "$@5", "string_enumeration",
        "string_enumeration_item", "for_expression", "primary_expression", YY_NULLPTR};

static const char*
yysymbol_name(yysymbol_kind_t yysymbol)
{
    return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-67)

#define yypact_value_is_default(Yyn) \
    ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-98)

#define yytable_value_is_error(Yyn) \
    0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
    {
        -67, 5, -67, -28, -1, -67, -67, 113, -67, -67,
        -67, 35, -67, -67, -67, -21, 83, 34, -67, 100,
        115, -67, 55, 119, 120, 63, 114, 67, 120, -67,
        128, 70, 78, -3, -67, 79, 128, -67, 76, -67,
        -67, -67, -67, -67, 10, -67, -67, -7, -67, 74,
        -67, -67, -67, -67, -67, -67, -67, 116, 85, 86,
        87, 88, 89, 90, -67, -67, 76, 183, 76, -37,
        -67, 19, -67, 131, 218, -67, -67, 146, 183, 96,
        183, 183, 4, 377, 183, 183, 183, 183, 183, 183,
        -67, -67, 19, 97, 184, 76, 159, 183, 76, 76,
        -32, 153, 183, 183, 183, 183, 183, 183, 183, 183,
        183, 183, 183, 183, 183, 183, 183, 183, 183, 183,
        409, 169, -67, 377, 183, -67, 235, 264, 152, -32,
        271, 290, 297, 316, 323, 342, -67, -67, -55, 61,
        -67, 242, 138, -67, -67, -67, -67, -67, 377, 37,
        37, 37, 377, 377, 377, 377, 377, 377, 377, -4,
        -4, 73, 73, -67, -67, -67, -67, -67, -67, 118,
        125, 130, -67, -67, -67, -67, -67, 409, 117, -67,
        -67, 133, -67, -67, -67, -67, -67, -67, -67, 76,
        -67, 53, 171, 173, 188, 126, 134, -67, 61, -67,
        -67, -52, -67, -53, 132, 135, 183, 183, 137, -67,
        140, -67, 53, 172, -67, -67, -67, 349, -45, 117,
        -67, 76, -67, 136, -67, -67, 183, 141, -42, -67,
        377, 76, -67, -30, -67};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
    {
        2, 0, 1, 14, 0, 4, 3, 0, 6, 5,
        7, 0, 16, 17, 15, 18, 0, 0, 20, 19,
        9, 21, 0, 11, 0, 0, 0, 0, 10, 22,
        0, 0, 0, 0, 23, 0, 12, 28, 0, 8,
        25, 24, 26, 27, 31, 29, 51, 64, 111, 113,
        109, 110, 58, 101, 102, 98, 99, 0, 0, 0,
        0, 0, 0, 0, 60, 61, 0, 0, 0, 114,
        126, 13, 59, 0, 83, 34, 48, 0, 0, 0,
        0, 0, 0, 97, 0, 0, 0, 0, 0, 0,
        73, 123, 0, 59, 83, 55, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        30, 33, 34, 65, 0, 66, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 84, 100, 0, 56,
        52, 0, 75, 74, 92, 90, 72, 62, 63, 121,
        122, 120, 76, 78, 77, 79, 80, 82, 81, 124,
        125, 115, 116, 117, 118, 119, 40, 37, 36, 41,
        44, 46, 38, 39, 35, 50, 49, 32, 0, 112,
        67, 0, 103, 104, 105, 106, 107, 108, 54, 0,
        53, 0, 0, 0, 0, 0, 0, 70, 57, 95,
        96, 0, 93, 0, 0, 0, 0, 0, 0, 86,
        0, 91, 0, 0, 42, 45, 47, 0, 0, 88,
        68, 0, 94, 0, 87, 85, 0, 0, 0, 43,
        89, 0, 71, 0, 69};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
    {
        -67, -67, -67, 210, -67, -67, -67, -67, -67, -67,
        -67, -67, 186, -67, 180, -67, 101, -67, -67, -67,
        -67, -67, 127, -38, -66, -67, -67, -67, -67, 30,
        -67, 98, -67, -67, 17, 193, -35};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
    {
        0, 1, 5, 6, 23, 26, 32, 7, 14, 17,
        19, 28, 29, 36, 37, 77, 120, 174, 121, 176,
        69, 138, 70, 92, 72, 196, 227, 210, 208, 125,
        218, 146, 191, 201, 202, 73, 74};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
    {
        71, 144, 93, 98, 99, 2, 3, 213, -14, -14,
        -14, 40, 41, 128, 10, 98, 99, 188, 78, 214,
        211, 189, 83, 79, 212, 75, 76, 225, 90, 139,
        232, 226, 91, 94, 95, 129, 96, 97, 8, 145,
        42, 43, 234, 123, 15, 126, 127, 4, 16, 130,
        131, 132, 133, 134, 135, 115, 116, 117, 118, 119,
        142, 143, 141, 199, 98, 99, 200, 148, 149, 150,
        151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
        161, 162, 163, 164, 165, 46, 47, 48, 49, 178,
        50, 51, 18, 52, 113, 114, 115, 116, 117, 118,
        119, 20, 53, 54, 55, 56, -59, -59, 57, 21,
        58, 59, 60, 61, 62, 63, 11, 12, 13, 64,
        65, 22, 31, 198, 24, 46, 25, 48, 49, 27,
        50, 51, 30, 52, 117, 118, 119, 33, 35, 38,
        66, 67, 53, 54, 55, 56, 39, 68, 80, 44,
        58, 59, 60, 61, 62, 63, 84, 85, 86, 87,
        88, 89, 100, 122, 103, 104, 105, 124, 140, 136,
        52, 217, 219, 175, 113, 114, 115, 116, 117, 118,
        119, 67, 180, 228, 99, 203, 223, 81, 204, 192,
        195, 230, 46, 233, 48, 49, 193, 50, 51, 206,
        52, 194, 197, 205, 215, 207, 220, 216, 229, 53,
        54, 221, 231, 9, 34, -97, 45, 58, 59, 60,
        61, 62, 63, 177, 101, 102, 209, 181, 147, 222,
        0, 103, 104, 105, 106, 107, 108, 109, 110, 111,
        112, 113, 114, 115, 116, 117, 118, 119, 67, -97,
        82, 0, 0, 0, 81, 0, 137, 0, 101, 102,
        0, 0, 0, 0, 0, 103, 104, 105, 106, 107,
        108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
        118, 119, 103, 104, 105, 0, 0, 0, 0, 103,
        104, 105, 113, 114, 115, 116, 117, 118, 119, 113,
        114, 115, 116, 117, 118, 119, 0, 0, 0, 0,
        179, 103, 104, 105, 0, 0, 0, 190, 103, 104,
        105, 113, 114, 115, 116, 117, 118, 119, 113, 114,
        115, 116, 117, 118, 119, 0, 137, 103, 104, 105,
        0, 0, 0, 182, 103, 104, 105, 113, 114, 115,
        116, 117, 118, 119, 113, 114, 115, 116, 117, 118,
        119, 0, 183, 103, 104, 105, 0, 0, 0, 184,
        103, 104, 105, 113, 114, 115, 116, 117, 118, 119,
        113, 114, 115, 116, 117, 118, 119, 0, 185, 103,
        104, 105, 0, 0, 0, 186, 103, 104, 105, 113,
        114, 115, 116, 117, 118, 119, 113, 114, 115, 116,
        117, 118, 119, 166, 187, 0, 0, 0, 0, 0,
        0, 224, 0, 0, 103, 104, 105, 167, 168, 169,
        170, 171, 172, 173, 113, 114, 115, 116, 117, 118,
        119};

static const yytype_int16 yycheck[] =
    {
        38, 33, 68, 45, 46, 0, 1, 60, 3, 4,
        5, 14, 15, 9, 15, 45, 46, 72, 25, 72,
        72, 76, 57, 30, 76, 15, 16, 72, 66, 95,
        72, 76, 67, 68, 71, 31, 73, 74, 66, 71,
        43, 44, 72, 78, 9, 80, 81, 42, 69, 84,
        85, 86, 87, 88, 89, 59, 60, 61, 62, 63,
        98, 99, 97, 10, 45, 46, 13, 102, 103, 104,
        105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
        115, 116, 117, 118, 119, 9, 10, 11, 12, 124,
        14, 15, 9, 17, 57, 58, 59, 60, 61, 62,
        63, 67, 26, 27, 28, 29, 45, 46, 32, 9,
        34, 35, 36, 37, 38, 39, 3, 4, 5, 43,
        44, 6, 8, 189, 69, 9, 7, 11, 12, 9,
        14, 15, 69, 17, 61, 62, 63, 70, 10, 69,
        64, 65, 26, 27, 28, 29, 68, 71, 74, 70,
        34, 35, 36, 37, 38, 39, 71, 71, 71, 71,
        71, 71, 31, 17, 47, 48, 49, 71, 9, 72,
        17, 206, 207, 4, 57, 58, 59, 60, 61, 62,
        63, 65, 30, 221, 46, 14, 14, 71, 15, 71,
        73, 226, 9, 231, 11, 12, 71, 14, 15, 73,
        17, 71, 69, 15, 72, 71, 69, 72, 72, 26,
        27, 71, 71, 3, 28, 31, 36, 34, 35, 36,
        37, 38, 39, 122, 40, 41, 196, 129, 101, 212,
        -1, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63, 65, 31,
        57, -1, -1, -1, 71, -1, 72, -1, 40, 41,
        -1, -1, -1, -1, -1, 47, 48, 49, 50, 51,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
        62, 63, 47, 48, 49, -1, -1, -1, -1, 47,
        48, 49, 57, 58, 59, 60, 61, 62, 63, 57,
        58, 59, 60, 61, 62, 63, -1, -1, -1, -1,
        75, 47, 48, 49, -1, -1, -1, 75, 47, 48,
        49, 57, 58, 59, 60, 61, 62, 63, 57, 58,
        59, 60, 61, 62, 63, -1, 72, 47, 48, 49,
        -1, -1, -1, 72, 47, 48, 49, 57, 58, 59,
        60, 61, 62, 63, 57, 58, 59, 60, 61, 62,
        63, -1, 72, 47, 48, 49, -1, -1, -1, 72,
        47, 48, 49, 57, 58, 59, 60, 61, 62, 63,
        57, 58, 59, 60, 61, 62, 63, -1, 72, 47,
        48, 49, -1, -1, -1, 72, 47, 48, 49, 57,
        58, 59, 60, 61, 62, 63, 57, 58, 59, 60,
        61, 62, 63, 4, 72, -1, -1, -1, -1, -1,
        -1, 72, -1, -1, 47, 48, 49, 18, 19, 20,
        21, 22, 23, 24, 57, 58, 59, 60, 61, 62,
        63};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
    {
        0, 78, 0, 1, 42, 79, 80, 84, 66, 80,
        15, 3, 4, 5, 85, 9, 69, 86, 9, 87,
        67, 9, 6, 81, 69, 7, 82, 9, 88, 89,
        69, 8, 83, 70, 89, 10, 90, 91, 69, 68,
        14, 15, 43, 44, 70, 91, 9, 10, 11, 12,
        14, 15, 17, 26, 27, 28, 29, 32, 34, 35,
        36, 37, 38, 39, 43, 44, 64, 65, 71, 97,
        99, 100, 101, 112, 113, 15, 16, 92, 25, 30,
        74, 71, 112, 113, 71, 71, 71, 71, 71, 71,
        100, 113, 100, 101, 113, 71, 73, 74, 45, 46,
        31, 40, 41, 47, 48, 49, 50, 51, 52, 53,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        93, 95, 17, 113, 71, 106, 113, 113, 9, 31,
        113, 113, 113, 113, 113, 113, 72, 72, 98, 101,
        9, 113, 100, 100, 33, 71, 108, 99, 113, 113,
        113, 113, 113, 113, 113, 113, 113, 113, 113, 113,
        113, 113, 113, 113, 113, 113, 4, 18, 19, 20,
        21, 22, 23, 24, 94, 4, 96, 93, 113, 75,
        30, 108, 72, 72, 72, 72, 72, 72, 72, 76,
        75, 109, 71, 71, 71, 73, 102, 69, 101, 10,
        13, 110, 111, 14, 15, 15, 73, 71, 105, 106,
        104, 72, 76, 60, 72, 72, 72, 113, 107, 113,
        69, 71, 111, 14, 72, 72, 76, 103, 100, 72,
        113, 71, 72, 100, 72};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
    {
        0, 77, 78, 78, 78, 78, 78, 79, 80, 81,
        81, 82, 82, 83, 84, 84, 85, 85, 86, 86,
        87, 87, 88, 88, 89, 89, 89, 89, 90, 90,
        91, 92, 91, 91, 93, 93, 94, 94, 94, 94,
        94, 94, 94, 94, 94, 94, 94, 94, 95, 95,
        96, 97, 97, 97, 97, 98, 98, 98, 99, 100,
        101, 101, 101, 101, 101, 101, 101, 102, 103, 101,
        104, 101, 101, 101, 101, 101, 101, 101, 101, 101,
        101, 101, 101, 101, 101, 105, 105, 106, 107, 107,
        109, 108, 108, 110, 110, 111, 111, 112, 112, 112,
        113, 113, 113, 113, 113, 113, 113, 113, 113, 113,
        113, 113, 113, 113, 113, 113, 113, 113, 113, 113,
        113, 113, 113, 113, 113, 113, 113};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
    {
        0, 2, 0, 2, 2, 3, 3, 2, 9, 0,
        3, 0, 3, 3, 0, 2, 1, 1, 0, 2,
        1, 2, 1, 2, 3, 3, 3, 3, 1, 2,
        4, 0, 5, 4, 0, 2, 1, 1, 1, 1,
        1, 1, 4, 6, 1, 4, 1, 4, 0, 2,
        1, 1, 3, 4, 4, 0, 1, 3, 1, 1,
        1, 1, 3, 3, 1, 3, 3, 0, 0, 11,
        0, 9, 3, 2, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 1, 3, 3, 1, 6, 1, 3,
        0, 4, 1, 1, 3, 1, 1, 1, 1, 1,
        3, 1, 1, 4, 4, 4, 4, 4, 4, 1,
        1, 1, 4, 1, 1, 3, 3, 3, 3, 3,
        3, 3, 3, 2, 3, 3, 1};

enum { YYENOMEM = -2 };

#define yyerrok (yyerrstatus = 0)
#define yyclearin (yychar = YYEMPTY)

#define YYACCEPT goto yyacceptlab
#define YYABORT goto yyabortlab
#define YYERROR goto yyerrorlab
#define YYNOMEM goto yyexhaustedlab

#define YYRECOVERING() (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                                 \
    do                                                                         \
        if (yychar == YYEMPTY) {                                               \
            yychar = (Token);                                                  \
            yylval = (Value);                                                  \
            YYPOPSTACK(yylen);                                                 \
            yystate = *yyssp;                                                  \
            goto yybackup;                                                     \
        } else {                                                               \
            yyerror(yyscanner, compiler, YY_("syntax error: cannot back up")); \
            YYERROR;                                                           \
        }                                                                      \
    while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF

/* Enable debugging if requested.  */
#if YYDEBUG

#ifndef YYFPRINTF
#include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#define YYFPRINTF fprintf
#endif

#define YYDPRINTF(Args)     \
    do {                    \
        if (yydebug)        \
            YYFPRINTF Args; \
    } while (0)

#define YY_SYMBOL_PRINT(Title, Kind, Value, Location)          \
    do {                                                       \
        if (yydebug) {                                         \
            YYFPRINTF(stderr, "%s ", Title);                   \
            yy_symbol_print(stderr,                            \
                            Kind, Value, yyscanner, compiler); \
            YYFPRINTF(stderr, "\n");                           \
        }                                                      \
    } while (0)

/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print(FILE* yyo,
                      yysymbol_kind_t yykind, YYSTYPE const* const yyvaluep, void* yyscanner, YR_COMPILER* compiler)
{
    FILE* yyoutput = yyo;
    YY_USE(yyoutput);
    YY_USE(yyscanner);
    YY_USE(compiler);
    if (!yyvaluep)
        return;
    YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
    YY_USE(yykind);
    YY_IGNORE_MAYBE_UNINITIALIZED_END
}

/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print(FILE* yyo,
                yysymbol_kind_t yykind, YYSTYPE const* const yyvaluep, void* yyscanner, YR_COMPILER* compiler)
{
    YYFPRINTF(yyo, "%s %s (",
              yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name(yykind));

    yy_symbol_value_print(yyo, yykind, yyvaluep, yyscanner, compiler);
    YYFPRINTF(yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print(yy_state_t* yybottom, yy_state_t* yytop)
{
    YYFPRINTF(stderr, "Stack now");
    for (; yybottom <= yytop; yybottom++) {
        int yybot = *yybottom;
        YYFPRINTF(stderr, " %d", yybot);
    }
    YYFPRINTF(stderr, "\n");
}

#define YY_STACK_PRINT(Bottom, Top)          \
    do {                                     \
        if (yydebug)                         \
            yy_stack_print((Bottom), (Top)); \
    } while (0)

/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print(yy_state_t* yyssp, YYSTYPE* yyvsp,
                int yyrule, void* yyscanner, YR_COMPILER* compiler)
{
    int yylno  = yyrline[yyrule];
    int yynrhs = yyr2[yyrule];
    int yyi;
    YYFPRINTF(stderr, "Reducing stack by rule %d (line %d):\n",
              yyrule - 1, yylno);
    /* The symbols being reduced.  */
    for (yyi = 0; yyi < yynrhs; yyi++) {
        YYFPRINTF(stderr, "   $%d = ", yyi + 1);
        yy_symbol_print(stderr,
                        YY_ACCESSING_SYMBOL(+yyssp[yyi + 1 - yynrhs]),
                        &yyvsp[(yyi + 1) - (yynrhs)], yyscanner, compiler);
        YYFPRINTF(stderr, "\n");
    }
}

#define YY_REDUCE_PRINT(Rule)                                         \
    do {                                                              \
        if (yydebug)                                                  \
            yy_reduce_print(yyssp, yyvsp, Rule, yyscanner, compiler); \
    } while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
#define YYDPRINTF(Args) ((void)0)
#define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
#define YY_STACK_PRINT(Bottom, Top)
#define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */

/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
#define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct(const char* yymsg,
           yysymbol_kind_t yykind, YYSTYPE* yyvaluep, void* yyscanner, YR_COMPILER* compiler)
{
    YY_USE(yyvaluep);
    YY_USE(yyscanner);
    YY_USE(compiler);
    if (!yymsg)
        yymsg = "Deleting";
    YY_SYMBOL_PRINT(yymsg, yykind, yyvaluep, yylocationp);

    YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
    switch (yykind) {
        case YYSYMBOL__IDENTIFIER_: /* _IDENTIFIER_  */
#line 224 "yara_grammar.y"
        {
            yr_free(((*yyvaluep).c_string));
        }
#line 1214 "yara_grammar.c"
        break;

        case YYSYMBOL__STRING_IDENTIFIER_: /* _STRING_IDENTIFIER_  */
#line 225 "yara_grammar.y"
        {
            yr_free(((*yyvaluep).c_string));
        }
#line 1220 "yara_grammar.c"
        break;

        case YYSYMBOL__STRING_COUNT_: /* _STRING_COUNT_  */
#line 226 "yara_grammar.y"
        {
            yr_free(((*yyvaluep).c_string));
        }
#line 1226 "yara_grammar.c"
        break;

        case YYSYMBOL__STRING_OFFSET_: /* _STRING_OFFSET_  */
#line 227 "yara_grammar.y"
        {
            yr_free(((*yyvaluep).c_string));
        }
#line 1232 "yara_grammar.c"
        break;

        case YYSYMBOL__STRING_IDENTIFIER_WITH_WILDCARD_: /* _STRING_IDENTIFIER_WITH_WILDCARD_  */
#line 228 "yara_grammar.y"
        {
            yr_free(((*yyvaluep).c_string));
        }
#line 1238 "yara_grammar.c"
        break;

        case YYSYMBOL__TEXT_STRING_: /* _TEXT_STRING_  */
#line 229 "yara_grammar.y"
        {
            yr_free(((*yyvaluep).sized_string));
        }
#line 1244 "yara_grammar.c"
        break;

        case YYSYMBOL__HEX_STRING_: /* _HEX_STRING_  */
#line 230 "yara_grammar.y"
        {
            yr_free(((*yyvaluep).sized_string));
        }
#line 1250 "yara_grammar.c"
        break;

        case YYSYMBOL__REGEXP_: /* _REGEXP_  */
#line 231 "yara_grammar.y"
        {
            yr_free(((*yyvaluep).sized_string));
        }
#line 1256 "yara_grammar.c"
        break;

        default:
            break;
    }
    YY_IGNORE_MAYBE_UNINITIALIZED_END
}

/*----------.
| yyparse.  |
`----------*/

int yyparse(void* yyscanner, YR_COMPILER* compiler)
{
    /* Lookahead token kind.  */
    int yychar;

    /* The semantic value of the lookahead symbol.  */
    /* Default value used for initialization, for pacifying older GCCs
       or non-GCC compilers.  */
    YY_INITIAL_VALUE(static YYSTYPE yyval_default;)
    YYSTYPE yylval YY_INITIAL_VALUE(= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs = 0;

    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t* yyss  = yyssa;
    yy_state_t* yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE* yyvs  = yyvsa;
    YYSTYPE* yyvsp = yyvs;

    int yyn;
    /* The return value of yyparse.  */
    int yyresult;
    /* Lookahead symbol kind.  */
    yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
    /* The variables used to return semantic value and location from the
       action routines.  */
    YYSTYPE yyval;

#define YYPOPSTACK(N) (yyvsp -= (N), yyssp -= (N))

    /* The number of symbols on the RHS of the reduced rule.
       Keep to zero when no symbol should be popped.  */
    int yylen = 0;

    YYDPRINTF((stderr, "Starting parse\n"));

    yychar = YYEMPTY; /* Cause a token to be read.  */

    goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
    /* In all cases, when you get here, the value and location stacks
       have just been pushed.  So pushing a state here evens the stacks.  */
    yyssp++;

/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
    YYDPRINTF((stderr, "Entering state %d\n", yystate));
    YY_ASSERT(0 <= yystate && yystate < YYNSTATES);
    YY_IGNORE_USELESS_CAST_BEGIN
    *yyssp = YY_CAST(yy_state_t, yystate);
    YY_IGNORE_USELESS_CAST_END
    YY_STACK_PRINT(yyss, yyssp);

    if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
        YYNOMEM;
#else
    {
        /* Get the current used size of the three stacks, in elements.  */
        YYPTRDIFF_T yysize = yyssp - yyss + 1;

#if defined yyoverflow
        {
            /* Give user a chance to reallocate the stack.  Use copies of
               these so that the &'s don't force the real ones into
               memory.  */
            yy_state_t* yyss1 = yyss;
            YYSTYPE* yyvs1    = yyvs;

            /* Each stack pointer address is followed by the size of the
               data in use in that stack, in bytes.  This used to be a
               conditional around just the two extra args, but that might
               be undefined if yyoverflow is a macro.  */
            yyoverflow(YY_("memory exhausted"),
                       &yyss1, yysize * YYSIZEOF(*yyssp),
                       &yyvs1, yysize * YYSIZEOF(*yyvsp),
                       &yystacksize);
            yyss = yyss1;
            yyvs = yyvs1;
        }
#else /* defined YYSTACK_RELOCATE */
        /* Extend the stack our own way.  */
        if (YYMAXDEPTH <= yystacksize)
            YYNOMEM;
        yystacksize *= 2;
        if (YYMAXDEPTH < yystacksize)
            yystacksize = YYMAXDEPTH;

        {
            yy_state_t* yyss1 = yyss;
            union yyalloc* yyptr =
                YY_CAST(union yyalloc*,
                        YYSTACK_ALLOC(YY_CAST(YYSIZE_T, YYSTACK_BYTES(yystacksize))));
            if (!yyptr)
                YYNOMEM;
            YYSTACK_RELOCATE(yyss_alloc, yyss);
            YYSTACK_RELOCATE(yyvs_alloc, yyvs);
#undef YYSTACK_RELOCATE
            if (yyss1 != yyssa)
                YYSTACK_FREE(yyss1);
        }
#endif

        yyssp = yyss + yysize - 1;
        yyvsp = yyvs + yysize - 1;

        YY_IGNORE_USELESS_CAST_BEGIN
        YYDPRINTF((stderr, "Stack size increased to %ld\n",
                   YY_CAST(long, yystacksize)));
        YY_IGNORE_USELESS_CAST_END

        if (yyss + yystacksize - 1 <= yyssp)
            YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

    if (yystate == YYFINAL)
        YYACCEPT;

    goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:
    /* Do appropriate processing given the current state.  Read a
       lookahead token if we need one and don't already have one.  */

    /* First try to decide what to do without reference to lookahead token.  */
    yyn = yypact[yystate];
    if (yypact_value_is_default(yyn))
        goto yydefault;

    /* Not known => get a lookahead token if don't already have one.  */

    /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
    if (yychar == YYEMPTY) {
        YYDPRINTF((stderr, "Reading a token\n"));
        yychar = yylex(&yylval, yyscanner, compiler);
    }

    if (yychar <= YYEOF) {
        yychar  = YYEOF;
        yytoken = YYSYMBOL_YYEOF;
        YYDPRINTF((stderr, "Now at end of input.\n"));
    } else if (yychar == YYerror) {
        /* The scanner already issued an error message, process directly
           to error recovery.  But do not keep the error token as
           lookahead, it is too special and may lead us to an endless
           loop in error recovery. */
        yychar  = YYUNDEF;
        yytoken = YYSYMBOL_YYerror;
        goto yyerrlab1;
    } else {
        yytoken = YYTRANSLATE(yychar);
        YY_SYMBOL_PRINT("Next token is", yytoken, &yylval, &yylloc);
    }

    /* If the proper action on seeing token YYTOKEN is to reduce or to
       detect an error, take that action.  */
    yyn += yytoken;
    if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
        goto yydefault;
    yyn = yytable[yyn];
    if (yyn <= 0) {
        if (yytable_value_is_error(yyn))
            goto yyerrlab;
        yyn = -yyn;
        goto yyreduce;
    }

    /* Count tokens shifted since error; after three, turn off error
       status.  */
    if (yyerrstatus)
        yyerrstatus--;

    /* Shift the lookahead token.  */
    YY_SYMBOL_PRINT("Shifting", yytoken, &yylval, &yylloc);
    yystate = yyn;
    YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
    *++yyvsp = yylval;
    YY_IGNORE_MAYBE_UNINITIALIZED_END

    /* Discard the shifted token.  */
    yychar = YYEMPTY;
    goto yynewstate;

/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
    yyn = yydefact[yystate];
    if (yyn == 0)
        goto yyerrlab;
    goto yyreduce;

/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
    /* yyn is the number of a rule to reduce with.  */
    yylen = yyr2[yyn];

    /* If YYLEN is nonzero, implement the default value of the action:
       '$$ = $1'.

       Otherwise, the following line sets YYVAL to garbage.
       This behavior is undocumented and Bison
       users should not rely upon it.  Assigning to YYVAL
       unconditionally makes the parser a bit smaller, and it avoids a
       GCC warning that YYVAL may be used uninitialized.  */
    yyval = yyvsp[1 - yylen];

    YY_REDUCE_PRINT(yyn);
    switch (yyn) {
        case 7: /* import: _IMPORT_ _TEXT_STRING_  */
#line 257 "yara_grammar.y"
        {
            int result = yr_parser_reduce_import(yyscanner, (yyvsp[0].sized_string));

            yr_free((yyvsp[0].sized_string));

            ERROR_IF(result != ERROR_SUCCESS);
        }
#line 1538 "yara_grammar.c"
        break;

        case 8: /* rule: rule_modifiers _RULE_ _IDENTIFIER_ tags '{' meta strings condition '}'  */
#line 269 "yara_grammar.y"
        {
            int result = yr_parser_reduce_rule_declaration(
                yyscanner,
                (yyvsp[-8].integer),
                (yyvsp[-6].c_string),
                (yyvsp[-5].c_string),
                (yyvsp[-2].string),
                (yyvsp[-3].meta));

            yr_free((yyvsp[-6].c_string));

            ERROR_IF(result != ERROR_SUCCESS);
        }
#line 1556 "yara_grammar.c"
        break;

        case 9: /* meta: %empty  */
#line 287 "yara_grammar.y"
        {
            (yyval.meta) = NULL;
        }
#line 1564 "yara_grammar.c"
        break;

        case 10: /* meta: _META_ ':' meta_declarations  */
#line 291 "yara_grammar.y"
        {
#if REAL_YARA // Meta not supported
            // Each rule have a list of meta-data info, consisting in a
            // sequence of YR_META structures. The last YR_META structure does
            // not represent a real meta-data, it's just an end-of-list marker
            // identified by a specific type (META_TYPE_NULL). Here we
            // write the end-of-list marker.

            YR_META null_meta;

            memset(&null_meta, 0xFF, sizeof(YR_META));
            null_meta.type = META_TYPE_NULL;

            compiler->last_result = yr_arena_write_data(
                compiler->metas_arena,
                &null_meta,
                sizeof(YR_META),
                NULL);

#endif
            (yyval.meta) = (yyvsp[0].meta);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 1593 "yara_grammar.c"
        break;

        case 11: /* strings: %empty  */
#line 320 "yara_grammar.y"
        {
            (yyval.string)                 = NULL;
            compiler->current_rule_strings = (yyval.string);
        }
#line 1602 "yara_grammar.c"
        break;

        case 12: /* strings: _STRINGS_ ':' string_declarations  */
#line 325 "yara_grammar.y"
        {
            // Each rule have a list of strings, consisting in a sequence
            // of YR_STRING structures. The last YR_STRING structure does not
            // represent a real string, it's just an end-of-list marker
            // identified by a specific flag (STRING_FLAGS_NULL). Here we
            // write the end-of-list marker.

            YR_STRING null_string;

            memset(&null_string, 0xFF, sizeof(YR_STRING));
            null_string.g_flags = STRING_GFLAGS_NULL;

            compiler->last_result = yr_arena_write_data(
                compiler->strings_arena,
                &null_string,
                sizeof(YR_STRING),
                NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            compiler->current_rule_strings = (yyvsp[0].string);
            (yyval.string)                 = (yyvsp[0].string);
        }
#line 1630 "yara_grammar.c"
        break;

        case 14: /* rule_modifiers: %empty  */
#line 357 "yara_grammar.y"
        {
            (yyval.integer) = 0;
        }
#line 1636 "yara_grammar.c"
        break;

        case 15: /* rule_modifiers: rule_modifiers rule_modifier  */
#line 358 "yara_grammar.y"
        {
            (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer);
        }
#line 1642 "yara_grammar.c"
        break;

        case 16: /* rule_modifier: _PRIVATE_  */
#line 363 "yara_grammar.y"
        {
            (yyval.integer) = RULE_GFLAGS_PRIVATE;
        }
#line 1648 "yara_grammar.c"
        break;

        case 17: /* rule_modifier: _GLOBAL_  */
#line 364 "yara_grammar.y"
        {
            (yyval.integer) = RULE_GFLAGS_GLOBAL;
        }
#line 1654 "yara_grammar.c"
        break;

        case 18: /* tags: %empty  */
#line 370 "yara_grammar.y"
        {
            (yyval.c_string) = NULL;
        }
#line 1662 "yara_grammar.c"
        break;

        case 19: /* tags: ':' tag_list  */
#line 374 "yara_grammar.y"
        {
#if REAL_YARA // tags not supported
            // Tags list is represented in the arena as a sequence
            // of null-terminated strings, the sequence ends with an
            // additional null character. Here we write the ending null
            // character. Example: tag1\0tag2\0tag3\0\0

            compiler->last_result = yr_arena_write_string(
                yyget_extra(yyscanner)->sz_arena, "", NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
#endif

            (yyval.c_string) = (yyvsp[0].c_string);
        }
#line 1682 "yara_grammar.c"
        break;

        case 20: /* tag_list: _IDENTIFIER_  */
#line 394 "yara_grammar.y"
        {
#if REAL_YARA // tags not supported
            char* identifier;

            compiler->last_result = yr_arena_write_string(
                yyget_extra(yyscanner)->sz_arena, (yyvsp[0].c_string), &identifier);

#endif
            yr_free((yyvsp[0].c_string));

#if REAL_YARA // tags not supported
            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.c_string) = identifier;
#endif
        }
#line 1703 "yara_grammar.c"
        break;

        case 21: /* tag_list: tag_list _IDENTIFIER_  */
#line 411 "yara_grammar.y"
        {
#if REAL_YARA // tags not supported
            char* tag_name    = (yyvsp[-1].c_string);
            size_t tag_length = tag_name != NULL ? strlen(tag_name) : 0;

            while (tag_length > 0) {
                if (strcmp(tag_name, (yyvsp[0].c_string)) == 0) {
                    yr_compiler_set_error_extra_info(compiler, tag_name);
                    compiler->last_result = ERROR_DUPLICATE_TAG_IDENTIFIER;
                    break;
                }

                tag_name = yr_arena_next_address(
                    yyget_extra(yyscanner)->sz_arena,
                    tag_name,
                    tag_length + 1);

                tag_length = tag_name != NULL ? strlen(tag_name) : 0;
            }

            if (compiler->last_result == ERROR_SUCCESS)
                compiler->last_result = yr_arena_write_string(
                    yyget_extra(yyscanner)->sz_arena, (yyvsp[0].c_string), NULL);

#endif
            yr_free((yyvsp[0].c_string));

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.c_string) = (yyvsp[-1].c_string);
        }
#line 1741 "yara_grammar.c"
        break;

        case 22: /* meta_declarations: meta_declaration  */
#line 449 "yara_grammar.y"
        {
            (yyval.meta) = (yyvsp[0].meta);
        }
#line 1747 "yara_grammar.c"
        break;

        case 23: /* meta_declarations: meta_declarations meta_declaration  */
#line 450 "yara_grammar.y"
        {
            (yyval.meta) = (yyvsp[-1].meta);
        }
#line 1753 "yara_grammar.c"
        break;

        case 24: /* meta_declaration: _IDENTIFIER_ '=' _TEXT_STRING_  */
#line 456 "yara_grammar.y"
        {
            SIZED_STRING* sized_string = (yyvsp[0].sized_string);

            (yyval.meta) = yr_parser_reduce_meta_declaration(
                yyscanner,
                META_TYPE_STRING,
                (yyvsp[-2].c_string),
                sized_string->c_string,
                0);

            yr_free((yyvsp[-2].c_string));
            yr_free((yyvsp[0].sized_string));

            ERROR_IF((yyval.meta) == NULL);
        }
#line 1773 "yara_grammar.c"
        break;

        case 25: /* meta_declaration: _IDENTIFIER_ '=' _NUMBER_  */
#line 472 "yara_grammar.y"
        {
            (yyval.meta) = yr_parser_reduce_meta_declaration(
                yyscanner,
                META_TYPE_INTEGER,
                (yyvsp[-2].c_string),
                NULL,
                (yyvsp[0].integer));

            yr_free((yyvsp[-2].c_string));

            ERROR_IF((yyval.meta) == NULL);
        }
#line 1790 "yara_grammar.c"
        break;

        case 26: /* meta_declaration: _IDENTIFIER_ '=' _TRUE_  */
#line 485 "yara_grammar.y"
        {
            (yyval.meta) = yr_parser_reduce_meta_declaration(
                yyscanner,
                META_TYPE_BOOLEAN,
                (yyvsp[-2].c_string),
                NULL,
                TRUE);

            yr_free((yyvsp[-2].c_string));

            ERROR_IF((yyval.meta) == NULL);
        }
#line 1807 "yara_grammar.c"
        break;

        case 27: /* meta_declaration: _IDENTIFIER_ '=' _FALSE_  */
#line 498 "yara_grammar.y"
        {
            (yyval.meta) = yr_parser_reduce_meta_declaration(
                yyscanner,
                META_TYPE_BOOLEAN,
                (yyvsp[-2].c_string),
                NULL,
                FALSE);

            yr_free((yyvsp[-2].c_string));

            ERROR_IF((yyval.meta) == NULL);
        }
#line 1824 "yara_grammar.c"
        break;

        case 28: /* string_declarations: string_declaration  */
#line 514 "yara_grammar.y"
        {
            (yyval.string) = (yyvsp[0].string);
        }
#line 1830 "yara_grammar.c"
        break;

        case 29: /* string_declarations: string_declarations string_declaration  */
#line 515 "yara_grammar.y"
        {
            (yyval.string) = (yyvsp[-1].string);
        }
#line 1836 "yara_grammar.c"
        break;

        case 30: /* string_declaration: _STRING_IDENTIFIER_ '=' _TEXT_STRING_ string_modifiers  */
#line 521 "yara_grammar.y"
        {
            (yyval.string) = yr_parser_reduce_string_declaration(
                yyscanner,
                (yyvsp[0].integer),
                (yyvsp[-3].c_string),
                (yyvsp[-1].sized_string));

            yr_free((yyvsp[-3].c_string));
            yr_free((yyvsp[-1].sized_string));

            ERROR_IF((yyval.string) == NULL);
        }
#line 1853 "yara_grammar.c"
        break;

        case 31: /* $@1: %empty  */
#line 534 "yara_grammar.y"
        {
            compiler->error_line = yyget_lineno(yyscanner);
        }
#line 1861 "yara_grammar.c"
        break;

        case 32: /* string_declaration: _STRING_IDENTIFIER_ '=' $@1 _REGEXP_ string_modifiers  */
#line 538 "yara_grammar.y"
        {
            (yyval.string) = yr_parser_reduce_string_declaration(
                yyscanner,
                (yyvsp[0].integer) | STRING_GFLAGS_REGEXP,
                (yyvsp[-4].c_string),
                (yyvsp[-1].sized_string));

            yr_free((yyvsp[-4].c_string));
            yr_free((yyvsp[-1].sized_string));

            ERROR_IF((yyval.string) == NULL);
        }
#line 1878 "yara_grammar.c"
        break;

        case 33: /* string_declaration: _STRING_IDENTIFIER_ '=' _HEX_STRING_ hex_modifiers  */
#line 551 "yara_grammar.y"
        {
            (yyval.string) = yr_parser_reduce_string_declaration(
                yyscanner,
                (yyvsp[0].integer) | STRING_GFLAGS_HEXADECIMAL,
                (yyvsp[-3].c_string),
                (yyvsp[-1].sized_string));

            yr_free((yyvsp[-3].c_string));
            yr_free((yyvsp[-1].sized_string));

            ERROR_IF((yyval.string) == NULL);
        }
#line 1895 "yara_grammar.c"
        break;

        case 34: /* string_modifiers: %empty  */
#line 567 "yara_grammar.y"
        {
            (yyval.integer) = 0;
        }
#line 1901 "yara_grammar.c"
        break;

        case 35: /* string_modifiers: string_modifiers string_modifier  */
#line 569 "yara_grammar.y"
        {
            if ((yyvsp[-1].integer) & (yyvsp[0].integer)) {
                compiler->last_result = ERROR_DUPLICATED_MODIFIER;
                ERROR_IF(compiler->last_result != ERROR_SUCCESS);
            }

            (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer);
        }
#line 1915 "yara_grammar.c"
        break;

        case 36: /* string_modifier: _WIDE_  */
#line 582 "yara_grammar.y"
        {
            (yyval.integer) = STRING_GFLAGS_WIDE;
        }
#line 1921 "yara_grammar.c"
        break;

        case 37: /* string_modifier: _ASCII_  */
#line 583 "yara_grammar.y"
        {
            (yyval.integer) = STRING_GFLAGS_ASCII;
        }
#line 1927 "yara_grammar.c"
        break;

        case 38: /* string_modifier: _NOCASE_  */
#line 584 "yara_grammar.y"
        {
            (yyval.integer) = STRING_GFLAGS_NO_CASE;
        }
#line 1933 "yara_grammar.c"
        break;

        case 39: /* string_modifier: _FULLWORD_  */
#line 585 "yara_grammar.y"
        {
            (yyval.integer) = STRING_GFLAGS_FULL_WORD;
        }
#line 1939 "yara_grammar.c"
        break;

        case 40: /* string_modifier: _PRIVATE_  */
#line 586 "yara_grammar.y"
        {
            (yyval.integer) = STRING_GFLAGS_PRIVATE;
        }
#line 1945 "yara_grammar.c"
        break;

        case 41: /* string_modifier: _XOR_  */
#line 587 "yara_grammar.y"
        {
            (yyval.integer) = 0;
            UNSUPPORTED_STRING_MODIFIER("xor");
        }
#line 1951 "yara_grammar.c"
        break;

        case 42: /* string_modifier: _XOR_ '(' _NUMBER_ ')'  */
#line 589 "yara_grammar.y"
        {
            (yyval.integer) = 0;
            UNSUPPORTED_STRING_MODIFIER("xor");
        }
#line 1960 "yara_grammar.c"
        break;

        case 43: /* string_modifier: _XOR_ '(' _NUMBER_ '-' _NUMBER_ ')'  */
#line 594 "yara_grammar.y"
        {
            (yyval.integer) = 0;
            UNSUPPORTED_STRING_MODIFIER("xor");
        }
#line 1969 "yara_grammar.c"
        break;

        case 44: /* string_modifier: _BASE64_  */
#line 599 "yara_grammar.y"
        {
            (yyval.integer) = 0;
            UNSUPPORTED_STRING_MODIFIER("base64");
        }
#line 1978 "yara_grammar.c"
        break;

        case 45: /* string_modifier: _BASE64_ '(' _TEXT_STRING_ ')'  */
#line 604 "yara_grammar.y"
        {
            yr_free((yyvsp[-1].sized_string));
            (yyval.integer) = 0;
            UNSUPPORTED_STRING_MODIFIER("base64");
        }
#line 1988 "yara_grammar.c"
        break;

        case 46: /* string_modifier: _BASE64_WIDE_  */
#line 610 "yara_grammar.y"
        {
            (yyval.integer) = 0;
            UNSUPPORTED_STRING_MODIFIER("base64wide");
        }
#line 1997 "yara_grammar.c"
        break;

        case 47: /* string_modifier: _BASE64_WIDE_ '(' _TEXT_STRING_ ')'  */
#line 615 "yara_grammar.y"
        {
            yr_free((yyvsp[-1].sized_string));
            (yyval.integer) = 0;
            UNSUPPORTED_STRING_MODIFIER("base64wide");
        }
#line 2007 "yara_grammar.c"
        break;

        case 48: /* hex_modifiers: %empty  */
#line 624 "yara_grammar.y"
        {
            (yyval.integer) = 0;
        }
#line 2013 "yara_grammar.c"
        break;

        case 49: /* hex_modifiers: hex_modifiers hex_modifier  */
#line 626 "yara_grammar.y"
        {
            if ((yyvsp[-1].integer) & (yyvsp[0].integer)) {
                compiler->last_result = ERROR_DUPLICATED_MODIFIER;
                ERROR_IF(compiler->last_result != ERROR_SUCCESS);
            }

            (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer);
        }
#line 2027 "yara_grammar.c"
        break;

        case 50: /* hex_modifier: _PRIVATE_  */
#line 639 "yara_grammar.y"
        {
            (yyval.integer) = STRING_GFLAGS_PRIVATE;
        }
#line 2033 "yara_grammar.c"
        break;

        case 51: /* identifier: _IDENTIFIER_  */
#line 645 "yara_grammar.y"
        {
            YR_OBJECT* object = NULL;
            YR_RULE* rule;

            char* id;
            char* ns = NULL;

            int var_index;

            var_index = yr_parser_lookup_loop_variable(yyscanner, (yyvsp[0].c_string));

            if (var_index >= 0) {
                compiler->last_result = yr_parser_emit_with_arg(
                    yyscanner,
                    OP_PUSH_M,
                    LOOP_LOCAL_VARS * var_index,
                    NULL);

                (yyval.object) = (YR_OBJECT*)-1;
            } else {
                // Search for identifier within the global namespace, where the
                // externals variables reside.
                object = (YR_OBJECT*)yr_hash_table_lookup(
                    compiler->objects_table,
                    (yyvsp[0].c_string),
                    NULL);
                if (object == NULL) {
                    // If not found, search within the current namespace.

                    ns     = compiler->current_namespace->name;
                    object = (YR_OBJECT*)yr_hash_table_lookup(
                        compiler->objects_table,
                        (yyvsp[0].c_string),
                        ns);
                }

                if (object != NULL) {
                    compiler->last_result = yr_arena_write_string(
                        compiler->sz_arena,
                        (yyvsp[0].c_string),
                        &id);

                    if (compiler->last_result == ERROR_SUCCESS)
                        compiler->last_result = yr_parser_emit_with_arg_reloc(
                            yyscanner,
                            OP_OBJ_LOAD,
                            PTR_TO_UINT64(id),
                            NULL);

                    (yyval.object) = object;
                } else {
                    rule = (YR_RULE*)yr_hash_table_lookup(
                        compiler->rules_table,
                        (yyvsp[0].c_string),
                        compiler->current_namespace->name);
                    if (rule != NULL) {
                        compiler->last_result = yr_parser_emit_with_arg_reloc(
                            yyscanner,
                            OP_PUSH_RULE,
                            PTR_TO_UINT64(rule),
                            NULL);
                    } else {
                        yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
                        compiler->last_result = ERROR_UNDEFINED_IDENTIFIER;
                    }

                    (yyval.object) = (YR_OBJECT*)-2;
                }
            }

            yr_free((yyvsp[0].c_string));

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 2122 "yara_grammar.c"
        break;

        case 52: /* identifier: identifier '.' _IDENTIFIER_  */
#line 730 "yara_grammar.y"
        {
            YR_OBJECT* object = (yyvsp[-2].object);
            YR_OBJECT* field  = NULL;

            char* ident;

            if (object != NULL &&
                object != (YR_OBJECT*)-1 && // not a loop variable identifier
                object != (YR_OBJECT*)-2 && // not a rule identifier
                object->type == OBJECT_TYPE_STRUCTURE) {
#if REAL_YARA
                field = yr_object_lookup_field(object, (yyvsp[0].c_string));
#endif
                if (field != NULL) {
                    compiler->last_result = yr_arena_write_string(
                        compiler->sz_arena,
                        (yyvsp[0].c_string),
                        &ident);

                    if (compiler->last_result == ERROR_SUCCESS)
                        compiler->last_result = yr_parser_emit_with_arg_reloc(
                            yyscanner,
                            OP_OBJ_FIELD,
                            PTR_TO_UINT64(ident),
                            NULL);
                } else {
                    yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
                    compiler->last_result = ERROR_INVALID_FIELD_NAME;
                }
            } else {
                yr_compiler_set_error_extra_info(
                    compiler,
                    object->identifier);

                compiler->last_result = ERROR_NOT_A_STRUCTURE;
            }

            (yyval.object) = field;

            yr_free((yyvsp[0].c_string));

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 2176 "yara_grammar.c"
        break;

        case 53: /* identifier: identifier '[' primary_expression ']'  */
#line 780 "yara_grammar.y"
        {
            if ((yyvsp[-3].object) != NULL && (yyvsp[-3].object)->type == OBJECT_TYPE_ARRAY) {
                compiler->last_result = yr_parser_emit(
                    yyscanner,
                    OP_INDEX_ARRAY,
                    NULL);

                (yyval.object) = ((YR_OBJECT_ARRAY*)(yyvsp[-3].object))->items->objects[0];
            } else {
                yr_compiler_set_error_extra_info(
                    compiler,
                    (yyvsp[-3].object)->identifier);

                compiler->last_result = ERROR_NOT_AN_ARRAY;
            }

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 2202 "yara_grammar.c"
        break;

        case 54: /* identifier: identifier '(' arguments_list ')'  */
#line 803 "yara_grammar.y"
        {
            int args_count;

            if ((yyvsp[-3].object) != NULL && (yyvsp[-3].object)->type == OBJECT_TYPE_FUNCTION) {
                compiler->last_result = yr_parser_check_types(
                    compiler, (YR_OBJECT_FUNCTION*)(yyvsp[-3].object), (yyvsp[-1].c_string));

                if (compiler->last_result == ERROR_SUCCESS) {
                    args_count = strlen((yyvsp[-1].c_string));

                    compiler->last_result = yr_parser_emit_with_arg(
                        yyscanner,
                        OP_CALL,
                        args_count,
                        NULL);
                }

                (yyval.object) = ((YR_OBJECT_FUNCTION*)(yyvsp[-3].object))->return_obj;
            } else {
                yr_compiler_set_error_extra_info(
                    compiler,
                    (yyvsp[-3].object)->identifier);

                compiler->last_result = ERROR_NOT_A_FUNCTION;
            }

            yr_free((yyvsp[-1].c_string));

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 2241 "yara_grammar.c"
        break;

        case 55: /* arguments_list: %empty  */
#line 842 "yara_grammar.y"
        {
            (yyval.c_string) = yr_strdup("");
        }
#line 2249 "yara_grammar.c"
        break;

        case 56: /* arguments_list: expression  */
#line 846 "yara_grammar.y"
        {
            (yyval.c_string) = yr_malloc(MAX_FUNCTION_ARGS + 1);

            switch ((yyvsp[0].expression_type)) {
                case EXPRESSION_TYPE_INTEGER:
                    strlcpy((yyval.c_string), "i", MAX_FUNCTION_ARGS);
                    break;
                case EXPRESSION_TYPE_BOOLEAN:
                    strlcpy((yyval.c_string), "b", MAX_FUNCTION_ARGS);
                    break;
                case EXPRESSION_TYPE_STRING:
                    strlcpy((yyval.c_string), "s", MAX_FUNCTION_ARGS);
                    break;
                case EXPRESSION_TYPE_REGEXP:
                    strlcpy((yyval.c_string), "r", MAX_FUNCTION_ARGS);
                    break;
            }

            ERROR_IF((yyval.c_string) == NULL);
        }
#line 2275 "yara_grammar.c"
        break;

        case 57: /* arguments_list: arguments_list ',' expression  */
#line 868 "yara_grammar.y"
        {
            if (strlen((yyvsp[-2].c_string)) == MAX_FUNCTION_ARGS) {
                compiler->last_result = ERROR_TOO_MANY_ARGUMENTS;
            } else {
                switch ((yyvsp[0].expression_type)) {
                    case EXPRESSION_TYPE_INTEGER:
                        strlcat((yyvsp[-2].c_string), "i", MAX_FUNCTION_ARGS);
                        break;
                    case EXPRESSION_TYPE_BOOLEAN:
                        strlcat((yyvsp[-2].c_string), "b", MAX_FUNCTION_ARGS);
                        break;
                    case EXPRESSION_TYPE_STRING:
                        strlcat((yyvsp[-2].c_string), "s", MAX_FUNCTION_ARGS);
                        break;
                    case EXPRESSION_TYPE_REGEXP:
                        strlcat((yyvsp[-2].c_string), "r", MAX_FUNCTION_ARGS);
                        break;
                }
            }

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.c_string) = (yyvsp[-2].c_string);
        }
#line 2308 "yara_grammar.c"
        break;

        case 58: /* regexp: _REGEXP_  */
#line 901 "yara_grammar.y"
        {
#ifdef REAL_YARA
            SIZED_STRING* sized_string = (yyvsp[0].sized_string);
            RE* re;
            RE_ERROR error;

            int re_flags = 0;

            if (sized_string->flags & SIZED_STRING_FLAGS_NO_CASE)
                re_flags |= RE_FLAGS_NO_CASE;

            if (sized_string->flags & SIZED_STRING_FLAGS_DOT_ALL)
                re_flags |= RE_FLAGS_DOT_ALL;

            compiler->last_result = yr_re_compile(
                sized_string->c_string,
                re_flags,
                compiler->re_code_arena,
                &re,
                &error);

            yr_free((yyvsp[0].sized_string));

            if (compiler->last_result == ERROR_INVALID_REGULAR_EXPRESSION)
                yr_compiler_set_error_extra_info(compiler, error.message);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            if (compiler->last_result == ERROR_SUCCESS)
                compiler->last_result = yr_parser_emit_with_arg_reloc(
                    yyscanner,
                    OP_PUSH,
                    PTR_TO_UINT64(re->root_node->forward_code),
                    NULL);

            yr_re_destroy(re);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
#endif

            (yyval.expression_type) = EXPRESSION_TYPE_REGEXP;
        }
#line 2355 "yara_grammar.c"
        break;

        case 59: /* boolean_expression: expression  */
#line 948 "yara_grammar.y"
        {
            if ((yyvsp[0].expression_type) == EXPRESSION_TYPE_STRING) {
                compiler->last_result = yr_parser_emit(
                    yyscanner,
                    OP_SZ_TO_BOOL,
                    NULL);

                ERROR_IF(compiler->last_result != ERROR_SUCCESS);
            }

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2374 "yara_grammar.c"
        break;

        case 60: /* expression: _TRUE_  */
#line 966 "yara_grammar.y"
        {
            compiler->last_result = yr_parser_emit_with_arg(
                yyscanner, OP_PUSH, 1, NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2387 "yara_grammar.c"
        break;

        case 61: /* expression: _FALSE_  */
#line 975 "yara_grammar.y"
        {
            compiler->last_result = yr_parser_emit_with_arg(
                yyscanner, OP_PUSH, 0, NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2400 "yara_grammar.c"
        break;

        case 62: /* expression: primary_expression _MATCHES_ regexp  */
#line 984 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_STRING, "matches");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_REGEXP, "matches");

            if (compiler->last_result == ERROR_SUCCESS)
                compiler->last_result = yr_parser_emit(
                    yyscanner,
                    OP_MATCHES,
                    NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2419 "yara_grammar.c"
        break;

        case 63: /* expression: primary_expression _CONTAINS_ primary_expression  */
#line 999 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_STRING, "contains");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_STRING, "contains");

            compiler->last_result = yr_parser_emit(
                yyscanner,
                OP_CONTAINS,
                NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2437 "yara_grammar.c"
        break;

        case 64: /* expression: _STRING_IDENTIFIER_  */
#line 1013 "yara_grammar.y"
        {
            int result = yr_parser_reduce_string_identifier(
                yyscanner,
                (yyvsp[0].c_string),
                OP_STR_FOUND);

            yr_free((yyvsp[0].c_string));

            ERROR_IF(result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2454 "yara_grammar.c"
        break;

        case 65: /* expression: _STRING_IDENTIFIER_ _AT_ primary_expression  */
#line 1026 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "at");

            compiler->last_result = yr_parser_reduce_string_identifier(
                yyscanner,
                (yyvsp[-2].c_string),
                OP_STR_FOUND_AT);

            yr_free((yyvsp[-2].c_string));

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            compiler->current_rule_clflags |= RULE_OFFSETS;

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2475 "yara_grammar.c"
        break;

        case 66: /* expression: _STRING_IDENTIFIER_ _IN_ range  */
#line 1043 "yara_grammar.y"
        {
            compiler->last_result = yr_parser_reduce_string_identifier(
                yyscanner,
                (yyvsp[-2].c_string),
                OP_STR_FOUND_IN);

            yr_free((yyvsp[-2].c_string));

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            compiler->current_rule_clflags |= RULE_OFFSETS;

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2494 "yara_grammar.c"
        break;

        case 67: /* $@2: %empty  */
#line 1058 "yara_grammar.y"
        {
            int var_index;

            if (compiler->loop_depth == MAX_LOOP_NESTING)
                compiler->last_result =
                    ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            var_index = yr_parser_lookup_loop_variable(
                yyscanner,
                (yyvsp[-1].c_string));

            if (var_index >= 0) {
                yr_compiler_set_error_extra_info(
                    compiler,
                    (yyvsp[-1].c_string));

                compiler->last_result =
                    ERROR_DUPLICATE_LOOP_IDENTIFIER;
            }
            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            // Push end-of-list marker
            compiler->last_result = yr_parser_emit_with_arg(
                yyscanner,
                OP_PUSH,
                UNDEFINED,
                NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 2532 "yara_grammar.c"
        break;

        case 68: /* $@3: %empty  */
#line 1092 "yara_grammar.y"
        {
            int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

            int8_t* addr;

            // Clear counter for number of expressions evaluating
            // to TRUE.
            yr_parser_emit_with_arg(
                yyscanner, OP_CLEAR_M, mem_offset + 1, NULL);

            // Clear iterations counter
            yr_parser_emit_with_arg(
                yyscanner, OP_CLEAR_M, mem_offset + 2, NULL);

            if ((yyvsp[-1].integer) == INTEGER_SET_ENUMERATION) {
                // Pop the first integer
                yr_parser_emit_with_arg(
                    yyscanner, OP_POP_M, mem_offset, &addr);
            } else // INTEGER_SET_RANGE
            {
                // Pop higher bound of set range
                yr_parser_emit_with_arg(
                    yyscanner, OP_POP_M, mem_offset + 3, &addr);

                // Pop lower bound of set range
                yr_parser_emit_with_arg(
                    yyscanner, OP_POP_M, mem_offset, NULL);
            }
            compiler->loop_address[compiler->loop_depth]    = addr;
            compiler->loop_identifier[compiler->loop_depth] = (yyvsp[-4].c_string);
            compiler->loop_depth++;
        }
#line 2571 "yara_grammar.c"
        break;

        case 69: /* expression: _FOR_ for_expression _IDENTIFIER_ _IN_ $@2 integer_set ':' $@3 '(' boolean_expression ')'  */
#line 1127 "yara_grammar.y"
        {
            int mem_offset;

            compiler->loop_depth--;
            mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

            // The value at the top of the stack is 1 if latest
            // expression was true or 0 otherwise. Add this value
            // to the counter for number of expressions evaluating
            // to true.
            yr_parser_emit_with_arg(
                yyscanner, OP_ADD_M, mem_offset + 1, NULL);

            // Increment iterations counter
            yr_parser_emit_with_arg(
                yyscanner, OP_INCR_M, mem_offset + 2, NULL);

            if ((yyvsp[-5].integer) == INTEGER_SET_ENUMERATION) {
                yr_parser_emit_with_arg_reloc(
                    yyscanner,
                    OP_JNUNDEF,
                    PTR_TO_UINT64(
                        compiler->loop_address[compiler->loop_depth]),
                    NULL);
            } else // INTEGER_SET_RANGE
            {
                // Increment lower bound of integer set
                yr_parser_emit_with_arg(
                    yyscanner, OP_INCR_M, mem_offset, NULL);

                // Push lower bound of integer set
                yr_parser_emit_with_arg(
                    yyscanner, OP_PUSH_M, mem_offset, NULL);

                // Push higher bound of integer set
                yr_parser_emit_with_arg(
                    yyscanner, OP_PUSH_M, mem_offset + 3, NULL);

                // Compare higher bound with lower bound, do loop again
                // if lower bound is still lower or equal than higher bound
                yr_parser_emit_with_arg_reloc(
                    yyscanner,
                    OP_JLE,
                    PTR_TO_UINT64(
                        compiler->loop_address[compiler->loop_depth]),
                    NULL);

                yr_parser_emit(yyscanner, OP_POP, NULL);
                yr_parser_emit(yyscanner, OP_POP, NULL);
            }

            // Pop end-of-list marker.
            yr_parser_emit(yyscanner, OP_POP, NULL);

            // At this point the loop quantifier (any, all, 1, 2,..)
            // is at the top of the stack. Check if the quantifier
            // is undefined (meaning "all") and replace it with the
            // iterations counter in that case.
            yr_parser_emit_with_arg(
                yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL);

            // Compare the loop quantifier with the number of
            // expressions evaluating to TRUE.
            yr_parser_emit_with_arg(
                yyscanner, OP_PUSH_M, mem_offset + 1, NULL);

            yr_parser_emit(yyscanner, OP_OF_COUNT, NULL);

            compiler->loop_identifier[compiler->loop_depth] = NULL;
            yr_free((yyvsp[-8].c_string));

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2651 "yara_grammar.c"
        break;

        case 70: /* $@4: %empty  */
#line 1203 "yara_grammar.y"
        {
            int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
            int8_t* addr;

            if (compiler->loop_depth == MAX_LOOP_NESTING)
                compiler->last_result =
                    ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

            if (compiler->loop_for_of_mem_offset != -1)
                compiler->last_result =
                    ERROR_NESTED_FOR_OF_LOOP;

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            yr_parser_emit_with_arg(
                yyscanner, OP_CLEAR_M, mem_offset + 1, NULL);

            yr_parser_emit_with_arg(
                yyscanner, OP_CLEAR_M, mem_offset + 2, NULL);

            // Pop the first string.
            yr_parser_emit_with_arg(
                yyscanner, OP_POP_M, mem_offset, &addr);

            compiler->loop_for_of_mem_offset                = mem_offset;
            compiler->loop_address[compiler->loop_depth]    = addr;
            compiler->loop_identifier[compiler->loop_depth] = NULL;
            compiler->loop_depth++;
        }
#line 2685 "yara_grammar.c"
        break;

        case 71: /* expression: _FOR_ for_expression _OF_ string_set ':' $@4 '(' boolean_expression ')'  */
#line 1233 "yara_grammar.y"
        {
            int mem_offset;

            compiler->loop_depth--;
            compiler->loop_for_of_mem_offset = -1;

            mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;

            // Increment counter by the value returned by the
            // boolean expression (0 or 1).
            yr_parser_emit_with_arg(
                yyscanner, OP_ADD_M, mem_offset + 1, NULL);

            // Increment iterations counter.
            yr_parser_emit_with_arg(
                yyscanner, OP_INCR_M, mem_offset + 2, NULL);

            // If next string is not undefined, go back to the
            // beginning of the loop.
            yr_parser_emit_with_arg_reloc(
                yyscanner,
                OP_JNUNDEF,
                PTR_TO_UINT64(
                    compiler->loop_address[compiler->loop_depth]),
                NULL);

            // Pop end-of-list marker.
            yr_parser_emit(yyscanner, OP_POP, NULL);

            // At this point the loop quantifier (any, all, 1, 2,..)
            // is at top of the stack. Check if the quantifier is
            // undefined (meaning "all") and replace it with the
            // iterations counter in that case.
            yr_parser_emit_with_arg(
                yyscanner, OP_SWAPUNDEF, mem_offset + 2, NULL);

            // Compare the loop quantifier with the number of
            // expressions evaluating to TRUE.
            yr_parser_emit_with_arg(
                yyscanner, OP_PUSH_M, mem_offset + 1, NULL);

            yr_parser_emit(yyscanner, OP_OF_COUNT, NULL);
            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;

        }
#line 2735 "yara_grammar.c"
        break;

        case 72: /* expression: for_expression _OF_ string_set  */
#line 1279 "yara_grammar.y"
        {
            yr_parser_emit(yyscanner, OP_OF, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2745 "yara_grammar.c"
        break;

        case 73: /* expression: _NOT_ boolean_expression  */
#line 1285 "yara_grammar.y"
        {
            yr_parser_emit(yyscanner, OP_NOT, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2755 "yara_grammar.c"
        break;

        case 74: /* expression: boolean_expression _AND_ boolean_expression  */
#line 1291 "yara_grammar.y"
        {
            yr_parser_emit(yyscanner, OP_AND, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2765 "yara_grammar.c"
        break;

        case 75: /* expression: boolean_expression _OR_ boolean_expression  */
#line 1297 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_BOOLEAN, "or");

            yr_parser_emit(yyscanner, OP_OR, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2777 "yara_grammar.c"
        break;

        case 76: /* expression: primary_expression _LT_ primary_expression  */
#line 1305 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "<");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "<");

            yr_parser_emit(yyscanner, OP_LT, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2790 "yara_grammar.c"
        break;

        case 77: /* expression: primary_expression _GT_ primary_expression  */
#line 1314 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, ">");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, ">");

            yr_parser_emit(yyscanner, OP_GT, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2803 "yara_grammar.c"
        break;

        case 78: /* expression: primary_expression _LE_ primary_expression  */
#line 1323 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "<=");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "<=");

            yr_parser_emit(yyscanner, OP_LE, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2816 "yara_grammar.c"
        break;

        case 79: /* expression: primary_expression _GE_ primary_expression  */
#line 1332 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, ">=");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, ">=");

            yr_parser_emit(yyscanner, OP_GE, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2829 "yara_grammar.c"
        break;

        case 80: /* expression: primary_expression _EQ_ primary_expression  */
#line 1341 "yara_grammar.y"
        {
            if ((yyvsp[-2].expression_type) != (yyvsp[0].expression_type)) {
                yr_compiler_set_error_extra_info(
                    compiler, "mismatching types for == operator");
                compiler->last_result = ERROR_WRONG_TYPE;
            } else if ((yyvsp[-2].expression_type) == EXPRESSION_TYPE_STRING) {
                compiler->last_result = yr_parser_emit(
                    yyscanner,
                    OP_SZ_EQ,
                    NULL);
            } else {
                compiler->last_result = yr_parser_emit(
                    yyscanner,
                    OP_EQ,
                    NULL);
            }

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2860 "yara_grammar.c"
        break;

        case 81: /* expression: primary_expression _IS_ primary_expression  */
#line 1368 "yara_grammar.y"
        {
            if ((yyvsp[-2].expression_type) != (yyvsp[0].expression_type)) {
                yr_compiler_set_error_extra_info(
                    compiler, "mismatching types for == operator");
                compiler->last_result = ERROR_WRONG_TYPE;
            } else if ((yyvsp[-2].expression_type) == EXPRESSION_TYPE_STRING) {
                compiler->last_result = yr_parser_emit(
                    yyscanner,
                    OP_SZ_EQ,
                    NULL);
            } else {
                compiler->last_result = yr_parser_emit(
                    yyscanner,
                    OP_EQ,
                    NULL);
            }

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2891 "yara_grammar.c"
        break;

        case 82: /* expression: primary_expression _NEQ_ primary_expression  */
#line 1395 "yara_grammar.y"
        {
            if ((yyvsp[-2].expression_type) != (yyvsp[0].expression_type)) {
                yr_compiler_set_error_extra_info(
                    compiler, "mismatching types for != operator");
                compiler->last_result = ERROR_WRONG_TYPE;
            } else if ((yyvsp[-2].expression_type) == EXPRESSION_TYPE_STRING) {
                compiler->last_result = yr_parser_emit(
                    yyscanner,
                    OP_SZ_NEQ,
                    NULL);
            } else {
                compiler->last_result = yr_parser_emit(
                    yyscanner,
                    OP_NEQ,
                    NULL);
            }

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
#line 2922 "yara_grammar.c"
        break;

        case 83: /* expression: primary_expression  */
#line 1422 "yara_grammar.y"
        {
            (yyval.expression_type) = (yyvsp[0].expression_type);
        }
#line 2930 "yara_grammar.c"
        break;

        case 84: /* expression: '(' expression ')'  */
#line 1426 "yara_grammar.y"
        {
            (yyval.expression_type) = (yyvsp[-1].expression_type);
        }
#line 2938 "yara_grammar.c"
        break;

        case 85: /* integer_set: '(' integer_enumeration ')'  */
#line 1433 "yara_grammar.y"
        {
            (yyval.integer) = INTEGER_SET_ENUMERATION;
        }
#line 2944 "yara_grammar.c"
        break;

        case 86: /* integer_set: range  */
#line 1434 "yara_grammar.y"
        {
            (yyval.integer) = INTEGER_SET_RANGE;
        }
#line 2950 "yara_grammar.c"
        break;

        case 87: /* range: '(' primary_expression '.' '.' primary_expression ')'  */
#line 1440 "yara_grammar.y"
        {
            if ((yyvsp[-4].expression_type) != EXPRESSION_TYPE_INTEGER) {
                yr_compiler_set_error_extra_info(
                    compiler, "wrong type for range's lower bound");
                compiler->last_result = ERROR_WRONG_TYPE;
            }

            if ((yyvsp[-1].expression_type) != EXPRESSION_TYPE_INTEGER) {
                yr_compiler_set_error_extra_info(
                    compiler, "wrong type for range's upper bound");
                compiler->last_result = ERROR_WRONG_TYPE;
            }

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 2972 "yara_grammar.c"
        break;

        case 88: /* integer_enumeration: primary_expression  */
#line 1462 "yara_grammar.y"
        {
            if ((yyvsp[0].expression_type) != EXPRESSION_TYPE_INTEGER) {
                yr_compiler_set_error_extra_info(
                    compiler, "wrong type for enumeration item");
                compiler->last_result = ERROR_WRONG_TYPE;
            }

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 2988 "yara_grammar.c"
        break;

        case 89: /* integer_enumeration: integer_enumeration ',' primary_expression  */
#line 1474 "yara_grammar.y"
        {
            if ((yyvsp[0].expression_type) != EXPRESSION_TYPE_INTEGER) {
                yr_compiler_set_error_extra_info(
                    compiler, "wrong type for enumeration item");
                compiler->last_result = ERROR_WRONG_TYPE;
            }

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 3003 "yara_grammar.c"
        break;

        case 90: /* $@5: %empty  */
#line 1489 "yara_grammar.y"
        {
            // Push end-of-list marker
            yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
        }
#line 3012 "yara_grammar.c"
        break;

        case 92: /* string_set: _THEM_  */
#line 1495 "yara_grammar.y"
        {
            yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
            yr_parser_emit_pushes_for_strings(yyscanner, "$*");
#ifdef YARA_PROTO
            compiler->current_rule_clflags |= RULE_THEM;
#endif
        }
#line 3024 "yara_grammar.c"
        break;

        case 95: /* string_enumeration_item: _STRING_IDENTIFIER_  */
#line 1513 "yara_grammar.y"
        {
            yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
            yr_free((yyvsp[0].c_string));
        }
#line 3033 "yara_grammar.c"
        break;

        case 96: /* string_enumeration_item: _STRING_IDENTIFIER_WITH_WILDCARD_  */
#line 1518 "yara_grammar.y"
        {
            yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
            yr_free((yyvsp[0].c_string));
        }
#line 3042 "yara_grammar.c"
        break;

        case 98: /* for_expression: _ALL_  */
#line 1528 "yara_grammar.y"
        {
            yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
#ifdef YARA_PROTO
            compiler->current_rule_clflags |= RULE_ALL;
#endif
        }
#line 3053 "yara_grammar.c"
        break;

        case 99: /* for_expression: _ANY_  */
#line 1535 "yara_grammar.y"
        {
            yr_parser_emit_with_arg(yyscanner, OP_PUSH, 1, NULL);
#ifdef YARA_PROTO
            compiler->current_rule_clflags |= RULE_ANY;
#endif
        }
#line 3064 "yara_grammar.c"
        break;

        case 100: /* primary_expression: '(' primary_expression ')'  */
#line 1546 "yara_grammar.y"
        {
            (yyval.expression_type) = (yyvsp[-1].expression_type);
        }
#line 3072 "yara_grammar.c"
        break;

        case 101: /* primary_expression: _FILESIZE_  */
#line 1550 "yara_grammar.y"
        {
            compiler->last_result = yr_parser_emit(
                yyscanner, OP_FILESIZE, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 3085 "yara_grammar.c"
        break;

        case 102: /* primary_expression: _ENTRYPOINT_  */
#line 1559 "yara_grammar.y"
        {
#ifndef YARA_PROTO
            yywarning(yyscanner,
                      "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" "
                      "function from PE module instead.");
#else
            compiler->current_rule_clflags |= RULE_EP;
#endif
            compiler->last_result = yr_parser_emit(
                yyscanner, OP_ENTRYPOINT, NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3104 "yara_grammar.c"
        break;

        case 103: /* primary_expression: _INT8_ '(' primary_expression ')'  */
#line 1574 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "int8");

            compiler->last_result = yr_parser_emit(
                yyscanner, OP_INT8, NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3119 "yara_grammar.c"
        break;

        case 104: /* primary_expression: _INT16_ '(' primary_expression ')'  */
#line 1585 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "int16");

            compiler->last_result = yr_parser_emit(
                yyscanner, OP_INT16, NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3134 "yara_grammar.c"
        break;

        case 105: /* primary_expression: _INT32_ '(' primary_expression ')'  */
#line 1596 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "int32");

            compiler->last_result = yr_parser_emit(
                yyscanner, OP_INT32, NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3149 "yara_grammar.c"
        break;

        case 106: /* primary_expression: _UINT8_ '(' primary_expression ')'  */
#line 1607 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "uint8");

            compiler->last_result = yr_parser_emit(
                yyscanner, OP_UINT8, NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3164 "yara_grammar.c"
        break;

        case 107: /* primary_expression: _UINT16_ '(' primary_expression ')'  */
#line 1618 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "uint16");

            compiler->last_result = yr_parser_emit(
                yyscanner, OP_UINT16, NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3179 "yara_grammar.c"
        break;

        case 108: /* primary_expression: _UINT32_ '(' primary_expression ')'  */
#line 1629 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "uint32");

            compiler->last_result = yr_parser_emit(
                yyscanner, OP_UINT32, NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3194 "yara_grammar.c"
        break;

        case 109: /* primary_expression: _NUMBER_  */
#line 1640 "yara_grammar.y"
        {
            compiler->last_result = yr_parser_emit_with_arg(
                yyscanner, OP_PUSH, (yyvsp[0].integer), NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3207 "yara_grammar.c"
        break;

        case 110: /* primary_expression: _TEXT_STRING_  */
#line 1649 "yara_grammar.y"
        {
#if REAL_YARA
            SIZED_STRING* sized_string = (yyvsp[0].sized_string);
#endif
            char* string = NULL;

#if REAL_YARA
            compiler->last_result = yr_arena_write_string(
                compiler->sz_arena,
                sized_string->c_string,
                &string);
#endif

            yr_free((yyvsp[0].sized_string));

            if (compiler->last_result == ERROR_SUCCESS)
                compiler->last_result = yr_parser_emit_with_arg_reloc(
                    yyscanner,
                    OP_PUSH,
                    PTR_TO_UINT64(string),
                    NULL);

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_STRING;
        }
#line 3238 "yara_grammar.c"
        break;

        case 111: /* primary_expression: _STRING_COUNT_  */
#line 1676 "yara_grammar.y"
        {
            compiler->last_result = yr_parser_reduce_string_identifier(
                yyscanner,
                (yyvsp[0].c_string),
                OP_STR_COUNT);

            yr_free((yyvsp[0].c_string));

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3255 "yara_grammar.c"
        break;

        case 112: /* primary_expression: _STRING_OFFSET_ '[' primary_expression ']'  */
#line 1689 "yara_grammar.y"
        {
            compiler->last_result = yr_parser_reduce_string_identifier(
                yyscanner,
                (yyvsp[-3].c_string),
                OP_STR_OFFSET);

            yr_free((yyvsp[-3].c_string));

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            compiler->current_rule_clflags |= RULE_OFFSETS;

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3274 "yara_grammar.c"
        break;

        case 113: /* primary_expression: _STRING_OFFSET_  */
#line 1704 "yara_grammar.y"
        {
            compiler->last_result = yr_parser_emit_with_arg(
                yyscanner,
                OP_PUSH,
                1,
                NULL);

            if (compiler->last_result == ERROR_SUCCESS)
                compiler->last_result = yr_parser_reduce_string_identifier(
                    yyscanner,
                    (yyvsp[0].c_string),
                    OP_STR_OFFSET);

            yr_free((yyvsp[0].c_string));

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);

            compiler->current_rule_clflags |= RULE_OFFSETS;

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3300 "yara_grammar.c"
        break;

        case 114: /* primary_expression: identifier  */
#line 1726 "yara_grammar.y"
        {
            if ((yyvsp[0].object) == (YR_OBJECT*)-1) // loop identifier
            {
                (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
            } else if ((yyvsp[0].object) == (YR_OBJECT*)-2) // rule identifier
            {
                (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
            } else if ((yyvsp[0].object) != NULL) {
                compiler->last_result = yr_parser_emit(
                    yyscanner, OP_OBJ_VALUE, NULL);

                switch ((yyvsp[0].object)->type) {
                    case OBJECT_TYPE_INTEGER:
                        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
                        break;
                    case OBJECT_TYPE_STRING:
                        (yyval.expression_type) = EXPRESSION_TYPE_STRING;
                        break;
                    default:
                        assert(FALSE);
                }
            } else {
                yr_compiler_set_error_extra_info(compiler, (yyvsp[0].object)->identifier);
                compiler->last_result = ERROR_WRONG_TYPE;
            }

            ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }
#line 3339 "yara_grammar.c"
        break;

        case 115: /* primary_expression: primary_expression '+' primary_expression  */
#line 1761 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "+");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "+");

            yr_parser_emit(yyscanner, OP_ADD, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3352 "yara_grammar.c"
        break;

        case 116: /* primary_expression: primary_expression '-' primary_expression  */
#line 1770 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "-");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "-");

            yr_parser_emit(yyscanner, OP_SUB, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3365 "yara_grammar.c"
        break;

        case 117: /* primary_expression: primary_expression '*' primary_expression  */
#line 1779 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "*");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "*");

            yr_parser_emit(yyscanner, OP_MUL, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3378 "yara_grammar.c"
        break;

        case 118: /* primary_expression: primary_expression '\\' primary_expression  */
#line 1788 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "\\");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "\\");

            yr_parser_emit(yyscanner, OP_DIV, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3391 "yara_grammar.c"
        break;

        case 119: /* primary_expression: primary_expression '%' primary_expression  */
#line 1797 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "%");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "%");

            yr_parser_emit(yyscanner, OP_MOD, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3404 "yara_grammar.c"
        break;

        case 120: /* primary_expression: primary_expression '^' primary_expression  */
#line 1806 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "^");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "^");

            yr_parser_emit(yyscanner, OP_XOR, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3417 "yara_grammar.c"
        break;

        case 121: /* primary_expression: primary_expression '&' primary_expression  */
#line 1815 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "^");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "^");

            yr_parser_emit(yyscanner, OP_AND, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3430 "yara_grammar.c"
        break;

        case 122: /* primary_expression: primary_expression '|' primary_expression  */
#line 1824 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "|");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "|");

            yr_parser_emit(yyscanner, OP_OR, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3443 "yara_grammar.c"
        break;

        case 123: /* primary_expression: '~' primary_expression  */
#line 1833 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "~");

            yr_parser_emit(yyscanner, OP_NEG, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3455 "yara_grammar.c"
        break;

        case 124: /* primary_expression: primary_expression _SHIFT_LEFT_ primary_expression  */
#line 1841 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "<<");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "<<");

            yr_parser_emit(yyscanner, OP_SHL, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3468 "yara_grammar.c"
        break;

        case 125: /* primary_expression: primary_expression _SHIFT_RIGHT_ primary_expression  */
#line 1850 "yara_grammar.y"
        {
            CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, ">>");
            CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, ">>");

            yr_parser_emit(yyscanner, OP_SHR, NULL);

            (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
#line 3481 "yara_grammar.c"
        break;

        case 126: /* primary_expression: regexp  */
#line 1859 "yara_grammar.y"
        {
            (yyval.expression_type) = (yyvsp[0].expression_type);
        }
#line 3489 "yara_grammar.c"
        break;

#line 3493 "yara_grammar.c"

        default:
            break;
    }
    /* User semantic actions sometimes alter yychar, and that requires
       that yytoken be updated with the new translation.  We take the
       approach of translating immediately before every use of yytoken.
       One alternative is translating here after every semantic action,
       but that translation would be missed if the semantic action invokes
       YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
       if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
       incorrect destructor might then be invoked immediately.  In the
       case of YYERROR or YYBACKUP, subsequent parser actions might lead
       to an incorrect destructor call or verbose syntax error message
       before the lookahead is translated.  */
    YY_SYMBOL_PRINT("-> $$ =", YY_CAST(yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

    YYPOPSTACK(yylen);
    yylen = 0;

    *++yyvsp = yyval;

    /* Now 'shift' the result of the reduction.  Determine what state
       that goes to, based on the state we popped back to and the rule
       number reduced by.  */
    {
        const int yylhs = yyr1[yyn] - YYNTOKENS;
        const int yyi   = yypgoto[yylhs] + *yyssp;
        yystate         = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
                               ? yytable[yyi]
                               : yydefgoto[yylhs]);
    }

    goto yynewstate;

/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
    /* Make sure we have latest lookahead translation.  See comments at
       user semantic actions for why this is necessary.  */
    yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE(yychar);
    /* If not already recovering from an error, report this error.  */
    if (!yyerrstatus) {
        ++yynerrs;
        yyerror(yyscanner, compiler, YY_("syntax error"));
    }

    if (yyerrstatus == 3) {
        /* If just tried and failed to reuse lookahead token after an
           error, discard it.  */

        if (yychar <= YYEOF) {
            /* Return failure if at end of input.  */
            if (yychar == YYEOF)
                YYABORT;
        } else {
            yydestruct("Error: discarding",
                       yytoken, &yylval, yyscanner, compiler);
            yychar = YYEMPTY;
        }
    }

    /* Else will try to reuse lookahead token after shifting the error
       token.  */
    goto yyerrlab1;

/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
    /* Pacify compilers when the user code never invokes YYERROR and the
       label yyerrorlab therefore never appears in user code.  */
    if (0)
        YYERROR;
    ++yynerrs;

    /* Do not reclaim the symbols of the rule whose action triggered
       this YYERROR.  */
    YYPOPSTACK(yylen);
    yylen = 0;
    YY_STACK_PRINT(yyss, yyssp);
    yystate = *yyssp;
    goto yyerrlab1;

/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
    yyerrstatus = 3; /* Each real token shifted decrements this.  */

    /* Pop stack until we find a state that shifts the error token.  */
    for (;;) {
        yyn = yypact[yystate];
        if (!yypact_value_is_default(yyn)) {
            yyn += YYSYMBOL_YYerror;
            if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror) {
                yyn = yytable[yyn];
                if (0 < yyn)
                    break;
            }
        }

        /* Pop the current state because it cannot handle the error token.  */
        if (yyssp == yyss)
            YYABORT;

        yydestruct("Error: popping",
                   YY_ACCESSING_SYMBOL(yystate), yyvsp, yyscanner, compiler);
        YYPOPSTACK(1);
        yystate = *yyssp;
        YY_STACK_PRINT(yyss, yyssp);
    }

    YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
    *++yyvsp = yylval;
    YY_IGNORE_MAYBE_UNINITIALIZED_END

    /* Shift the error token.  */
    YY_SYMBOL_PRINT("Shifting", YY_ACCESSING_SYMBOL(yyn), yyvsp, yylsp);

    yystate = yyn;
    goto yynewstate;

/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
    yyresult = 0;
    goto yyreturnlab;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
    yyresult = 1;
    goto yyreturnlab;

/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
    yyerror(yyscanner, compiler, YY_("memory exhausted"));
    yyresult = 2;
    goto yyreturnlab;

/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
    if (yychar != YYEMPTY) {
        /* Make sure we have latest lookahead translation.  See comments at
           user semantic actions for why this is necessary.  */
        yytoken = YYTRANSLATE(yychar);
        yydestruct("Cleanup: discarding lookahead",
                   yytoken, &yylval, yyscanner, compiler);
    }
    /* Do not reclaim the symbols of the rule whose action triggered
       this YYABORT or YYACCEPT.  */
    YYPOPSTACK(yylen);
    YY_STACK_PRINT(yyss, yyssp);
    while (yyssp != yyss) {
        yydestruct("Cleanup: popping",
                   YY_ACCESSING_SYMBOL(+*yyssp), yyvsp, yyscanner, compiler);
        YYPOPSTACK(1);
    }
#ifndef yyoverflow
    if (yyss != yyssa)
        YYSTACK_FREE(yyss);
#endif

    return yyresult;
}

#line 1864 "yara_grammar.y"
