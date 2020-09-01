/* A Bison parser, made by GNU Bison 3.5.1.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.5.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         yara_yyparse
#define yylex           yara_yylex
#define yyerror         yara_yyerror
#define yydebug         yara_yydebug
#define yynerrs         yara_yynerrs

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

#define INTEGER_SET_ENUMERATION   1
#define INTEGER_SET_RANGE         2

#define EXPRESSION_TYPE_BOOLEAN   1
#define EXPRESSION_TYPE_INTEGER   2
#define EXPRESSION_TYPE_STRING    3
#define EXPRESSION_TYPE_REGEXP    4


#define ERROR_IF(x) \
    if (x) \
    { \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    } \

#define CHECK_TYPE_WITH_CLEANUP(actual_type, expected_type, op, cleanup) \
    if (actual_type != expected_type) \
    { \
      switch(actual_type) \
      { \
        case EXPRESSION_TYPE_INTEGER: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"integer\" for " op " operator"); \
          break; \
        case EXPRESSION_TYPE_STRING: \
          yr_compiler_set_error_extra_info( \
              compiler, "wrong type \"string\" for \"" op "\" operator"); \
          break; \
      } \
      compiler->last_result = ERROR_WRONG_TYPE; \
      cleanup; \
      yyerror(yyscanner, compiler, NULL); \
      YYERROR; \
    }

#define CHECK_TYPE(actual_type, expected_type, op) \
    CHECK_TYPE_WITH_CLEANUP(actual_type, expected_type, op, ) \


#define MSG(op)  "wrong type \"string\" for \"" op "\" operator"


#line 150 "yara_grammar.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_YARA_YY_YARA_GRAMMAR_H_INCLUDED
# define YY_YARA_YY_YARA_GRAMMAR_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yara_yydebug;
#endif
/* "%code requires" blocks.  */
#line 39 "yara_grammar.y"

#include "yara_compiler.h"

#line 197 "yara_grammar.c"

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    _RULE_ = 258,
    _PRIVATE_ = 259,
    _GLOBAL_ = 260,
    _META_ = 261,
    _STRINGS_ = 262,
    _CONDITION_ = 263,
    _IDENTIFIER_ = 264,
    _STRING_IDENTIFIER_ = 265,
    _STRING_COUNT_ = 266,
    _STRING_OFFSET_ = 267,
    _STRING_IDENTIFIER_WITH_WILDCARD_ = 268,
    _NUMBER_ = 269,
    _TEXT_STRING_ = 270,
    _HEX_STRING_ = 271,
    _REGEXP_ = 272,
    _ASCII_ = 273,
    _WIDE_ = 274,
    _NOCASE_ = 275,
    _FULLWORD_ = 276,
    _AT_ = 277,
    _FILESIZE_ = 278,
    _ENTRYPOINT_ = 279,
    _ALL_ = 280,
    _ANY_ = 281,
    _IN_ = 282,
    _OF_ = 283,
    _FOR_ = 284,
    _THEM_ = 285,
    _INT8_ = 286,
    _INT16_ = 287,
    _INT32_ = 288,
    _UINT8_ = 289,
    _UINT16_ = 290,
    _UINT32_ = 291,
    _MATCHES_ = 292,
    _CONTAINS_ = 293,
    _IMPORT_ = 294,
    _TRUE_ = 295,
    _FALSE_ = 296,
    _OR_ = 297,
    _AND_ = 298,
    _LT_ = 299,
    _LE_ = 300,
    _GT_ = 301,
    _GE_ = 302,
    _EQ_ = 303,
    _NEQ_ = 304,
    _IS_ = 305,
    _SHIFT_LEFT_ = 306,
    _SHIFT_RIGHT_ = 307,
    _NOT_ = 308
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 219 "yara_grammar.y"

  SIZED_STRING*   sized_string;
  char*           c_string;
  int8_t          expression_type;
  int64_t         integer;
  YR_STRING*      string;
  YR_META*        meta;
  YR_OBJECT*      object;

#line 272 "yara_grammar.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);

#endif /* !YY_YARA_YY_YARA_GRAMMAR_H_INCLUDED  */



#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
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

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))

/* Stored state numbers (used for stacks). */
typedef yytype_uint8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   433

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  74
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  35
/* YYNRULES -- Number of rules.  */
#define YYNRULES  115
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  216

#define YYUNDEFTOK  2
#define YYMAXUTOK   309


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    60,    44,     2,
      71,    72,    58,    56,    73,    57,    68,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    66,     2,
       2,    67,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    69,    59,    70,    46,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    64,    45,    65,    62,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    61,    63
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   233,   233,   234,   235,   236,   237,   242,   254,   273,
     276,   306,   310,   338,   343,   344,   349,   350,   356,   359,
     379,   396,   435,   436,   441,   457,   470,   483,   500,   501,
     506,   520,   519,   536,   553,   554,   559,   560,   561,   562,
     567,   652,   702,   725,   765,   768,   790,   823,   870,   888,
     897,   906,   921,   935,   948,   965,   981,  1015,   980,  1126,
    1125,  1201,  1207,  1213,  1219,  1227,  1236,  1245,  1254,  1263,
    1290,  1317,  1344,  1348,  1356,  1357,  1362,  1384,  1396,  1412,
    1411,  1417,  1429,  1430,  1435,  1440,  1449,  1450,  1457,  1468,
    1472,  1481,  1496,  1507,  1518,  1529,  1540,  1551,  1562,  1571,
    1598,  1611,  1626,  1648,  1683,  1692,  1701,  1710,  1719,  1728,
    1737,  1746,  1755,  1763,  1772,  1781
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "_RULE_", "_PRIVATE_", "_GLOBAL_",
  "_META_", "_STRINGS_", "_CONDITION_", "_IDENTIFIER_",
  "_STRING_IDENTIFIER_", "_STRING_COUNT_", "_STRING_OFFSET_",
  "_STRING_IDENTIFIER_WITH_WILDCARD_", "_NUMBER_", "_TEXT_STRING_",
  "_HEX_STRING_", "_REGEXP_", "_ASCII_", "_WIDE_", "_NOCASE_",
  "_FULLWORD_", "_AT_", "_FILESIZE_", "_ENTRYPOINT_", "_ALL_", "_ANY_",
  "_IN_", "_OF_", "_FOR_", "_THEM_", "_INT8_", "_INT16_", "_INT32_",
  "_UINT8_", "_UINT16_", "_UINT32_", "_MATCHES_", "_CONTAINS_", "_IMPORT_",
  "_TRUE_", "_FALSE_", "_OR_", "_AND_", "'&'", "'|'", "'^'", "_LT_",
  "_LE_", "_GT_", "_GE_", "_EQ_", "_NEQ_", "_IS_", "_SHIFT_LEFT_",
  "_SHIFT_RIGHT_", "'+'", "'-'", "'*'", "'\\\\'", "'%'", "_NOT_", "'~'",
  "\"include\"", "'{'", "'}'", "':'", "'='", "'.'", "'['", "']'", "'('",
  "')'", "','", "$accept", "rules", "import", "rule", "meta", "strings",
  "condition", "rule_modifiers", "rule_modifier", "tags", "tag_list",
  "meta_declarations", "meta_declaration", "string_declarations",
  "string_declaration", "$@1", "string_modifiers", "string_modifier",
  "identifier", "arguments_list", "regexp", "boolean_expression",
  "expression", "$@2", "$@3", "$@4", "integer_set", "range",
  "integer_enumeration", "string_set", "$@5", "string_enumeration",
  "string_enumeration_item", "for_expression", "primary_expression", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,    38,   124,    94,   299,   300,   301,
     302,   303,   304,   305,   306,   307,    43,    45,    42,    92,
      37,   308,   126,   309,   123,   125,    58,    61,    46,    91,
      93,    40,    41,    44
};
# endif

#define YYPACT_NINF (-66)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-87)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -66,     6,   -66,   -59,     0,   -66,   -66,    59,   -66,   -66,
     -66,     9,   -66,   -66,   -66,   -44,    16,   -24,   -66,    49,
      81,   -66,    26,    88,    92,    43,   115,    54,    92,   -66,
     116,    63,    66,    -2,   -66,    75,   116,   -66,    79,   -66,
     -66,   -66,   -66,   -66,    82,   -66,   -66,    -8,   -66,    83,
     -66,   -66,   -66,   -66,   -66,   -66,   -66,   113,    72,    80,
      84,    94,    96,    97,   -66,   -66,    79,   168,    79,   -42,
     -66,    57,   -66,   125,   205,   -66,   -66,   137,   168,    98,
     168,   168,    -7,   372,   168,   168,   168,   168,   168,   168,
     -66,   -66,    57,   100,   169,   161,   168,    79,    79,    79,
     -29,   156,   168,   168,   168,   168,   168,   168,   168,   168,
     168,   168,   168,   168,   168,   168,   168,   168,   168,   168,
      36,   -66,   372,   168,   -66,   338,   222,   149,   -29,   229,
     251,   258,   280,   287,   309,   -66,   -66,   -66,   345,    34,
      74,   135,   -66,   -66,   -66,   -66,   -66,   372,   104,   104,
     104,   372,   372,   372,   372,   372,   372,   372,   -23,   -23,
      25,    25,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,
      36,   365,   -66,   -66,   120,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   -66,    79,    -5,   119,   110,   -66,    74,   -66,
     -66,    60,   -66,   168,   168,   122,   -66,   118,   -66,    -5,
     316,    62,   365,   -66,    79,   -66,   -66,   -66,   168,   123,
     -26,   372,    79,   -66,   -19,   -66
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       2,     0,     1,    14,     0,     4,     3,     0,     6,     5,
       7,     0,    16,    17,    15,    18,     0,     0,    20,    19,
       9,    21,     0,    11,     0,     0,     0,     0,    10,    22,
       0,     0,     0,     0,    23,     0,    12,    28,     0,     8,
      25,    24,    26,    27,    31,    29,    40,    53,   100,   102,
      98,    99,    47,    90,    91,    87,    88,     0,     0,     0,
       0,     0,     0,     0,    49,    50,     0,     0,     0,   103,
     115,    13,    48,     0,    72,    34,    33,     0,     0,     0,
       0,     0,     0,    86,     0,     0,     0,     0,     0,     0,
      62,   112,     0,    48,    72,     0,     0,    44,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      30,    34,    54,     0,    55,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    73,    89,    41,     0,     0,
      45,    64,    63,    81,    79,    61,    51,    52,   110,   111,
     109,    65,    67,    66,    68,    69,    71,    70,   113,   114,
     104,   105,   106,   107,   108,    37,    36,    38,    39,    35,
      32,     0,   101,    56,     0,    92,    93,    94,    95,    96,
      97,    42,    43,     0,     0,     0,     0,    59,    46,    84,
      85,     0,    82,     0,     0,     0,    75,     0,    80,     0,
       0,     0,    77,    57,     0,    83,    76,    74,     0,     0,
       0,    78,     0,    60,     0,    58
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -66,   -66,   -66,   187,   -66,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   165,   -66,   159,   -66,    77,   -66,   -66,   -66,
      95,   -38,   -65,   -66,   -66,   -66,   -66,    19,   -66,   103,
     -66,   -66,    10,   151,   -37
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     5,     6,    23,    26,    32,     7,    14,    17,
      19,    28,    29,    36,    37,    77,   120,   169,    69,   139,
      70,    92,    72,   186,   209,   197,   195,   124,   201,   145,
     184,   191,   192,    73,    74
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      71,   143,   127,    93,     8,   189,     2,     3,   190,   -14,
     -14,   -14,    40,    41,    78,    10,    98,    99,    15,    79,
      83,   128,    16,    98,    99,    18,    95,    96,    90,    97,
      91,    94,   140,   115,   116,   117,   118,   119,    42,    43,
      20,   122,   144,   125,   126,     4,   213,   129,   130,   131,
     132,   133,   134,   215,   165,   166,   167,   168,    21,   138,
     141,   142,    11,    12,    13,   147,   148,   149,   150,   151,
     152,   153,   154,   155,   156,   157,   158,   159,   160,   161,
     162,   163,   164,   117,   118,   119,   171,    22,    46,    47,
      48,    49,    24,    50,    51,    25,    52,    75,    76,    98,
      99,    27,    53,    54,    55,    56,   182,   183,    57,    30,
      58,    59,    60,    61,    62,    63,   -48,   -48,   188,    64,
      65,    33,    46,    31,    48,    49,    35,    50,    51,    38,
      52,    39,   198,   199,   207,   208,    53,    54,    55,    56,
      66,    67,    44,    84,    58,    59,    60,    61,    62,    63,
      68,    85,    80,   100,   121,    86,   200,   202,   113,   114,
     115,   116,   117,   118,   119,    87,   210,    88,    89,   123,
     137,   211,   135,    52,   214,    67,   173,    46,    99,    48,
      49,   194,    50,    51,    81,    52,   187,   193,   203,   204,
       9,    53,    54,    34,   212,    45,   146,   -86,   170,    58,
      59,    60,    61,    62,    63,   196,   101,   102,    82,   205,
       0,     0,     0,   103,   104,   105,   106,   107,   108,   109,
     110,   111,   112,   113,   114,   115,   116,   117,   118,   119,
      67,   174,     0,   -86,     0,     0,     0,     0,     0,    81,
       0,   136,   101,   102,     0,     0,     0,     0,     0,   103,
     104,   105,   106,   107,   108,   109,   110,   111,   112,   113,
     114,   115,   116,   117,   118,   119,   103,   104,   105,     0,
       0,     0,     0,   103,   104,   105,   113,   114,   115,   116,
     117,   118,   119,   113,   114,   115,   116,   117,   118,   119,
       0,     0,     0,     0,   136,   103,   104,   105,     0,     0,
       0,   175,   103,   104,   105,   113,   114,   115,   116,   117,
     118,   119,   113,   114,   115,   116,   117,   118,   119,     0,
       0,     0,     0,   176,   103,   104,   105,     0,     0,     0,
     177,   103,   104,   105,   113,   114,   115,   116,   117,   118,
     119,   113,   114,   115,   116,   117,   118,   119,     0,     0,
       0,     0,   178,   103,   104,   105,     0,     0,     0,   179,
     103,   104,   105,   113,   114,   115,   116,   117,   118,   119,
     113,   114,   115,   116,   117,   118,   119,     0,     0,     0,
       0,   180,   103,   104,   105,     0,     0,     0,   206,   103,
     104,   105,   113,   114,   115,   116,   117,   118,   119,   113,
     114,   115,   116,   117,   118,   119,     0,     0,   172,   103,
     104,   105,     0,     0,     0,   181,   103,   104,   105,   113,
     114,   115,   116,   117,   118,   119,   113,   114,   115,   116,
     117,   118,   119,   185
};

static const yytype_int16 yycheck[] =
{
      38,    30,     9,    68,    63,    10,     0,     1,    13,     3,
       4,     5,    14,    15,    22,    15,    42,    43,     9,    27,
      57,    28,    66,    42,    43,     9,    68,    69,    66,    71,
      67,    68,    97,    56,    57,    58,    59,    60,    40,    41,
      64,    78,    71,    80,    81,    39,    72,    84,    85,    86,
      87,    88,    89,    72,    18,    19,    20,    21,     9,    96,
      98,    99,     3,     4,     5,   102,   103,   104,   105,   106,
     107,   108,   109,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,    58,    59,    60,   123,     6,     9,    10,
      11,    12,    66,    14,    15,     7,    17,    15,    16,    42,
      43,     9,    23,    24,    25,    26,    72,    73,    29,    66,
      31,    32,    33,    34,    35,    36,    42,    43,   183,    40,
      41,    67,     9,     8,    11,    12,    10,    14,    15,    66,
      17,    65,    72,    73,    72,    73,    23,    24,    25,    26,
      61,    62,    67,    71,    31,    32,    33,    34,    35,    36,
      71,    71,    69,    28,    17,    71,   193,   194,    54,    55,
      56,    57,    58,    59,    60,    71,   204,    71,    71,    71,
       9,   208,    72,    17,   212,    62,    27,     9,    43,    11,
      12,    71,    14,    15,    71,    17,    66,    68,    66,    71,
       3,    23,    24,    28,    71,    36,   101,    28,   121,    31,
      32,    33,    34,    35,    36,   186,    37,    38,    57,   199,
      -1,    -1,    -1,    44,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      62,   128,    -1,    28,    -1,    -1,    -1,    -1,    -1,    71,
      -1,    72,    37,    38,    -1,    -1,    -1,    -1,    -1,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    44,    45,    46,    -1,
      -1,    -1,    -1,    44,    45,    46,    54,    55,    56,    57,
      58,    59,    60,    54,    55,    56,    57,    58,    59,    60,
      -1,    -1,    -1,    -1,    72,    44,    45,    46,    -1,    -1,
      -1,    72,    44,    45,    46,    54,    55,    56,    57,    58,
      59,    60,    54,    55,    56,    57,    58,    59,    60,    -1,
      -1,    -1,    -1,    72,    44,    45,    46,    -1,    -1,    -1,
      72,    44,    45,    46,    54,    55,    56,    57,    58,    59,
      60,    54,    55,    56,    57,    58,    59,    60,    -1,    -1,
      -1,    -1,    72,    44,    45,    46,    -1,    -1,    -1,    72,
      44,    45,    46,    54,    55,    56,    57,    58,    59,    60,
      54,    55,    56,    57,    58,    59,    60,    -1,    -1,    -1,
      -1,    72,    44,    45,    46,    -1,    -1,    -1,    72,    44,
      45,    46,    54,    55,    56,    57,    58,    59,    60,    54,
      55,    56,    57,    58,    59,    60,    -1,    -1,    70,    44,
      45,    46,    -1,    -1,    -1,    70,    44,    45,    46,    54,
      55,    56,    57,    58,    59,    60,    54,    55,    56,    57,
      58,    59,    60,    68
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    75,     0,     1,    39,    76,    77,    81,    63,    77,
      15,     3,     4,     5,    82,     9,    66,    83,     9,    84,
      64,     9,     6,    78,    66,     7,    79,     9,    85,    86,
      66,     8,    80,    67,    86,    10,    87,    88,    66,    65,
      14,    15,    40,    41,    67,    88,     9,    10,    11,    12,
      14,    15,    17,    23,    24,    25,    26,    29,    31,    32,
      33,    34,    35,    36,    40,    41,    61,    62,    71,    92,
      94,    95,    96,   107,   108,    15,    16,    89,    22,    27,
      69,    71,   107,   108,    71,    71,    71,    71,    71,    71,
      95,   108,    95,    96,   108,    68,    69,    71,    42,    43,
      28,    37,    38,    44,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      90,    17,   108,    71,   101,   108,   108,     9,    28,   108,
     108,   108,   108,   108,   108,    72,    72,     9,   108,    93,
      96,    95,    95,    30,    71,   103,    94,   108,   108,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,    18,    19,    20,    21,    91,
      90,   108,    70,    27,   103,    72,    72,    72,    72,    72,
      72,    70,    72,    73,   104,    68,    97,    66,    96,    10,
      13,   105,   106,    68,    71,   100,   101,    99,    72,    73,
     108,   102,   108,    66,    71,   106,    72,    72,    73,    98,
      95,   108,    71,    72,    95,    72
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int8 yyr1[] =
{
       0,    74,    75,    75,    75,    75,    75,    76,    77,    78,
      78,    79,    79,    80,    81,    81,    82,    82,    83,    83,
      84,    84,    85,    85,    86,    86,    86,    86,    87,    87,
      88,    89,    88,    88,    90,    90,    91,    91,    91,    91,
      92,    92,    92,    92,    93,    93,    93,    94,    95,    96,
      96,    96,    96,    96,    96,    96,    97,    98,    96,    99,
      96,    96,    96,    96,    96,    96,    96,    96,    96,    96,
      96,    96,    96,    96,   100,   100,   101,   102,   102,   104,
     103,   103,   105,   105,   106,   106,   107,   107,   107,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,   108
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     2,     2,     3,     3,     2,     9,     0,
       3,     0,     3,     3,     0,     2,     1,     1,     0,     2,
       1,     2,     1,     2,     3,     3,     3,     3,     1,     2,
       4,     0,     5,     3,     0,     2,     1,     1,     1,     1,
       1,     3,     4,     4,     0,     1,     3,     1,     1,     1,
       1,     3,     3,     1,     3,     3,     0,     0,    11,     0,
       9,     3,     2,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     1,     3,     3,     1,     6,     1,     3,     0,
       4,     1,     1,     3,     1,     1,     1,     1,     1,     3,
       1,     1,     4,     4,     4,     4,     4,     4,     1,     1,
       1,     4,     1,     1,     3,     3,     3,     3,     3,     3,
       3,     3,     2,     3,     3,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (yyscanner, compiler, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, yyscanner, compiler); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, YR_COMPILER* compiler)
{
  FILE *yyoutput = yyo;
  YYUSE (yyoutput);
  YYUSE (yyscanner);
  YYUSE (compiler);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yytype], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, YR_COMPILER* compiler)
{
  YYFPRINTF (yyo, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyo, yytype, yyvaluep, yyscanner, compiler);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, int yyrule, void *yyscanner, YR_COMPILER* compiler)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[+yyssp[yyi + 1 - yynrhs]],
                       &yyvsp[(yyi + 1) - (yynrhs)]
                                              , yyscanner, compiler);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, yyscanner, compiler); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
#  else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                yy_state_t *yyssp, int yytoken)
{
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Actual size of YYARG. */
  int yycount = 0;
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[+*yyssp];
      YYPTRDIFF_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
      yysize = yysize0;
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYPTRDIFF_T yysize1
                    = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
                    yysize = yysize1;
                  else
                    return 2;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    /* Don't count the "%s"s in the final size, but reserve room for
       the terminator.  */
    YYPTRDIFF_T yysize1 = yysize + (yystrlen (yyformat) - 2 * yycount) + 1;
    if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
      yysize = yysize1;
    else
      return 2;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, void *yyscanner, YR_COMPILER* compiler)
{
  YYUSE (yyvaluep);
  YYUSE (yyscanner);
  YYUSE (compiler);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yytype)
    {
    case 9: /* _IDENTIFIER_  */
#line 210 "yara_grammar.y"
            { yr_free(((*yyvaluep).c_string)); }
#line 1395 "yara_grammar.c"
        break;

    case 10: /* _STRING_IDENTIFIER_  */
#line 211 "yara_grammar.y"
            { yr_free(((*yyvaluep).c_string)); }
#line 1401 "yara_grammar.c"
        break;

    case 11: /* _STRING_COUNT_  */
#line 212 "yara_grammar.y"
            { yr_free(((*yyvaluep).c_string)); }
#line 1407 "yara_grammar.c"
        break;

    case 12: /* _STRING_OFFSET_  */
#line 213 "yara_grammar.y"
            { yr_free(((*yyvaluep).c_string)); }
#line 1413 "yara_grammar.c"
        break;

    case 13: /* _STRING_IDENTIFIER_WITH_WILDCARD_  */
#line 214 "yara_grammar.y"
            { yr_free(((*yyvaluep).c_string)); }
#line 1419 "yara_grammar.c"
        break;

    case 15: /* _TEXT_STRING_  */
#line 215 "yara_grammar.y"
            { yr_free(((*yyvaluep).sized_string)); }
#line 1425 "yara_grammar.c"
        break;

    case 16: /* _HEX_STRING_  */
#line 216 "yara_grammar.y"
            { yr_free(((*yyvaluep).sized_string)); }
#line 1431 "yara_grammar.c"
        break;

    case 17: /* _REGEXP_  */
#line 217 "yara_grammar.y"
            { yr_free(((*yyvaluep).sized_string)); }
#line 1437 "yara_grammar.c"
        break;

      default:
        break;
    }
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void *yyscanner, YR_COMPILER* compiler)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs;

    yy_state_fast_t yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss;
    yy_state_t *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYPTRDIFF_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
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
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
# undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
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
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex (&yylval, yyscanner, compiler);
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
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
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 7:
#line 243 "yara_grammar.y"
      {
        int result = yr_parser_reduce_import(yyscanner, (yyvsp[0].sized_string));

        yr_free((yyvsp[0].sized_string));

        ERROR_IF(result != ERROR_SUCCESS);
      }
#line 1717 "yara_grammar.c"
    break;

  case 8:
#line 255 "yara_grammar.y"
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
#line 1735 "yara_grammar.c"
    break;

  case 9:
#line 273 "yara_grammar.y"
      {
        (yyval.meta) = NULL;
      }
#line 1743 "yara_grammar.c"
    break;

  case 10:
#line 277 "yara_grammar.y"
      {
#if REAL_YARA //Meta not supported
        // Each rule have a list of meta-data info, consisting in a
        // sequence of YR_META structures. The last YR_META structure does
        // not represent a real meta-data, it's just a end-of-list marker
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
#line 1772 "yara_grammar.c"
    break;

  case 11:
#line 306 "yara_grammar.y"
      {
        (yyval.string) = NULL;
        compiler->current_rule_strings = (yyval.string);
      }
#line 1781 "yara_grammar.c"
    break;

  case 12:
#line 311 "yara_grammar.y"
      {
        // Each rule have a list of strings, consisting in a sequence
        // of YR_STRING structures. The last YR_STRING structure does not
        // represent a real string, it's just a end-of-list marker
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
        (yyval.string) = (yyvsp[0].string);
      }
#line 1809 "yara_grammar.c"
    break;

  case 14:
#line 343 "yara_grammar.y"
                                       { (yyval.integer) = 0;  }
#line 1815 "yara_grammar.c"
    break;

  case 15:
#line 344 "yara_grammar.y"
                                       { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 1821 "yara_grammar.c"
    break;

  case 16:
#line 349 "yara_grammar.y"
                     { (yyval.integer) = RULE_GFLAGS_PRIVATE; }
#line 1827 "yara_grammar.c"
    break;

  case 17:
#line 350 "yara_grammar.y"
                     { (yyval.integer) = RULE_GFLAGS_GLOBAL; }
#line 1833 "yara_grammar.c"
    break;

  case 18:
#line 356 "yara_grammar.y"
      {
        (yyval.c_string) = NULL;
      }
#line 1841 "yara_grammar.c"
    break;

  case 19:
#line 360 "yara_grammar.y"
      {
#if REAL_YARA //tags not supported
        // Tags list is represented in the arena as a sequence
        // of null-terminated strings, the sequence ends with an
        // additional null character. Here we write the ending null
        //character. Example: tag1\0tag2\0tag3\0\0

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, "", NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
#endif

        (yyval.c_string) = (yyvsp[0].c_string);
      }
#line 1861 "yara_grammar.c"
    break;

  case 20:
#line 380 "yara_grammar.y"
      {
#if REAL_YARA //tags not supported
        char* identifier;

        compiler->last_result = yr_arena_write_string(
            yyget_extra(yyscanner)->sz_arena, (yyvsp[0].c_string), &identifier);

#endif
        yr_free((yyvsp[0].c_string));

#if REAL_YARA //tags not supported
        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.c_string) = identifier;
#endif
      }
#line 1882 "yara_grammar.c"
    break;

  case 21:
#line 397 "yara_grammar.y"
      {
#if REAL_YARA //tags not supported
        char* tag_name = (yyvsp[-1].c_string);
        size_t tag_length = tag_name != NULL ? strlen(tag_name) : 0;

        while (tag_length > 0)
        {
          if (strcmp(tag_name, (yyvsp[0].c_string)) == 0)
          {
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
#line 1920 "yara_grammar.c"
    break;

  case 22:
#line 435 "yara_grammar.y"
                                          {  (yyval.meta) = (yyvsp[0].meta); }
#line 1926 "yara_grammar.c"
    break;

  case 23:
#line 436 "yara_grammar.y"
                                          {  (yyval.meta) = (yyvsp[-1].meta); }
#line 1932 "yara_grammar.c"
    break;

  case 24:
#line 442 "yara_grammar.y"
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
#line 1952 "yara_grammar.c"
    break;

  case 25:
#line 458 "yara_grammar.y"
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
#line 1969 "yara_grammar.c"
    break;

  case 26:
#line 471 "yara_grammar.y"
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
#line 1986 "yara_grammar.c"
    break;

  case 27:
#line 484 "yara_grammar.y"
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
#line 2003 "yara_grammar.c"
    break;

  case 28:
#line 500 "yara_grammar.y"
                                              { (yyval.string) = (yyvsp[0].string); }
#line 2009 "yara_grammar.c"
    break;

  case 29:
#line 501 "yara_grammar.y"
                                              { (yyval.string) = (yyvsp[-1].string); }
#line 2015 "yara_grammar.c"
    break;

  case 30:
#line 507 "yara_grammar.y"
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
#line 2032 "yara_grammar.c"
    break;

  case 31:
#line 520 "yara_grammar.y"
      {
        compiler->error_line = yyget_lineno(yyscanner);
      }
#line 2040 "yara_grammar.c"
    break;

  case 32:
#line 524 "yara_grammar.y"
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
#line 2057 "yara_grammar.c"
    break;

  case 33:
#line 537 "yara_grammar.y"
      {
        (yyval.string) = yr_parser_reduce_string_declaration(
            yyscanner,
            STRING_GFLAGS_HEXADECIMAL,
            (yyvsp[-2].c_string),
            (yyvsp[0].sized_string));

        yr_free((yyvsp[-2].c_string));
        yr_free((yyvsp[0].sized_string));

        ERROR_IF((yyval.string) == NULL);
      }
#line 2074 "yara_grammar.c"
    break;

  case 34:
#line 553 "yara_grammar.y"
                                          { (yyval.integer) = 0; }
#line 2080 "yara_grammar.c"
    break;

  case 35:
#line 554 "yara_grammar.y"
                                          { (yyval.integer) = (yyvsp[-1].integer) | (yyvsp[0].integer); }
#line 2086 "yara_grammar.c"
    break;

  case 36:
#line 559 "yara_grammar.y"
                    { (yyval.integer) = STRING_GFLAGS_WIDE; }
#line 2092 "yara_grammar.c"
    break;

  case 37:
#line 560 "yara_grammar.y"
                    { (yyval.integer) = STRING_GFLAGS_ASCII; }
#line 2098 "yara_grammar.c"
    break;

  case 38:
#line 561 "yara_grammar.y"
                    { (yyval.integer) = STRING_GFLAGS_NO_CASE; }
#line 2104 "yara_grammar.c"
    break;

  case 39:
#line 562 "yara_grammar.y"
                    { (yyval.integer) = STRING_GFLAGS_FULL_WORD; }
#line 2110 "yara_grammar.c"
    break;

  case 40:
#line 568 "yara_grammar.y"
      {
        YR_OBJECT* object = NULL;
        YR_RULE* rule;

        char* id;
        char* ns = NULL;

        int var_index;

        var_index = yr_parser_lookup_loop_variable(yyscanner, (yyvsp[0].c_string));

        if (var_index >= 0)
        {
         compiler->last_result = yr_parser_emit_with_arg(
            yyscanner,
            OP_PUSH_M,
            LOOP_LOCAL_VARS * var_index,
            NULL);

          (yyval.object) = (YR_OBJECT*) -1;
        }
        else
        {
          // Search for identifier within the global namespace, where the
          // externals variables reside.
          object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table,
                (yyvsp[0].c_string),
                NULL);
          if (object == NULL)
          {
            // If not found, search within the current namespace.

            ns = compiler->current_namespace->name;
            object = (YR_OBJECT*) yr_hash_table_lookup(
                compiler->objects_table,
                (yyvsp[0].c_string),
                ns);
          }

          if (object != NULL)
          {
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
          }
          else
          {
           rule = (YR_RULE*) yr_hash_table_lookup(
                compiler->rules_table,
                (yyvsp[0].c_string),
                compiler->current_namespace->name);
            if (rule != NULL)
            {
              compiler->last_result = yr_parser_emit_with_arg_reloc(
                  yyscanner,
                  OP_PUSH_RULE,
                  PTR_TO_UINT64(rule),
                  NULL);
            }
            else
            {
              yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
              compiler->last_result = ERROR_UNDEFINED_IDENTIFIER;
            }

            (yyval.object) = (YR_OBJECT*) -2;
          }
        }

        yr_free((yyvsp[0].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 2199 "yara_grammar.c"
    break;

  case 41:
#line 653 "yara_grammar.y"
      {
        YR_OBJECT* object = (yyvsp[-2].object);
        YR_OBJECT* field = NULL;

        char* ident;

        if (object != NULL &&
            object != (YR_OBJECT*) -1 &&    // not a loop variable identifier
            object != (YR_OBJECT*) -2 &&    // not a rule identifier
            object->type == OBJECT_TYPE_STRUCTURE)
        {
#if REAL_YARA
         field = yr_object_lookup_field(object, (yyvsp[0].c_string));
#endif
          if (field != NULL)
          {
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
          }
          else
          {
            yr_compiler_set_error_extra_info(compiler, (yyvsp[0].c_string));
            compiler->last_result = ERROR_INVALID_FIELD_NAME;
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              object->identifier);

          compiler->last_result = ERROR_NOT_A_STRUCTURE;
        }

        (yyval.object) = field;

        yr_free((yyvsp[0].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 2253 "yara_grammar.c"
    break;

  case 42:
#line 703 "yara_grammar.y"
      {
        if ((yyvsp[-3].object) != NULL && (yyvsp[-3].object)->type == OBJECT_TYPE_ARRAY)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_INDEX_ARRAY,
              NULL);

          (yyval.object) = ((YR_OBJECT_ARRAY*) (yyvsp[-3].object))->items->objects[0];
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[-3].object)->identifier);

          compiler->last_result = ERROR_NOT_AN_ARRAY;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 2279 "yara_grammar.c"
    break;

  case 43:
#line 726 "yara_grammar.y"
      {
        int args_count;

        if ((yyvsp[-3].object) != NULL && (yyvsp[-3].object)->type == OBJECT_TYPE_FUNCTION)
        {
          compiler->last_result = yr_parser_check_types(
              compiler, (YR_OBJECT_FUNCTION*) (yyvsp[-3].object), (yyvsp[-1].c_string));

          if (compiler->last_result == ERROR_SUCCESS)
          {
            args_count = strlen((yyvsp[-1].c_string));

            compiler->last_result = yr_parser_emit_with_arg(
                yyscanner,
                OP_CALL,
                args_count,
                NULL);
          }

          (yyval.object) = ((YR_OBJECT_FUNCTION*) (yyvsp[-3].object))->return_obj;
        }
        else
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[-3].object)->identifier);

          compiler->last_result = ERROR_NOT_A_FUNCTION;
        }

        yr_free((yyvsp[-1].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 2318 "yara_grammar.c"
    break;

  case 44:
#line 765 "yara_grammar.y"
      {
        (yyval.c_string) = yr_strdup("");
      }
#line 2326 "yara_grammar.c"
    break;

  case 45:
#line 769 "yara_grammar.y"
      {
        (yyval.c_string) = yr_malloc(MAX_FUNCTION_ARGS + 1);

        switch((yyvsp[0].expression_type))
        {
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
#line 2352 "yara_grammar.c"
    break;

  case 46:
#line 791 "yara_grammar.y"
      {
        if (strlen((yyvsp[-2].c_string)) == MAX_FUNCTION_ARGS)
        {
          compiler->last_result = ERROR_TOO_MANY_ARGUMENTS;
        }
        else
        {
          switch((yyvsp[0].expression_type))
          {
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
#line 2385 "yara_grammar.c"
    break;

  case 47:
#line 824 "yara_grammar.y"
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
#line 2432 "yara_grammar.c"
    break;

  case 48:
#line 871 "yara_grammar.y"
      {
        if ((yyvsp[0].expression_type) == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_TO_BOOL,
              NULL);

          ERROR_IF(compiler->last_result != ERROR_SUCCESS);
        }


        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2451 "yara_grammar.c"
    break;

  case 49:
#line 889 "yara_grammar.y"
      {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 1, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2464 "yara_grammar.c"
    break;

  case 50:
#line 898 "yara_grammar.y"
      {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, 0, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2477 "yara_grammar.c"
    break;

  case 51:
#line 907 "yara_grammar.y"
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
#line 2496 "yara_grammar.c"
    break;

  case 52:
#line 922 "yara_grammar.y"
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
#line 2514 "yara_grammar.c"
    break;

  case 53:
#line 936 "yara_grammar.y"
      {
        int result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[0].c_string),
            OP_STR_FOUND);

        yr_free((yyvsp[0].c_string));

        ERROR_IF(result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2531 "yara_grammar.c"
    break;

  case 54:
#line 949 "yara_grammar.y"
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
#line 2552 "yara_grammar.c"
    break;

  case 55:
#line 966 "yara_grammar.y"
      {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[-2].c_string),
            OP_STR_FOUND_IN);

        yr_free((yyvsp[-2].c_string));

        ERROR_IF(compiler->last_result!= ERROR_SUCCESS);

        compiler->current_rule_clflags |= RULE_OFFSETS;

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2571 "yara_grammar.c"
    break;

  case 56:
#line 981 "yara_grammar.y"
      {
        int var_index;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
              ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        var_index = yr_parser_lookup_loop_variable(
            yyscanner,
            (yyvsp[-1].c_string));

        if (var_index >= 0)
        {
          yr_compiler_set_error_extra_info(
              compiler,
              (yyvsp[-1].c_string));

          compiler->last_result = \
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
#line 2609 "yara_grammar.c"
    break;

  case 57:
#line 1015 "yara_grammar.y"
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

        if ((yyvsp[-1].integer) == INTEGER_SET_ENUMERATION)
        {
          // Pop the first integer
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, &addr);
        }
        else // INTEGER_SET_RANGE
        {
          // Pop higher bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset + 3, &addr);

          // Pop lower bound of set range
          yr_parser_emit_with_arg(
              yyscanner, OP_POP_M, mem_offset, NULL);
        }
        compiler->loop_address[compiler->loop_depth] = addr;
        compiler->loop_identifier[compiler->loop_depth] = (yyvsp[-4].c_string);
        compiler->loop_depth++;
      }
#line 2648 "yara_grammar.c"
    break;

  case 58:
#line 1050 "yara_grammar.y"
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

        if ((yyvsp[-5].integer) == INTEGER_SET_ENUMERATION)
        {
          yr_parser_emit_with_arg_reloc(
              yyscanner,
              OP_JNUNDEF,
              PTR_TO_UINT64(
                  compiler->loop_address[compiler->loop_depth]),
              NULL);
        }
        else // INTEGER_SET_RANGE
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

        yr_parser_emit(yyscanner, OP_LE, NULL);

        compiler->loop_identifier[compiler->loop_depth] = NULL;
        yr_free((yyvsp[-8].c_string));

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2728 "yara_grammar.c"
    break;

  case 59:
#line 1126 "yara_grammar.y"
      {
        int mem_offset = LOOP_LOCAL_VARS * compiler->loop_depth;
        int8_t* addr;

        if (compiler->loop_depth == MAX_LOOP_NESTING)
          compiler->last_result = \
            ERROR_LOOP_NESTING_LIMIT_EXCEEDED;

        if (compiler->loop_for_of_mem_offset != -1)
          compiler->last_result = \
            ERROR_NESTED_FOR_OF_LOOP;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 1, NULL);

        yr_parser_emit_with_arg(
            yyscanner, OP_CLEAR_M, mem_offset + 2, NULL);

        // Pop the first string.
        yr_parser_emit_with_arg(
            yyscanner, OP_POP_M, mem_offset, &addr);

        compiler->loop_for_of_mem_offset = mem_offset;
        compiler->loop_address[compiler->loop_depth] = addr;
        compiler->loop_identifier[compiler->loop_depth] = NULL;
        compiler->loop_depth++;
      }
#line 2762 "yara_grammar.c"
    break;

  case 60:
#line 1156 "yara_grammar.y"
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

        yr_parser_emit(yyscanner, OP_LE, NULL);
        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;

      }
#line 2812 "yara_grammar.c"
    break;

  case 61:
#line 1202 "yara_grammar.y"
      {
        yr_parser_emit(yyscanner, OP_OF, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2822 "yara_grammar.c"
    break;

  case 62:
#line 1208 "yara_grammar.y"
      {
        yr_parser_emit(yyscanner, OP_NOT, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2832 "yara_grammar.c"
    break;

  case 63:
#line 1214 "yara_grammar.y"
      {
        yr_parser_emit(yyscanner, OP_AND, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2842 "yara_grammar.c"
    break;

  case 64:
#line 1220 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_BOOLEAN, "or");

        yr_parser_emit(yyscanner, OP_OR, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2854 "yara_grammar.c"
    break;

  case 65:
#line 1228 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "<");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "<");

        yr_parser_emit(yyscanner, OP_LT, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2867 "yara_grammar.c"
    break;

  case 66:
#line 1237 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, ">");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, ">");

        yr_parser_emit(yyscanner, OP_GT, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2880 "yara_grammar.c"
    break;

  case 67:
#line 1246 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "<=");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "<=");

        yr_parser_emit(yyscanner, OP_LE, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2893 "yara_grammar.c"
    break;

  case 68:
#line 1255 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, ">=");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, ">=");

        yr_parser_emit(yyscanner, OP_GE, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2906 "yara_grammar.c"
    break;

  case 69:
#line 1264 "yara_grammar.y"
      {
        if ((yyvsp[-2].expression_type) != (yyvsp[0].expression_type))
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for == operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ((yyvsp[-2].expression_type) == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_EQ,
              NULL);
        }
        else
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_EQ,
              NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2937 "yara_grammar.c"
    break;

  case 70:
#line 1291 "yara_grammar.y"
      {
        if ((yyvsp[-2].expression_type) != (yyvsp[0].expression_type))
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for == operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ((yyvsp[-2].expression_type) == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_EQ,
              NULL);
        }
        else
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_EQ,
              NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2968 "yara_grammar.c"
    break;

  case 71:
#line 1318 "yara_grammar.y"
      {
        if ((yyvsp[-2].expression_type) != (yyvsp[0].expression_type))
        {
          yr_compiler_set_error_extra_info(
              compiler, "mismatching types for != operator");
          compiler->last_result = ERROR_WRONG_TYPE;
        }
        else if ((yyvsp[-2].expression_type) == EXPRESSION_TYPE_STRING)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_SZ_NEQ,
              NULL);
        }
        else
        {
          compiler->last_result = yr_parser_emit(
              yyscanner,
              OP_NEQ,
              NULL);
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
      }
#line 2999 "yara_grammar.c"
    break;

  case 72:
#line 1345 "yara_grammar.y"
      {
        (yyval.expression_type) = (yyvsp[0].expression_type);
      }
#line 3007 "yara_grammar.c"
    break;

  case 73:
#line 1349 "yara_grammar.y"
      {
        (yyval.expression_type) = (yyvsp[-1].expression_type);
      }
#line 3015 "yara_grammar.c"
    break;

  case 74:
#line 1356 "yara_grammar.y"
                                   { (yyval.integer) = INTEGER_SET_ENUMERATION; }
#line 3021 "yara_grammar.c"
    break;

  case 75:
#line 1357 "yara_grammar.y"
                                   { (yyval.integer) = INTEGER_SET_RANGE; }
#line 3027 "yara_grammar.c"
    break;

  case 76:
#line 1363 "yara_grammar.y"
      {
        if ((yyvsp[-4].expression_type) != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's lower bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        if ((yyvsp[-1].expression_type) != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for range's upper bound");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3049 "yara_grammar.c"
    break;

  case 77:
#line 1385 "yara_grammar.y"
      {
        if ((yyvsp[0].expression_type) != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;

        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3065 "yara_grammar.c"
    break;

  case 78:
#line 1397 "yara_grammar.y"
      {
        if ((yyvsp[0].expression_type) != EXPRESSION_TYPE_INTEGER)
        {
          yr_compiler_set_error_extra_info(
              compiler, "wrong type for enumeration item");
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3080 "yara_grammar.c"
    break;

  case 79:
#line 1412 "yara_grammar.y"
      {
        // Push end-of-list marker
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
      }
#line 3089 "yara_grammar.c"
    break;

  case 81:
#line 1418 "yara_grammar.y"
      {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
        yr_parser_emit_pushes_for_strings(yyscanner, "$*");
#ifdef YARA_PROTO
        compiler->current_rule_clflags |= RULE_THEM;
#endif
      }
#line 3101 "yara_grammar.c"
    break;

  case 84:
#line 1436 "yara_grammar.y"
      {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));
      }
#line 3110 "yara_grammar.c"
    break;

  case 85:
#line 1441 "yara_grammar.y"
      {
        yr_parser_emit_pushes_for_strings(yyscanner, (yyvsp[0].c_string));
        yr_free((yyvsp[0].c_string));
      }
#line 3119 "yara_grammar.c"
    break;

  case 87:
#line 1451 "yara_grammar.y"
      {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, UNDEFINED, NULL);
#ifdef YARA_PROTO
        compiler->current_rule_clflags |= RULE_ALL;
#endif
      }
#line 3130 "yara_grammar.c"
    break;

  case 88:
#line 1458 "yara_grammar.y"
      {
        yr_parser_emit_with_arg(yyscanner, OP_PUSH, 1, NULL);
#ifdef YARA_PROTO
        compiler->current_rule_clflags |= RULE_ANY;
#endif
      }
#line 3141 "yara_grammar.c"
    break;

  case 89:
#line 1469 "yara_grammar.y"
      {
        (yyval.expression_type) = (yyvsp[-1].expression_type);
      }
#line 3149 "yara_grammar.c"
    break;

  case 90:
#line 1473 "yara_grammar.y"
      {
        compiler->last_result = yr_parser_emit(
            yyscanner, OP_FILESIZE, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3162 "yara_grammar.c"
    break;

  case 91:
#line 1482 "yara_grammar.y"
      {
#ifndef YARA_PROTO
        yywarning(yyscanner,
            "Using deprecated \"entrypoint\" keyword. Use the \"entry_point\" " "function from PE module instead.");
#else
        compiler->current_rule_clflags |= RULE_EP;
#endif
        compiler->last_result = yr_parser_emit(
            yyscanner, OP_ENTRYPOINT, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3181 "yara_grammar.c"
    break;

  case 92:
#line 1497 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "int8");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT8, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3196 "yara_grammar.c"
    break;

  case 93:
#line 1508 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "int16");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT16, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3211 "yara_grammar.c"
    break;

  case 94:
#line 1519 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "int32");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_INT32, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3226 "yara_grammar.c"
    break;

  case 95:
#line 1530 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "uint8");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_UINT8, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3241 "yara_grammar.c"
    break;

  case 96:
#line 1541 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "uint16");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_UINT16, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3256 "yara_grammar.c"
    break;

  case 97:
#line 1552 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-1].expression_type), EXPRESSION_TYPE_INTEGER, "uint32");

        compiler->last_result = yr_parser_emit(
            yyscanner, OP_UINT32, NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3271 "yara_grammar.c"
    break;

  case 98:
#line 1563 "yara_grammar.y"
      {
        compiler->last_result = yr_parser_emit_with_arg(
            yyscanner, OP_PUSH, (yyvsp[0].integer), NULL);

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3284 "yara_grammar.c"
    break;

  case 99:
#line 1572 "yara_grammar.y"
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
#line 3315 "yara_grammar.c"
    break;

  case 100:
#line 1599 "yara_grammar.y"
      {
        compiler->last_result = yr_parser_reduce_string_identifier(
            yyscanner,
            (yyvsp[0].c_string),
            OP_STR_COUNT);

        yr_free((yyvsp[0].c_string));

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3332 "yara_grammar.c"
    break;

  case 101:
#line 1612 "yara_grammar.y"
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
#line 3351 "yara_grammar.c"
    break;

  case 102:
#line 1627 "yara_grammar.y"
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
#line 3377 "yara_grammar.c"
    break;

  case 103:
#line 1649 "yara_grammar.y"
      {
        if ((yyvsp[0].object) == (YR_OBJECT*) -1)  // loop identifier
        {
          (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
        }
        else if ((yyvsp[0].object) == (YR_OBJECT*) -2)  // rule identifier
        {
          (yyval.expression_type) = EXPRESSION_TYPE_BOOLEAN;
        }
        else if ((yyvsp[0].object) != NULL)
        {
          compiler->last_result = yr_parser_emit(
              yyscanner, OP_OBJ_VALUE, NULL);

          switch((yyvsp[0].object)->type)
          {
            case OBJECT_TYPE_INTEGER:
              (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
              break;
            case OBJECT_TYPE_STRING:
              (yyval.expression_type) = EXPRESSION_TYPE_STRING;
              break;
            default:
              assert(FALSE);
          }
        }
        else
        {
          yr_compiler_set_error_extra_info(compiler, (yyvsp[0].object)->identifier);
          compiler->last_result = ERROR_WRONG_TYPE;
        }

        ERROR_IF(compiler->last_result != ERROR_SUCCESS);
      }
#line 3416 "yara_grammar.c"
    break;

  case 104:
#line 1684 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "+");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "+");

        yr_parser_emit(yyscanner, OP_ADD, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3429 "yara_grammar.c"
    break;

  case 105:
#line 1693 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "-");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "-");

        yr_parser_emit(yyscanner, OP_SUB, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3442 "yara_grammar.c"
    break;

  case 106:
#line 1702 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "*");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "*");

        yr_parser_emit(yyscanner, OP_MUL, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3455 "yara_grammar.c"
    break;

  case 107:
#line 1711 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "\\");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "\\");

        yr_parser_emit(yyscanner, OP_DIV, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3468 "yara_grammar.c"
    break;

  case 108:
#line 1720 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "%");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "%");

        yr_parser_emit(yyscanner, OP_MOD, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3481 "yara_grammar.c"
    break;

  case 109:
#line 1729 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_XOR, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3494 "yara_grammar.c"
    break;

  case 110:
#line 1738 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "^");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "^");

        yr_parser_emit(yyscanner, OP_AND, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3507 "yara_grammar.c"
    break;

  case 111:
#line 1747 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "|");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "|");

        yr_parser_emit(yyscanner, OP_OR, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3520 "yara_grammar.c"
    break;

  case 112:
#line 1756 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "~");

        yr_parser_emit(yyscanner, OP_NEG, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3532 "yara_grammar.c"
    break;

  case 113:
#line 1764 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, "<<");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, "<<");

        yr_parser_emit(yyscanner, OP_SHL, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3545 "yara_grammar.c"
    break;

  case 114:
#line 1773 "yara_grammar.y"
      {
        CHECK_TYPE((yyvsp[-2].expression_type), EXPRESSION_TYPE_INTEGER, ">>");
        CHECK_TYPE((yyvsp[0].expression_type), EXPRESSION_TYPE_INTEGER, ">>");

        yr_parser_emit(yyscanner, OP_SHR, NULL);

        (yyval.expression_type) = EXPRESSION_TYPE_INTEGER;
      }
#line 3558 "yara_grammar.c"
    break;

  case 115:
#line 1782 "yara_grammar.y"
      {
        (yyval.expression_type) = (yyvsp[0].expression_type);
      }
#line 3566 "yara_grammar.c"
    break;


#line 3570 "yara_grammar.c"

      default: break;
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
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
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
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (yyscanner, compiler, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *, YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yyscanner, compiler, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
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

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, yyscanner, compiler);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (yyscanner, compiler, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif


/*-----------------------------------------------------.
| yyreturn -- parsing is finished, return the result.  |
`-----------------------------------------------------*/
yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, yyscanner, compiler);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[+*yyssp], yyvsp, yyscanner, compiler);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 1787 "yara_grammar.y"

