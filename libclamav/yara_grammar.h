/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

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

#line 53 "yara_grammar.h"

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    _RULE_ = 258,                  /* _RULE_  */
    _PRIVATE_ = 259,               /* _PRIVATE_  */
    _GLOBAL_ = 260,                /* _GLOBAL_  */
    _META_ = 261,                  /* _META_  */
    _STRINGS_ = 262,               /* _STRINGS_  */
    _CONDITION_ = 263,             /* _CONDITION_  */
    _IDENTIFIER_ = 264,            /* _IDENTIFIER_  */
    _STRING_IDENTIFIER_ = 265,     /* _STRING_IDENTIFIER_  */
    _STRING_COUNT_ = 266,          /* _STRING_COUNT_  */
    _STRING_OFFSET_ = 267,         /* _STRING_OFFSET_  */
    _STRING_IDENTIFIER_WITH_WILDCARD_ = 268, /* _STRING_IDENTIFIER_WITH_WILDCARD_  */
    _NUMBER_ = 269,                /* _NUMBER_  */
    _TEXT_STRING_ = 270,           /* _TEXT_STRING_  */
    _HEX_STRING_ = 271,            /* _HEX_STRING_  */
    _REGEXP_ = 272,                /* _REGEXP_  */
    _ASCII_ = 273,                 /* _ASCII_  */
    _WIDE_ = 274,                  /* _WIDE_  */
    _XOR_ = 275,                   /* _XOR_  */
    _BASE64_ = 276,                /* _BASE64_  */
    _BASE64_WIDE_ = 277,           /* _BASE64_WIDE_  */
    _NOCASE_ = 278,                /* _NOCASE_  */
    _FULLWORD_ = 279,              /* _FULLWORD_  */
    _AT_ = 280,                    /* _AT_  */
    _FILESIZE_ = 281,              /* _FILESIZE_  */
    _ENTRYPOINT_ = 282,            /* _ENTRYPOINT_  */
    _ALL_ = 283,                   /* _ALL_  */
    _ANY_ = 284,                   /* _ANY_  */
    _IN_ = 285,                    /* _IN_  */
    _OF_ = 286,                    /* _OF_  */
    _FOR_ = 287,                   /* _FOR_  */
    _THEM_ = 288,                  /* _THEM_  */
    _INT8_ = 289,                  /* _INT8_  */
    _INT16_ = 290,                 /* _INT16_  */
    _INT32_ = 291,                 /* _INT32_  */
    _UINT8_ = 292,                 /* _UINT8_  */
    _UINT16_ = 293,                /* _UINT16_  */
    _UINT32_ = 294,                /* _UINT32_  */
    _MATCHES_ = 295,               /* _MATCHES_  */
    _CONTAINS_ = 296,              /* _CONTAINS_  */
    _IMPORT_ = 297,                /* _IMPORT_  */
    _TRUE_ = 298,                  /* _TRUE_  */
    _FALSE_ = 299,                 /* _FALSE_  */
    _OR_ = 300,                    /* _OR_  */
    _AND_ = 301,                   /* _AND_  */
    _LT_ = 302,                    /* _LT_  */
    _LE_ = 303,                    /* _LE_  */
    _GT_ = 304,                    /* _GT_  */
    _GE_ = 305,                    /* _GE_  */
    _EQ_ = 306,                    /* _EQ_  */
    _NEQ_ = 307,                   /* _NEQ_  */
    _IS_ = 308,                    /* _IS_  */
    _SHIFT_LEFT_ = 309,            /* _SHIFT_LEFT_  */
    _SHIFT_RIGHT_ = 310,           /* _SHIFT_RIGHT_  */
    _NOT_ = 311                    /* _NOT_  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 233 "yara_grammar.y"

  SIZED_STRING*   sized_string;
  char*           c_string;
  int8_t          expression_type;
  int64_t         integer;
  YR_STRING*      string;
  YR_META*        meta;
  YR_OBJECT*      object;

#line 136 "yara_grammar.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif




int yara_yyparse (void *yyscanner, YR_COMPILER* compiler);


#endif /* !YY_YARA_YY_YARA_GRAMMAR_H_INCLUDED  */
