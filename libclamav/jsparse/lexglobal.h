/*
 *  Javascript normalizer.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#ifndef YYSTYPE
enum token_type {
	TOK_FUTURE_RESERVED_WORD=1,
	TOK_ERROR,
	TOK_IDENTIFIER_NAME,
	TOK_TRUE,
	TOK_FALSE,
	TOK_NULL,
	TOK_BRACKET_OPEN,
	TOK_BRACKET_CLOSE,
	TOK_COMMA,
	TOK_CURLY_BRACE_OPEN,
	TOK_CURLY_BRACE_CLOSE,
	TOK_PAR_OPEN,
	TOK_PAR_CLOSE,
	TOK_DOT,
	TOK_SEMICOLON,
	TOK_COLON,
	TOK_NEW,
	TOK_NumericInt,
	TOK_NumericFloat,
	TOK_StringLiteral,
	TOK_REGULAR_EXPRESSION_LITERAL,
	TOK_THIS,
	TOK_PLUSPLUS,
	TOK_MINUSMINUS,
	TOK_DELETE,
	TOK_VOID,
	TOK_TYPEOF,
	TOK_MINUS,
	TOK_TILDE,
	TOK_EXCLAMATION,
	TOK_MULTIPLY,
	TOK_DIVIDE,
	TOK_PERCENT,
	TOK_PLUS,
	TOK_SHIFT_LEFT,
	TOK_SHIFT_RIGHT,
	TOK_DOUBLESHIFT_RIGHT,
	TOK_LESS,
	TOK_GREATER,
	TOK_LESSEQUAL,
	TOK_GREATEREQUAL,
	TOK_INSTANCEOF,
	TOK_IN,
	TOK_EQUAL_EQUAL,
	TOK_NOT_EQUAL,
	TOK_TRIPLE_EQUAL,
	TOK_NOT_DOUBLEEQUAL,
	TOK_AND,
	TOK_XOR,
	TOK_OR,
	TOK_AND_AND,
	TOK_OR_OR,
	TOK_QUESTIONMARK,
	TOK_EQUAL,
	TOK_ASSIGNMENT_OPERATOR_NOEQUAL,
	TOK_VAR,
	TOK_IF,
	TOK_ELSE,
	TOK_DO,
	TOK_WHILE,
	TOK_FOR,
	TOK_CONTINUE,
	TOK_BREAK,
	TOK_RETURN,
	TOK_WITH,
	TOK_SWITCH,
	TOK_CASE,
	TOK_DEFAULT,
	TOK_THROW,
	TOK_TRY,
	TOK_CATCH,
	TOK_FINALLY,
	TOK_FUNCTION,
	TOK_UNNORM_IDENTIFIER
};

enum val_type {
	vtype_undefined,
	vtype_cstring,
	vtype_string,
	vtype_scope,
	vtype_dval,
	vtype_ival
};

typedef struct token {
	union {
		const char *cstring;
		char  *string;
		struct scope *scope;/* for function */
		double dval;
		long   ival;
	} val;
	enum token_type type;
	enum val_type   vtype;
} yystype;

/* inline functions to access the structure to ensure type safety */

#define TOKEN_SET(DST, VTYPE, VAL) do {\
	(DST)->vtype = vtype_##VTYPE ; (DST)->val.VTYPE = (VAL); \
} while(0);

#define cstring_invalid NULL
#define string_invalid NULL
#define scope_invalid NULL
/* there isn't really an invalid double, or long value, but we don't care
 * about those values anyway, so -1 will be fine here */
#define dval_invalid -1
#define ival_invalid -1

/* compatible if same type, or if we request a const char* instead of char*,
 * but not viceversa! */
static int vtype_compatible(enum val_type orig, enum val_type req)
{
	return orig == req || (orig == vtype_string && req == vtype_cstring);
}

#define TOKEN_GET(SRC, VTYPE) (vtype_compatible((SRC)->vtype, vtype_##VTYPE) ? (SRC)->val.VTYPE : VTYPE##_invalid)

#define YYSTYPE yystype
#endif
