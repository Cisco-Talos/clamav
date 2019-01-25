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
#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "clamav.h"
#include "jsparse/lexglobal.h"
#include "hashtab.h"
#include "others.h"
#include "str.h"
#include "js-norm.h"
#include "jsparse/generated/operators.h"
#include "jsparse/generated/keywords.h"
#include "jsparse/textbuf.h"

/* ----------- tokenizer ---------------- */
enum tokenizer_state {
	Initial,
	MultilineComment,
	SinglelineComment,
	Number,
	DoubleQString,
	SingleQString,
	Identifier,
	Dummy
};


typedef struct scanner {
	struct text_buffer buf;
	const char *yytext;
	size_t yylen;
	const char *in;
	size_t insize;
	size_t pos;
	size_t lastpos;
	enum tokenizer_state state;
	enum tokenizer_state last_state;
} *yyscan_t;

typedef int YY_BUFFER_STATE;

static int yylex( YYSTYPE *lvalp, yyscan_t  );
static YY_BUFFER_STATE yy_scan_bytes( const char *, size_t, yyscan_t scanner );
static const char *yyget_text ( yyscan_t scanner );
static int yyget_leng ( yyscan_t scanner );
static int yylex_init ( yyscan_t * ptr_yy_globals ) ;
static int yylex_destroy ( yyscan_t yyscanner ) ;
/* ----------- tokenizer end ---------------- */

enum fsm_state {
	Base,
	InsideVar,
	InsideInitializer,
	WaitFunctionName,
	WaitParameterList,
	InsideFunctionDecl
};

struct scope {
	struct cli_hashtable id_map;
	struct scope *parent;/* hierarchy */
	struct scope *nxt;/* all scopes kept in a list so we can easily free all of them */
	enum fsm_state fsm_state;
	int  last_token;
	unsigned int brackets;
	unsigned int blocks;
};

struct tokens {
	yystype *data;
	size_t   cnt;
	size_t   capacity;
};

/* state for the current JS file being parsed */
struct parser_state {
	unsigned long     var_uniq;
	unsigned long     syntax_errors;
	struct scope *global;
	struct scope *current;
	struct scope *list;
	yyscan_t scanner;
	struct tokens tokens;
	unsigned int      rec;
};

static struct scope* scope_new(struct parser_state *state)
{
	struct scope *parent = state->current;
	struct scope *s = cli_calloc(1, sizeof(*s));
	if(!s)
		return NULL;
	if(cli_hashtab_init(&s->id_map, 10) < 0) {
		free(s);
		return NULL;
	}
	s->parent = parent;
	s->fsm_state = Base;
	s->nxt = state->list;
	state->list = s;
	state->current = s;
	return s;
}

static struct scope* scope_done(struct scope *s)
{
	struct scope* parent = s->parent;
	/* TODO: have a hashtab_destroy */
	cli_hashtab_clear(&s->id_map);
	free(s->id_map.htable);
	free(s);
	return parent;
}

/* transitions:
 *   Base --(VAR)--> InsideVar
 *   InsideVar --(Identifier)-->InsideInitializer
 *   InsideVar --(anything_else) --> POP (to Base)
 *   InsideInitializer --(COMMA)--> POP (to InsideVar)
 *   InsideInitializer | InsideVar --(SEMICOLON) --> POP (to Base)
 *   InsideInitializer --(BRACKET_OPEN) --> WaitBrClose
 *   InsideInitializer --(PAR_OPEN) --> WaitParClose
 *   WaitBrClose --(BRACKET_OPEN) --> increase depth
 *   WaitBrClose --(BRACKET_CLOSE) --> POP
 *   WaitParClose --(PAR_CLOSE) --> POP
 *   WaitParClose --(PAR_OPEN) --> increase depth
 */

/* Base --(VAR)--> PUSH, to InsideVar
 * InsideVar --(Identifier)--> InsideInitializer
 * InsideVar --(ELSE)--> POP, inc. syntax_errors
 * InsideInitializer --(COMMA)--> POP (to InsideVar)
 * --(BRACKET_OPEN)--> inc bracket_counter
 * --(PAR_OPEN)--> inc par_counter
 * --(BRACKET_CLOSE) --> dec bracket_counter
 * --(PAR_CLOSE)--> dec par_counter
 * --(VAR)--> PUSH, to InsideVar (if bracket_counter != 0 || par_counter != 0)
 *        --> POP, to InsideVar, inc. syntax_errors (if bracket_counter == 0  && par_counter == 0)
 *  POP only allowed if bracket_counter == 0 && par_counter == 0 
 *
 * InsideInitializer acts differently, make it only a flag
 * ....................
 *
 * Pushing, Poping is done when entering / exiting function scopes,
 * tracking { and function ( is done by the function scope tracker too.
 *
 * we only need to track brackets.
 */


/*
 * var x = document;
 * x.writeln(...);
 *
 * ^we must not normalize member method names
 */

/*
 * Variables are declared at function scope, and their initial value is
 * undefined. At the point where the initializer is, and from there on the value
 * is defined.
 *
 * { doesn't introduce a new variable scope, they are in function's scope too
 *
 * function foo() {
 *  alert(x); -> x exists, undefined
 *  var x=5; 
 *  alert(x); -> x exists, =5
 * }
 * 
 * vs.
 *
 * function bar() {
 *   alert(x);//error, x not declared
 *   x=5;
 *   }
 *
 * vs.
 *
 * but we can declare variables without var, only valid if we use them after
 * assigning.
 *
 * function foobar() {
 *   x=5;
 *   alert(x);//x is defined, value is 5
 *   }
 *
 * other examples:
 * function foo2() {
 *   alert(x); -> x exists, undefined
 *   {
 *       var x=5; -> x equals to 5
 *   }
 *   alert(x); -> x is 5
 * }
 *
 * function foo3() {
 *   var x=4; -> x exists, equals to 4
 *   alert(x); -> x exists, equals to 4
 *   {
 *       var x=5; -> x equals to 5
 *   }
 *   alert(x); -> x is 5
 * }
 *
 * function bar3() {
 *   //same as foo3
 *   var x=4;
 *   alert(x);
 *   { 
 *        x=5;
 *   }
 *   alert(x);
 * }
 *
 */


static const char* scope_declare(struct scope *s, const char *token, const size_t len, struct parser_state *state)
{
	const struct cli_element *el = cli_hashtab_insert(&s->id_map, token, len, state->var_uniq++);
	/* cli_hashtab_insert either finds an already existing entry, or allocates a
	 * new one, we return the allocated string */
	return el ? el->key : NULL;
}

static const char* scope_use(struct scope *s, const char *token, const size_t len)
{
	const struct cli_element *el = cli_hashtab_find(&s->id_map, token, len);
	if(el) {
		/* identifier already found in current scope,
		 * return here to avoid overwriting uniq id */
		return el->key;
	}
	/* identifier not yet in current scope's hashtab, add with ID -1.
	 * Later if we find a declaration it will automatically assign a uniq ID
	 * to it. If not, we'll know that we have to push ID == -1 tokens to an
	 * outer scope.*/
	el = cli_hashtab_insert(&s->id_map, token, len, -1);
	return el ? el->key : NULL;
}

static long scope_lookup(struct scope *s, const char *token, const size_t len)
{
	while(s) {
		const struct cli_element *el = cli_hashtab_find(&s->id_map, token, len);
		if(el && el->data != -1) {
			return el->data;
		}
		/* not found in current scope, try in outer scope */
		s = s->parent;
	}
	return -1;
}

static int tokens_ensure_capacity(struct tokens *tokens, size_t cap)
{
	if(tokens->capacity < cap) {
	        yystype *data;
		cap += 1024;
		/* Keep old data if OOM */
		data = cli_realloc(tokens->data, cap * sizeof(*tokens->data));
		if(!data)
			return CL_EMEM;
		tokens->data = data;
		tokens->capacity = cap;
	}
	return CL_SUCCESS;
}

static int add_token(struct parser_state *state, const yystype *token)
{
	if(tokens_ensure_capacity(&state->tokens, state->tokens.cnt + 1))
		return -1;
	state->tokens.data[state->tokens.cnt++] = *token;
	return 0;
}

struct buf {
	size_t pos;
	int outfd;
	char buf[65536];
};

static inline int buf_outc(char c, struct buf *buf)
{
	if(buf->pos >= sizeof(buf->buf)) {
		if(write(buf->outfd, buf->buf, sizeof(buf->buf)) != sizeof(buf->buf))
			return CL_EWRITE;
		buf->pos = 0;
	}
	buf->buf[buf->pos++] = c;
	return CL_SUCCESS;
}

static inline int buf_outs(const char *s, struct buf *buf)
{
	const size_t buf_len = sizeof(buf->buf);
	size_t i;

	i = buf->pos;
	while(*s) {
		while(i < buf_len && *s) {
			if(isspace(*s & 0xff))
				buf->buf[i++] = ' ';
			else
				buf->buf[i++] = tolower((unsigned char)(*s));
			++s;
		}
		if(i == buf_len) {
			if(write(buf->outfd, buf->buf, buf_len) < 0)
				return CL_EWRITE;
		       i = 0;
		}
	}
	buf->pos = i;
	return CL_SUCCESS;
}

static inline void output_space(char last, char current, struct buf *out)
{
	if(isalnum(last) && isalnum(current))
		buf_outc(' ', out);
}


/* return class of last character */
static char output_token(const yystype *token, struct scope *scope, struct buf *out, char lastchar)
{
	char sbuf[128];
	const char *s = TOKEN_GET(token, cstring);
	/* TODO: use a local buffer, instead of FILE* */
	switch(token->type) {
		case TOK_StringLiteral:
			output_space(lastchar,'"', out);
			buf_outc('"', out);
			if(s) {
				buf_outs(s, out);
			}
			buf_outc('"', out);
			return '\"';
		case TOK_NumericInt:
			output_space(lastchar,'0', out);
			snprintf(sbuf, sizeof(sbuf), "%ld", TOKEN_GET(token, ival));
			buf_outs(sbuf, out);
			return '0';
		case TOK_NumericFloat:
			output_space(lastchar,'0', out);
			snprintf(sbuf, sizeof(sbuf), "%g", TOKEN_GET(token, dval));
			buf_outs(sbuf, out);
			return '0';
		case TOK_IDENTIFIER_NAME:
			output_space(lastchar,'a', out);
			if(s) {
				long id = scope_lookup(scope, s, strlen(s));
				if(id == -1) {
					/* identifier not normalized */
					buf_outs(s, out);
				} else {
					snprintf(sbuf, sizeof(sbuf), "n%03ld",id);
					buf_outs(sbuf, out);
				}
			}
			return 'a';
		case TOK_FUNCTION:
			output_space(lastchar,'a', out);
			buf_outs("function",out);
			return 'a';
		default:
			if(s) {
				const size_t len = strlen(s);
				output_space(lastchar,s[0], out);
				buf_outs(s, out);
				return len ? s[len-1] : '\0';
			}
			return '\0';
	}
}

/*
 * We can't delete the scope as soon as we see a }, because
 * we still need the hashmap from it.
 *
 * If we would normalize all the identifiers, and output when a scope is closed,
 * then it would be impossible to normalize calls to other functions.
 *
 * So we need to keep all scopes in memory, to do this instead of scope_done, we
 * simply just set current = current->parent when a scope is closed.
 * We keep a list of all scopes created in parser_state-> When we parsed
 * everything, we output everything, and then delete all scopes.
 *
 * We also need to know where to switch scopes on the second pass, so for
 * TOK_FUNCTION types we will use another pointer, that points to the scope
 * (added to yystype's union).
 *
 * We lookup the identifier in the scope (using scope_lookup, it looks in parent
 * scopes too), if ID is found then output (n%3d, Id),
 * otherwise output the identifier as is.
 *
 * To make  it easier to match sigs, we do a xfrm : 
 * 'function ID1 (..'. => 'n%3d = function (...'
 */

/*
 * we'll add all identifier to the scope's map
 * those that are not decl. will have initial ID -1
 * if we later see a decl for it in same scope, it'll automatically get a
 * correct ID.
 *
 * When parsing of local scope is done, we take any ID -1 identifiers,
 * and push them up one level (careful not to overwrite existing IDs).
 *
 * it would be nice if the tokens would contain a link to the entry in the
 * hashtab, a link that automatically gets updated when the element is moved
 * (pushed up). This would prevent subsequent lookups in the map,
 * when we want to output the tokens.
 * There is no easy way to do that, so we just do another lookup
 *
 */

/*
 * This actually works, redefining foo:
 * function foo() {
 *   var foo=5; alert(foo);
 * }
 * So we can't treat function names just as any other identifier?
 * We can, because you can no longer call foo, if you redefined it as a var.
 * So if we rename both foo-s with same name, it will have same behaviour.
 *
 * This means that a new scope should begin after function, and not after
 * function ... (.
 */

static void scope_free_all(struct scope *p)
{
	struct scope *nxt;
	do {
		nxt = p->nxt;
		scope_done(p);
		p = nxt;
	} while(p);
}

size_t cli_strtokenize(char *buffer, const char delim, const size_t token_count, const char **tokens);
static int match_parameters(const yystype *tokens, const char ** param_names, size_t count)
{
	size_t i,j=0;
	if(tokens[0].type != TOK_PAR_OPEN)
		return -1;
	i=1;
	while(count--) {
		const char *token_val = TOKEN_GET(&tokens[i], cstring);
		if(tokens[i].type != TOK_IDENTIFIER_NAME ||
		   !token_val ||
		   strcmp(token_val, param_names[j++]))
			return -1;
		++i;
		if((count && tokens[i].type != TOK_COMMA)
		   || (!count && tokens[i].type != TOK_PAR_CLOSE))
			return -1;
		++i;
	}
	return 0;
}

static const char *de_packer_3[] = {"p","a","c","k","e","r"};
static const char *de_packer_2[] = {"p","a","c","k","e","d"};

static inline char *textbuffer_done(yyscan_t scanner)
{
       char *str = cli_realloc(scanner->buf.data, scanner->buf.pos);
       if(!str) {
               str = scanner->buf.data;
       }
       scanner->yytext = str;
       scanner->yylen = scanner->buf.pos - 1;
       memset(&scanner->buf, 0, sizeof(scanner->buf));
       return str;
}

#define MODULE "JS-Norm: "

static void free_token(yystype *token)
{
	if(token->vtype == vtype_string) {
		free(token->val.string);
		token->val.string = NULL;
	}
}

static int replace_token_range(struct tokens *dst, size_t start, size_t end, const struct tokens *with)
{
	const size_t len = with ? with->cnt : 0;
	size_t i;
	cli_dbgmsg(MODULE "Replacing tokens %lu - %lu with %lu tokens\n", (unsigned long)start,
                   (unsigned long)end, (unsigned long)len);
	if(start >= dst->cnt || end > dst->cnt)
		return -1;
	for(i=start;i<end;i++) {
		free_token(&dst->data[i]);
	}
	if(tokens_ensure_capacity(dst, dst->cnt - (end-start) + len))
		return CL_EMEM;
	memmove(&dst->data[start+len], &dst->data[end], (dst->cnt - end) * sizeof(dst->data[0]));
	if(with && len > 0) {
		memcpy(&dst->data[start], with->data, len * sizeof(dst->data[0]));
	}
	dst->cnt = dst->cnt - (end-start) + len;
	return CL_SUCCESS;
}

static int append_tokens(struct tokens *dst, const struct tokens *src)
{
	if(!dst || !src)
		return CL_ENULLARG;
	if(tokens_ensure_capacity(dst, dst->cnt + src->cnt))
		return CL_EMEM;
	cli_dbgmsg(MODULE "Appending %lu tokens\n", (unsigned long)(src->cnt));
	memcpy(&dst->data[dst->cnt], src->data, src->cnt * sizeof(dst->data[0]));
	dst->cnt += src->cnt;
	return CL_SUCCESS;
}

static void decode_de(yystype *params[], struct text_buffer *txtbuf)
{
	const char *p = TOKEN_GET(params[0], cstring);
	const long a = TOKEN_GET(params[1], ival);
	/*const char *c = params[2];*/
	char *k = TOKEN_GET(params[3], string);
	/*const char *r = params[5];*/

	unsigned val=0;
	unsigned nsplit = 0;
	const char* o;
	const char **tokens;

	memset(txtbuf, 0, sizeof(*txtbuf));
	if(!p || !k )
		return;
	for(o = k; *o; o++) if(*o == '|') nsplit++;
	nsplit++;
	tokens = malloc(sizeof(char*)*nsplit);
	if(!tokens) {
		return;
	}
	cli_strtokenize(k,'|',nsplit, tokens);

	do {
		while(*p && !isalnum(*p)) {
			if(*p=='\\' && (p[1] == '\'' || p[1] == '\"'))
				p++;
			else
				textbuffer_putc(txtbuf, *p++);
		}
		if(!*p) break;
		val = 0;
		o = p;
		while(*p && isalnum(*p)) {
			unsigned x;
			unsigned char v = *p++;
			/* TODO: use a table here */
			if(v >= 'a') x = 10+v-'a';
			else if(v >= 'A') x = 36+v-'A';
			else x = v-'0';
			val = val*a+x;
		}
		if(val >= nsplit || !tokens[val] || !tokens[val][0])
			while(o!=p)
				textbuffer_putc(txtbuf, *o++);
		else	textbuffer_append(txtbuf, tokens[val]);
	} while (*p);
	free(tokens);
	textbuffer_append(txtbuf, "\0");
}

struct decode_result {
	struct text_buffer txtbuf;
	size_t pos_begin;
	size_t pos_end;
        unsigned append:1; /* 0: tokens are replaced with new token(s),
                            1: old tokens are deleted, new ones appended at the end */
};

static void handle_de(yystype *tokens, size_t start, const size_t cnt, const char *name, struct decode_result *res)
{
	/* find function decl. end */
	size_t i, nesting = 1, j;
	yystype* parameters [6];
	const size_t parameters_cnt = 6;

	for(i=start;i < cnt; i++) {
		if(tokens[i].type == TOK_FUNCTION) {
			if(TOKEN_GET(&tokens[i], scope))
				nesting++;
			else
				nesting--;
			if(!nesting)
				break;
		}
	}
	if(nesting)
		return;
	memset(parameters, 0, sizeof(parameters));
	if(name) {
		/* find call to function */
		for(;i+2 < cnt; i++) {
			const char* token_val = TOKEN_GET(&tokens[i], cstring);
			if(tokens[i].type == TOK_IDENTIFIER_NAME &&
			   token_val &&
			   !strcmp(name, token_val) &&
			   tokens[i+1].type == TOK_PAR_OPEN) {

				i += 2;
				for(j = 0;j < parameters_cnt && i < cnt;j++) {
					parameters[j] = &tokens[i++];
					if(j != parameters_cnt-1)
						while (tokens[i].type != TOK_COMMA && i < cnt) i++;
					else
						while (tokens[i].type != TOK_PAR_CLOSE && i < cnt) i++;
					i++;
				}
				if(j == parameters_cnt)
					decode_de(parameters, &res->txtbuf);
			}
		}
	} else {
		while(i<cnt && tokens[i].type != TOK_PAR_OPEN) i++;
		++i;
		if(i >= cnt) return;
		/* TODO: move this v to another func */
				for(j = 0;j < parameters_cnt && i < cnt;j++) {
					parameters[j] = &tokens[i++];
					if(j != parameters_cnt-1)
						while (tokens[i].type != TOK_COMMA && i < cnt) i++;
					else
						while (tokens[i].type != TOK_PAR_CLOSE && i < cnt) i++;
					i++;
				}
				if(j == parameters_cnt)
					decode_de(parameters, &res->txtbuf);
	}
	if(parameters[0] && parameters[parameters_cnt-1]) {
		res->pos_begin = parameters[0] - tokens;
		res->pos_end = parameters[parameters_cnt-1] - tokens + 1;
		if(tokens[res->pos_end].type == TOK_BRACKET_OPEN &&
				tokens[res->pos_end+1].type == TOK_BRACKET_CLOSE &&
				tokens[res->pos_end+2].type == TOK_PAR_CLOSE)
			res->pos_end += 3; /* {}) */
		else
			res->pos_end++; /* ) */
	}
}

static int handle_unescape(struct tokens *tokens, size_t start)
{
	if(tokens->data[start].type == TOK_StringLiteral) {
		char *R;
		struct tokens new_tokens;
		yystype tok;

		R = cli_unescape(TOKEN_GET(&tokens->data[start], cstring));
		tok.type = TOK_StringLiteral;
		TOKEN_SET(&tok, string, R);
		new_tokens.capacity = new_tokens.cnt = 1;
		new_tokens.data = &tok;
		if(replace_token_range(tokens, start-2, start+2, &new_tokens) < 0)
			return CL_EMEM;
	}
	return CL_SUCCESS;
}


/* scriptasylum dot com's JS encoder */
static void handle_df(const yystype *tokens, size_t start, struct decode_result *res)
{
	char *str, *s1;
	size_t len, s1_len, i;
	unsigned char clast;
	char *R;

	if(tokens[start].type != TOK_StringLiteral)
		return;
	str = TOKEN_GET(&tokens[start], string);
	if(!str)
		return;
	len = strlen(str);
	if(!len)
		return;
	clast = str[len-1] - '0';

	str[len-1] = '\0';
	s1 = cli_unescape(str);
	s1_len = strlen(s1);
	for(i=0;i<s1_len;i++) {
		s1[i] -= clast;
	}
	R = cli_unescape(s1);
	free(s1);
	res->pos_begin = start-2;
	res->pos_end = start+2;
	res->txtbuf.data = R;
	res->txtbuf.pos = strlen(R);
	res->append = 1;
}



static void handle_eval(struct tokens *tokens, size_t start, struct decode_result *res)
{
	res->txtbuf.data = TOKEN_GET(&tokens->data[start], string);
	if(res->txtbuf.data && tokens->data[start+1].type == TOK_PAR_CLOSE) {
		TOKEN_SET(&tokens->data[start], string, NULL);
		res->txtbuf.pos = strlen(res->txtbuf.data);
		res->pos_begin = start-2;
		res->pos_end = start+2;
	}
}

static void run_folders(struct tokens *tokens)
{
  size_t i;

  for(i = 0; i < tokens->cnt; i++) {
	  const char *cstring = TOKEN_GET(&tokens->data[i], cstring);
	  if(i+2 < tokens->cnt && tokens->data[i].type == TOK_IDENTIFIER_NAME &&
		    cstring &&
		    !strcmp("unescape", cstring) && tokens->data[i+1].type == TOK_PAR_OPEN) {

		  handle_unescape(tokens, i+2);
	  }
  }
}

static inline int state_update_scope(struct parser_state *state, const yystype *token)
{
	if(token->type == TOK_FUNCTION) {
		struct scope *scope = TOKEN_GET(token, scope);
		if(scope) {
			state->current = scope;
		}
		else {
			/* dummy token marking function end */
			if(state->current->parent)
				state->current = state->current->parent;
			/* don't output this token, it is just a dummy marker */
			return 0;
		}
	}
	return 1;
}

static void run_decoders(struct parser_state *state)
{
  size_t i;
  const char* name;
  struct tokens *tokens = &state->tokens;

  for(i = 0; i < tokens->cnt; i++) {
	  const char *cstring = TOKEN_GET(&tokens->data[i], cstring);
	  struct decode_result res;
	  res.pos_begin = res.pos_end = 0;
	  res.append = 0;
	  if(tokens->data[i].type == TOK_FUNCTION && i+13 < tokens->cnt) {
		  name = NULL;
		  ++i;
		  if(tokens->data[i].type == TOK_IDENTIFIER_NAME) {
			  cstring = TOKEN_GET(&tokens->data[i], cstring);
			  name = cstring;
			  ++i;
		  }
		  if(match_parameters(&tokens->data[i], de_packer_3, sizeof(de_packer_3)/sizeof(de_packer_3[0])) != -1
		     || match_parameters(&tokens->data[i], de_packer_2, sizeof(de_packer_2)/sizeof(de_packer_2[0])) != -1)  {
			  /* find function decl. end */
			  handle_de(tokens->data, i, tokens->cnt, name, &res);
		  }
	  } else if(i+2 < tokens->cnt && tokens->data[i].type == TOK_IDENTIFIER_NAME &&
		    cstring &&
		    !strcmp("dF", cstring) && tokens->data[i+1].type == TOK_PAR_OPEN) {
		  /* TODO: also match signature of dF function (possibly
		   * declared using unescape */

		  handle_df(tokens->data, i+2, &res);
	  } else if(i+2 < tokens->cnt && tokens->data[i].type == TOK_IDENTIFIER_NAME &&
			  cstring &&
			  !strcmp("eval", cstring) && tokens->data[i+1].type == TOK_PAR_OPEN) {
		  handle_eval(tokens, i+2, &res);
	  }
	if(res.pos_end > res.pos_begin) {
		struct tokens parent_tokens;
		if(res.pos_end < tokens->cnt && tokens->data[res.pos_end].type == TOK_SEMICOLON)
			res.pos_end++;
		parent_tokens = state->tokens;/* save current tokens */
		/* initialize embedded context */
		memset(&state->tokens, 0, sizeof(state->tokens));
		if(++state->rec > 16)
			cli_dbgmsg(MODULE "recursion limit reached\n");
		else {
			cli_js_process_buffer(state, res.txtbuf.data, res.txtbuf.pos);
			--state->rec;
		}
		free(res.txtbuf.data);
		/* state->tokens still refers to the embedded/nested context
		 * here */
		if(!res.append) {
			replace_token_range(&parent_tokens, res.pos_begin, res.pos_end, &state->tokens);
		} else {
			/* delete tokens */
			replace_token_range(&parent_tokens, res.pos_begin, res.pos_end, NULL);
			append_tokens(&parent_tokens, &state->tokens);
		}
		/* end of embedded context, restore tokens state */
		free(state->tokens.data);
		state->tokens = parent_tokens;
	}
	  state_update_scope(state, &state->tokens.data[i]);
  }
}

void cli_js_parse_done(struct parser_state* state)
{
	struct tokens * tokens = &state->tokens;
	size_t par_balance = 0, i;
	char end = '\0';
	YYSTYPE val;

	cli_dbgmsg(MODULE "in cli_js_parse_done()\n");
	/* close unfinished token */
	switch (state->scanner->state) {
		case DoubleQString:
			end = '"';
			break;
		case SingleQString:
			end = '\'';
			break;
		default: /* make gcc happy */
			break;
	}
	if (end != '\0')
		cli_js_process_buffer(state, &end, 1);
	/* close remaining parenthesis */
	for (i=0;i<tokens->cnt;i++) {
		if (tokens->data[i].type == TOK_PAR_OPEN)
			par_balance++;
		else if (tokens->data[i].type == TOK_PAR_CLOSE && par_balance > 0)
			par_balance--;
	}
	if (par_balance > 0) {
		memset(&val, 0, sizeof(val));
		val.type = TOK_PAR_CLOSE;
		TOKEN_SET(&val, cstring, ")");
		while (par_balance-- > 0) {
			add_token(state, &val);
		}
	}

	/* we had to close unfinished strings, parenthesis,
	 * so that the folders/decoders can run properly */
	run_folders(&state->tokens);
	run_decoders(state);

	yylex_destroy(state->scanner);
	state->scanner = NULL;
}


void cli_js_output(struct parser_state *state, const char *tempdir)
{
	unsigned i;
	struct buf buf;
	char lastchar = '\0';
	char filename[1024];

	snprintf(filename, 1024, "%s"PATHSEP"javascript", tempdir);

	buf.pos = 0;
	buf.outfd = open(filename, O_CREAT | O_WRONLY, 0600);
	if(buf.outfd < 0) {
		cli_errmsg(MODULE "cannot open output file for writing: %s\n", filename);
		return;
	}
	/* append to file */
	if(lseek(buf.outfd, 0, SEEK_END) != 0) {
		/* separate multiple scripts with \n */
		buf_outc('\n', &buf);
	}
	buf_outs("<script>", &buf);
	state->current = state->global;
	for(i = 0; i < state->tokens.cnt; i++) {
		if(state_update_scope(state, &state->tokens.data[i]))
			lastchar = output_token(&state->tokens.data[i], state->current, &buf, lastchar);
	}
	/* add /script if not already there */
	if(buf.pos < 9 || memcmp(buf.buf + buf.pos - 9, "</script>", 9))
		buf_outs("</script>", &buf);
	if(write(buf.outfd, buf.buf, buf.pos) < 0) {
		cli_dbgmsg(MODULE "I/O error\n");
	}
	close(buf.outfd);
	cli_dbgmsg(MODULE "dumped/appended normalized script to: %s\n",filename);
}

void cli_js_destroy(struct parser_state *state)
{
	size_t i;
	if(!state)
		return;
	scope_free_all(state->list);
	for(i=0;i<state->tokens.cnt;i++) {
		free_token(&state->tokens.data[i]);
	}
	free(state->tokens.data);
	/* detect use after free */
	if(state->scanner)
		yylex_destroy(state->scanner);
	memset(state, 0x55, sizeof(*state));
	free(state);
	cli_dbgmsg(MODULE "cli_js_destroy() done\n");
}

/* buffer is html-normlike "chunk", if original file is bigger than buffer,
 * we rewind to a space, so we'll know that tokens won't be broken in half at
 * the end of a buffer. All tokens except string-literals of course.
 * So we can assume that after the buffer there is either a space, EOF, or a
 * chunk of text not containing whitespace at all (for which we care only if its
 * a stringliteral)*/
void cli_js_process_buffer(struct parser_state *state, const char *buf, size_t n)
{
	struct scope* current = state->current;
	YYSTYPE val;
	int yv;
	YY_BUFFER_STATE yyb;

	if(!state->global) {
		/* this state has either not been initialized,
		 * or cli_js_parse_done() was already called on it */
		cli_warnmsg(MODULE "invalid state\n");
		return;
	}
	yyb = yy_scan_bytes(buf, n, state->scanner);
	memset(&val, 0, sizeof(val));
	val.vtype = vtype_undefined;
	/* on EOF yylex will return 0 */
	while( (yv=yylex(&val, state->scanner)) != 0)
	{
		const char *text;
		size_t leng;

		val.type = yv;
		switch(yv) {
			case TOK_VAR:
				current->fsm_state = InsideVar;
				break;
			case TOK_IDENTIFIER_NAME:
				text = yyget_text(state->scanner);
				leng = yyget_leng(state->scanner);
				if(current->last_token == TOK_DOT) {
					/* this is a member name, don't normalize
					*/
					TOKEN_SET(&val, string, cli_strdup(text));
					val.type = TOK_UNNORM_IDENTIFIER;
				} else {
					switch(current->fsm_state) {
						case WaitParameterList:
							state->syntax_errors++;
							/* fall through */
						case Base:
						case InsideInitializer:
							TOKEN_SET(&val, cstring, scope_use(current, text, leng));
							break;
						case InsideVar:
						case InsideFunctionDecl:
							TOKEN_SET(&val, cstring, scope_declare(current, text, leng, state));
							current->fsm_state = InsideInitializer;
							current->brackets = 0;
							break;
						case WaitFunctionName:
							TOKEN_SET(&val, cstring, scope_declare(current, text, leng, state));
							current->fsm_state = WaitParameterList;
							break;
					}
				}
				break;
			case TOK_PAR_OPEN:
				switch(current->fsm_state) {
					case WaitFunctionName:
						/* fallthrough */
					case WaitParameterList:
						current->fsm_state = InsideFunctionDecl;
						break;
					default:
						/* noop */
						break;
				}
				break;
			case TOK_PAR_CLOSE:
				switch(current->fsm_state) {
					case WaitFunctionName:
						state->syntax_errors++;
						break;
					case WaitParameterList:
						current->fsm_state = Base;
						break;
					default:
						/* noop */
						break;
				}
				break;
			case TOK_CURLY_BRACE_OPEN:
				switch(current->fsm_state) {
					case WaitFunctionName:
						/* fallthrough */
					case WaitParameterList:
					case InsideFunctionDecl:
						/* in a syntactically correct
						 * file, we would already be in
						 * the Base state when we see a {
						 */
						current->fsm_state = Base;
						/* fall-through */
					case InsideVar:
					case InsideInitializer:
						state->syntax_errors++;
						/* fall-through */
					case Base:
					default:
						current->blocks++;
						break;
				}
				break;
					case TOK_CURLY_BRACE_CLOSE:
				if(current->blocks > 0)
					current->blocks--;
				else
					state->syntax_errors++;
				if(!current->blocks) {
					if(current->parent) {
						/* add dummy FUNCTION token to
						 * mark function end */
						TOKEN_SET(&val, cstring, "}");
						add_token(state, &val);
						TOKEN_SET(&val, scope, NULL);
						val.type = TOK_FUNCTION;

						state->current = current = current->parent;
					} else{
						/* extra } */
						state->syntax_errors++;
				}
				}
				break;
			case TOK_BRACKET_OPEN:
				current->brackets++;
				break;
			case TOK_BRACKET_CLOSE:
				if(current->brackets > 0)
					current->brackets--;
				else
					state->syntax_errors++;
				break;
			case TOK_COMMA:
				if (current->fsm_state == InsideInitializer && current->brackets == 0 && current->blocks == 0) {
					/* initializer ended only if we
					 * encountered a comma, and [] are
					 * balanced.
					 * This avoids switching state on:
					 * var x = [4,y,u];*/
					current->fsm_state = InsideVar;
				}
				break;
			case TOK_SEMICOLON:
				if (current->brackets == 0 && current->blocks == 0) {
					/* avoid switching state on unbalanced []:
					 * var x = [test;testi]; */
					current->fsm_state = Base;
				}
				break;
			case TOK_FUNCTION:
				current = scope_new(state);
				current->fsm_state = WaitFunctionName;
				TOKEN_SET(&val, scope, state->current);
				break;
			case TOK_StringLiteral:
				if(state->tokens.cnt > 1 && state->tokens.data[state->tokens.cnt-1].type == TOK_PLUS) {
					/* see if can fold */
					yystype *prev_string = &state->tokens.data[state->tokens.cnt-2];
					if(prev_string->type == TOK_StringLiteral) {
						char *str = TOKEN_GET(prev_string, string);
						size_t str_len = strlen(str);

						text = yyget_text(state->scanner);
						leng = yyget_leng(state->scanner);


						/* delete TOK_PLUS */
						free_token(&state->tokens.data[--state->tokens.cnt]);

						str = cli_realloc(str, str_len + leng + 1);
						if (!str)
						    break;
						strncpy(str+str_len, text, leng);
						str[str_len + leng] = '\0';
						TOKEN_SET(prev_string, string, str);
						free(val.val.string);
						memset(&val, 0, sizeof(val));
						val.vtype = vtype_undefined;
						continue;
					}
				}
				break;
		}
		if(val.vtype == vtype_undefined) {
			text = yyget_text(state->scanner);
			TOKEN_SET(&val, string, cli_strdup(text));
			abort();
		}
		add_token(state, &val);
		current->last_token = yv;
		memset(&val, 0, sizeof(val));
		val.vtype = vtype_undefined;
	}
}

struct parser_state *cli_js_init(void)
{
	struct parser_state *state = cli_calloc(1, sizeof(*state));
	if(!state)
		return NULL;
	if(!scope_new(state)) {
		free(state);
		return NULL;
	}
	state->global = state->current;

	if(yylex_init(&state->scanner)) {
		scope_done(state->global);
		free(state);
		return NULL;
	}
	cli_dbgmsg(MODULE "cli_js_init() done\n");
	return state;
}

/*-------------- tokenizer ---------------------*/
enum char_class {
	Whitespace,
	Slash,
	Operator,
	DQuote,
	SQuote,
	Digit,
	IdStart,
	BracketOpen = TOK_BRACKET_OPEN,
	BracketClose = TOK_BRACKET_CLOSE,
	Comma = TOK_COMMA,
	CurlyOpen = TOK_CURLY_BRACE_OPEN,
	CurlyClose = TOK_CURLY_BRACE_CLOSE,
	ParOpen = TOK_PAR_OPEN,
	ParClose = TOK_PAR_CLOSE,
	Dot = TOK_DOT,
	SemiColon = TOK_SEMICOLON,
	Nop
};

#define SL Slash
#define DG Digit
#define DQ DQuote
#define SQ SQuote
#define ID IdStart
#define OP Operator
#define WS Whitespace
#define BO BracketOpen
#define BC BracketClose
#define CM Comma
#define CO CurlyOpen
#define CC CurlyClose
#define PO ParOpen
#define PC ParClose
#define DT Dot
#define SC SemiColon
#define NA Nop

static const enum char_class ctype[256] = {
	NA, NA, NA, NA, NA, NA, NA, NA, NA, WS, WS, WS, NA, WS, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
	WS, OP, DQ, NA, ID, OP, OP, SQ, PO, PC, OP, OP, CM, OP, DT, SL,
	DG, DG, DG, DG, DG, DG, DG, DG, DG, DG, OP, SC, OP, OP, OP, OP,
	NA, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID,
	ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, BO, ID, BC, OP, ID,
	NA, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID,
	ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, CO, OP, CC, OP, NA,
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA
};

static const enum char_class id_ctype[256] = {
	NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, ID, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, NA, NA, NA, NA, NA, NA,
        NA, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID,
        ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, NA, OP, NA, NA, ID,
        NA, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID,
        ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, ID, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
        NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
};

#define CASE_SPECIAL_CHAR(C, S) case C: TOKEN_SET(lvalp, cstring, (S)); return cClass;

#define BUF_KEEP_SIZE 32768

static void textbuf_clean(struct text_buffer *buf)
{
	if(buf->capacity > BUF_KEEP_SIZE) {
	        char *data= cli_realloc(buf->data, BUF_KEEP_SIZE);
		if (data)
		    buf->data = data;
		buf->capacity = BUF_KEEP_SIZE;
	}
	buf->pos = 0;
}

static inline int parseString(YYSTYPE *lvalp, yyscan_t scanner, const char q,
		enum tokenizer_state tostate)
{
	size_t len;
	/* look for " terminating the string */
	const char *start = &scanner->in[scanner->pos], *end = start;
	do {
		const size_t siz = &scanner->in[scanner->insize] - end;
		end = memchr(end, q, siz);
		if(end && end > start && end[-1] == '\\') {
			++end;
			continue;
		}
		break;
	} while (1);
	if(end && end >= start)
		len = end - start;
	else
		len = scanner->insize - scanner->pos;
	cli_textbuffer_append_normalize(&scanner->buf, start, len);
	if(end) {
	        char *str;
		/* skip over end quote */
		scanner->pos += len + 1;
		textbuffer_putc(&scanner->buf, '\0');
		str = textbuffer_done(scanner);
		if (str) {
		    TOKEN_SET(lvalp, string, str);
		} else {
		    TOKEN_SET(lvalp, cstring, "");
		}
		scanner->state = Initial;
		assert(lvalp->val.string);
		return TOK_StringLiteral;
	} else {
		scanner->pos += len;
		/* unfinished string */
		scanner->state = tostate;
		return 0;
	}
}

static inline int parseDQString(YYSTYPE *lvalp, yyscan_t scanner)
{
	return parseString(lvalp, scanner, '"', DoubleQString);
}

static inline int parseSQString(YYSTYPE *lvalp, yyscan_t scanner)
{
	return parseString(lvalp, scanner, '\'', SingleQString);
}

static inline int parseNumber(YYSTYPE *lvalp, yyscan_t scanner)
{
	const unsigned char *in = (const unsigned char*)scanner->in;
	int is_float = 0;
	while(scanner->pos < scanner->insize) {
		unsigned char c = in[scanner->pos++];
		if(isdigit(c)) {
			textbuffer_putc(&scanner->buf, c);
			continue;
		}
		if(c =='.' && !is_float) {
			is_float = 1;
			textbuffer_putc(&scanner->buf, '.');
			continue;
		}
		if((c=='e' || c=='E') && is_float) {
			textbuffer_putc(&scanner->buf, c);
			if(scanner->pos < scanner->insize) {
				c = in[scanner->pos++];
				if(c == '+' || c == '-' || isdigit(c)) {
					textbuffer_putc(&scanner->buf, c);
					continue;
				}
			}
		}
		scanner->pos--;
		textbuffer_putc(&scanner->buf, '\0');
		scanner->state = Initial;
		if (!scanner->buf.data)
			return 0;
		if(is_float) {
			TOKEN_SET(lvalp, dval, atof(scanner->buf.data));
			return TOK_NumericFloat;
		} else {
			TOKEN_SET(lvalp, ival, atoi(scanner->buf.data));
			return TOK_NumericInt;
		}
	}
	scanner->state = Number;
	return 0;
}

static inline int parseId(YYSTYPE *lvalp, yyscan_t scanner)
{
	const struct keyword *kw;
	const unsigned char *in = (const unsigned char*)scanner->in;
	scanner->state = Initial;
	while(scanner->pos < scanner->insize) {
		unsigned char c = in[scanner->pos++];
		enum char_class cClass = id_ctype[c];
		switch(cClass) {
			case IdStart:
				textbuffer_putc(&scanner->buf, c);
				break;
			case Operator:
				/* the table contains OP only for \ */
				assert(c == '\\');
				if(scanner->pos < scanner->insize &&
						in[scanner->pos++] == 'u') {
					textbuffer_putc(&scanner->buf, c);
					break;
				}
				if(scanner->pos == scanner->insize) {
					scanner->pos++;
				}
				/* else fallthrough */
			default:
				/* character is no longer part of identifier */
				scanner->state = Initial;
				textbuffer_putc(&scanner->buf, '\0');
				scanner->pos--;
				kw = in_word_set(scanner->buf.data, scanner->buf.pos-1);
				if(kw) {
					/* we got a keyword */
					TOKEN_SET(lvalp, cstring, kw->name);
					return kw->val;
				}
				/* it is not a keyword, just an identifier */
				TOKEN_SET(lvalp, cstring, NULL);
				return TOK_IDENTIFIER_NAME;
		}
	}
	scanner->state = Identifier;
	return 0;
}

static int parseOperator(YYSTYPE *lvalp, yyscan_t scanner)
{
	size_t len = MIN(5, scanner->insize - scanner->pos);
	while(len) {
		const struct operator *kw = in_op_set(&scanner->in[scanner->pos], len);
		if(kw) {
			TOKEN_SET(lvalp, cstring, kw->name);
			scanner->pos += len;
			return kw->val;
		}
		len--;
	}
	/* never reached */
	assert(0);
	scanner->pos++;
	TOKEN_SET(lvalp, cstring, NULL);
	return TOK_ERROR;
}

static int yylex_init(yyscan_t *scanner)
{
	*scanner = cli_calloc(1, sizeof(**scanner));
	return *scanner ? 0 : -1;
}

static int yylex_destroy(yyscan_t scanner)
{
	free(scanner->buf.data);
	free(scanner);
	return 0;
}

static int yy_scan_bytes(const char *p, size_t len, yyscan_t scanner)
{
	scanner->in = p;
	scanner->insize = len;
	scanner->pos = 0;
	scanner->lastpos = -1;
	scanner->last_state = Dummy;
	return 0;
}

static const char *yyget_text(yyscan_t scanner)
{
    return scanner->yytext ? scanner->yytext :  scanner->buf.data;
}

static int yyget_leng(yyscan_t scanner)
{
	/* we have a \0 too */
	return scanner->yylen ? scanner->yylen: (scanner->buf.pos > 0 ? scanner->buf.pos - 1 : 0);
}

static int yylex(YYSTYPE *lvalp, yyscan_t  scanner)
{
	const size_t len = scanner->insize;
	const unsigned char *in = (const unsigned char*)scanner->in;
	unsigned char lookahead;
	enum char_class cClass;

	scanner->yytext = NULL;
	scanner->yylen = 0;
	if(scanner->pos == scanner->lastpos) {
		if(scanner->last_state == scanner->state) {
			cli_dbgmsg(MODULE "infloop detected, skipping character\n");
			scanner->pos++;
		}
		/* its not necesarely an infloop if it changed
		 * state, and it shouldn't infloop between states */
	}
	scanner->lastpos = scanner->pos;
	scanner->last_state = scanner->state;
	while(scanner->pos < scanner->insize) {
		switch(scanner->state) {
			case Initial:
				textbuf_clean(&scanner->buf);
				cClass = ctype[in[scanner->pos++]];
				switch(cClass) {
					case Whitespace:
						/* eat whitespace */
						continue;
					case Slash:
						if(scanner->pos < len) {
							lookahead = in[scanner->pos];
							switch(lookahead) {
								case '*':
									scanner->state = MultilineComment;
									scanner->pos++;
									continue;
								case '/':
									scanner->state = SinglelineComment;
									scanner->pos++;
									continue;
							}
						}
						--scanner->pos;
						return parseOperator(lvalp, scanner);
					case Operator:
						--scanner->pos;
						return parseOperator(lvalp, scanner);
					case DQuote:
						return parseDQString(lvalp, scanner);
					case SQuote:
						return parseSQString(lvalp, scanner);
					case Digit:
						--scanner->pos;
						return parseNumber(lvalp, scanner);
					case IdStart:
						--scanner->pos;
						return parseId(lvalp,scanner);
					CASE_SPECIAL_CHAR(BracketOpen, "[");
					CASE_SPECIAL_CHAR(BracketClose, "]");
					CASE_SPECIAL_CHAR(Comma, ",");
					CASE_SPECIAL_CHAR(CurlyOpen, "{");
					CASE_SPECIAL_CHAR(CurlyClose, "}");
					CASE_SPECIAL_CHAR(ParOpen, "(");
					CASE_SPECIAL_CHAR(ParClose, ")");
					CASE_SPECIAL_CHAR(Dot, ".");
					CASE_SPECIAL_CHAR(SemiColon, ";");
					case Nop:
					       continue;
				}
				break;
			case DoubleQString:
				return parseString(lvalp, scanner, '"', DoubleQString);
			case SingleQString:
				return parseString(lvalp, scanner, '\'', SingleQString);
			case Identifier:
				return parseId(lvalp, scanner);
			case MultilineComment:
				while(scanner->pos+1 < scanner->insize) {
					if(in[scanner->pos] == '*' && in[scanner->pos+1] == '/') {
						scanner->state = Initial;
						scanner->pos++;
						break;
					}
					scanner->pos++;
				}
				scanner->pos++;
				break;
			case Number:
				return parseNumber(lvalp, scanner);
			case SinglelineComment:
				while(scanner->pos < scanner->insize) {
					/* htmlnorm converts \n to space, so
					 * stop on space too */
					if(in[scanner->pos] == '\n' || in[scanner->pos] == ' ')
						break;
					scanner->pos++;
				}
				scanner->state = Initial;
				break;
			default:
				assert(0 && "Not reached");
		}
	}
	return 0;
}
