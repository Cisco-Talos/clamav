/*
 *  A fast filter for static patterns.
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
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "filtering.h"
#include "matcher-ac.h"
#include <string.h>
#include <assert.h>
#include "perflogging.h"
/* ----- shift-or filtering -------------- */

/*
 * Description of algorithm:
 *
 * Multiple patterns are added to the filter.
 * The filter retains an approximation of these patterns, which can lead to
 * false positive matches, but not false negative matches.
 *
 * For each position in the filter we retain what qgrams can match at that
 * position, for example (if we'd use characters as qgrams):
 * pattern1: atu
 * pattern2: bzf
 * pattern3: xat
 * 
 * filter accepts:
 * [abx][tza][uft]
 *
 * But it also accepts (false positives):
 * azu, azf, azt, ...
 *
 * It doesn't however accept:
 * aaa, atz, ...
 *
 * This is implemented by having a bit-level state-machine with MAXSOPATLEN (=32) states, 
 * each active bit meaning that a state is active.
 * 
 * The states are activated sequentially, eachtransition decision is made 
 * considering if we can accept the character at position X. 
 * Since we can start a match at any position, position 0 is
 * reactivated each time.
 * When the last position is activated, the filter reports a match.
 * If we can't accept the character at position X, the state remains inactive,
 * and further states aren't activated (unless we activate this state in the
 * future).
 *
 * Essentially this is an automaton like this:
 *
 *  /\    (a|b|x)        (t|z|a)        (u|f|t)
 * [S1] ---------> [S2] -------> [S3] ---------> [S4] -> match
 *  \_______________/             |               
 *  \_____________________________/               
 *
 *
 * But we are tracking multiple active states at each time (or run N automatons
 * in parallel if you like, N = number of states).
 *
 * We can have S3 and S2 active, meaning that if the next character is
 * acceptable, it transitions to S1,S3 and S4 being active, otherwise it
 * transitions to S1 being active.
 *
 * Active states can either be represented as a binary 1 or 0, and using
 * bit-shifting and masking.
 * If we choose 1, we must use &, and after shifting always reactivate bit 0.
 * If we choose 0, we must use |, and after shifting we don't need to do
 * anything (since by shifting a 0 is implicitly introduced).
 *
 * This file implements the latter (shift-or) method.
 *
 * The discussion above considered pattern to be of same length (or truncated to
 * be so). In reality patterns are of variable length, and we often have short
 * pattern.
 *
 * Thus another bitmap was introduced, meaning that if (end[Q] == set), then
 * a pattern can end at this position.
 * Also we would fill the pattern's position filters quite quickly with only 256
 * choices for a position, so the algorithm uses overlapping qgrams of length 2:
 * 'abcd' is 3 qgrams: 'ab','bc','cd'
 *
 * The algorithm is very sensitive to the end[Q] filter, since it can have false
 * positives due to short patterns!
 * For optimal performance we need:
 *   - patterns as long as possible
 *   - probability for end[Q] to match low (avoid 0000, and other common case
 *   - choose the most "diverse" subset from a long pattern
 *
 * diverse = referring to what we are scanning, so that the filter rarely
 * matches, so this actually means that we *want* to avoid adding more
 * characters to the filter, if we have 2 patterns:
 * abxfg, and dalabxpo, it may be preferable to shift the 2nd one so that we
 * don't add new character at the beginning.
 *
 * With NDB signatures there are more challenges to overcome:
 *    e8??0000000aa
 *
 *    will make the filter accept:
 *    e8<all-256-values-here>, <all-256-values>00, ... 000000aa
 *
 *    We should delay the pattern end as long as possible, especially if it is  0000
 *    The problem is that now the filter accepts 0000 on position 3, regardless
 *    of what we have on position 1 (even if we have something else than e8), so
 *    we have to be very careful not to allow 0000 on first position too,
 *    otherwise the filter will happily accept 000000000000.
 *
 * To optimize cache usage there are 2 end filters, one character (fits L1), and one qgram
 * based (fits L2), both must match for the filter to consider it a match.   
 *
 *
 */

/*#define DETAILED_DEBUG*/
#ifdef DETAILED_DEBUG
#define detailed_dbg cli_dbgmsg
#else
#define detailed_dbg(...)
#endif

#define BITMAP_CONTAINS(bmap, val) ((bmap)[(val) >> 5] & (1 << ((val) & 0x1f)))
#define BITMAP_INSERT(bmap, val) ((bmap)[(val) >> 5] |= (1 << ((val) & 0x1f)))

void filter_init(struct filter *m)
{
	memset(m->B, ~0, sizeof(m->B));
	memset(m->end, ~0, sizeof(m->end));
}

/* because we use uint32_t */
#define MAXSOPATLEN 8

static inline int filter_isset(const struct filter *m, unsigned pos, uint16_t val)
{
	return !(m->B[val] & (1<<pos));
}

static inline void filter_set_atpos(struct filter *m, unsigned pos, uint16_t val)
{
	if (!filter_isset(m, pos, val)) {
		cli_perf_log_count(FILTER_LOAD, pos);
		m->B[val] &= ~(1<<pos);
	}
}


static inline int filter_end_isset(const struct filter *m, unsigned pos, uint16_t a)
{
	return !(m->end[a] & (1<<pos));
}

static inline void filter_set_end(struct filter *m, unsigned pos, uint16_t a)
{
	if (!filter_end_isset(m, pos, a)) {
		cli_perf_log_count(FILTER_END_LOAD, pos);
		m->end[a] &= ~(1 << pos);
	}
}
#define MAX_CHOICES 8
/* just an arbitrary limit, if patterns are longer, we cut
 * the filter can only use MAXSOPATLEN (32) characters,
 * this longer buffer is needed so that we can choose the "best" subpattern from
 * it */
#define MAXPATLEN 255

/* merge another pattern into the filter
 * add('abc'); add('bcd'); will match [ab][bc][cd] */
int filter_add_static(struct filter *m, const unsigned char *pattern, unsigned long len, const char *name)
{
	uint16_t q = 0;
	uint8_t j, maxlen;
	uint32_t best = 0xffffffff;
	uint8_t best_pos = 0;

    UNUSEDPARAM(name);

	cli_perf_log_count(TRIE_ORIG_LEN, len > 8 ? 8 : len);
	/* TODO: choose best among MAXCHOICES */
	/* cut length */
	if(len > MAXPATLEN) {
		len = MAXPATLEN;
	}
	if(len < 2)
		return -1;

	/* we want subsigs to be as long as possible */
	if (len > 4) {
		maxlen = len - 4;
		if (maxlen == 1) maxlen = 2;
	} else
		maxlen = 2;
	for(j=0;(best < 100 && j<MAX_CHOICES) || (j < maxlen) ;j++) {
		uint32_t num = MAXSOPATLEN;
		uint8_t k;
		if (j+2 > len)
			break;
		for(k=j;k<len-1 && (k-j < MAXSOPATLEN);k++) {
			q = cli_readint16( &pattern[k] );
			/* we want to favor subsigs that add as little as
			 * possible to the filter */
			num += filter_isset(m, k-j, q) ? 0 : MAXSOPATLEN - (k-j);
			if ((k == j || k == j+1) && (q == 0x0000 || q == 0xffff))
				num += k==j ?  10000 : 1000;/* bad */
		}
		/* it is very important to keep the end set small */
		num += 10*(filter_end_isset(m, k-j-1, q) ? 0 : 1);
		/* it is very important to have signatures as long as possible
		 * */
		num += 5*(MAXSOPATLEN - (k-j));
		/* if we are lower length than threshold penalize */
		if (k-j+1 < 4)
			num += 200;
		/* favour longer patterns */
		num -= (2*MAXSOPATLEN - (k + 1+j))*(k-j)/2;

		if (num < best) {
			best = num;
			best_pos = j;
		}
	}

	assert(best_pos < len-1);
	if (pattern[best_pos] == 0 && pattern[best_pos+1] == 0) {
		detailed_dbg("filter (warning): subsignature begins with zero (static): %s\n", name);
	}
	pattern += best_pos;
	len -= best_pos;
	/* cut length */
	if(len > MAXSOPATLEN) {
		len = MAXSOPATLEN;
	}
	/* Shift-Or like preprocessing */
	for(j=0;j < len-1;j++) {
		/* use overlapping little-endian 2-grams. We need them overlapping because matching can start at any position */
		q = cli_readint16( &pattern[j] );
		filter_set_atpos(m, j, q);
	}
	/* we use variable length patterns, use last character to mark pattern end,
	 * can lead to false positives.*/
	/* mark that at state j, the q-gram q can end the pattern */
	if(j) {
		j--;
		filter_set_end(m, j, q);
	}
	return j+2;
}

struct char_spec {
	/* if non-null i-th character = alt[start + step*i]; start+step*i < end;
	 */
	struct cli_ac_special *alt;
	uint8_t start;
	uint8_t end;
	uint8_t step;
	uint8_t negative;
};

static inline unsigned char spec_ith_char(const struct char_spec *spec, unsigned i)
{
	const struct cli_ac_special *alt = spec->alt;
	if (alt) {
		assert (alt->type == 1);
		assert (i < alt->num);
		return (alt->alt).byte[i];
	}
	return i;
}

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#define SPEC_FOREACH(spec0, k0, spec1, k1) do {\
    unsigned char c0 = spec_ith_char(spec0, k0);\
    unsigned char c1 = spec_ith_char(spec1, k1);\
    unsigned c0end, c1end, cc0,cc1;\
    c0end = spec0->negative ? 255 : c0;\
    c1end = spec1->negative ? 255 : c1;\
    cc0 = spec0->negative ? 0 : c0;\
    cc1 = spec1->negative ? 0 : c1;\
    for (;cc0 <= c0end;cc0++) {\
	for (;cc1 <= c1end; cc1++) {\
	    uint16_t a = cc0 | (cc1<<8);\
	    if (spec0->negative && cc0 == c0)\
	    continue;\
	    if (spec1->negative && cc1 == c1)\
	    continue;

#define SPEC_END_FOR }}} while(0)

enum badness {
	reject,
	/* try to avoid if possible */
	avoid_first,
	avoid_anywhere, /* includes avoid_first! */
	/* not that bad, but still not best */
	dontlike,
	acceptable,
	like
};
static inline void get_score(enum badness badness, unsigned i, const struct filter *m, const struct char_spec *spec0, const struct char_spec *spec1, int32_t *score, int32_t *score_end)
{
	int32_t base;
	unsigned k0, k1, num_introduced = 0, num_end_introduced = 0;
	switch (badness) {
		case reject:
			/* not reached */
			assert(0);
			base = -0x7fffff;
			break;
		case avoid_first:
			if (!i)
				base = -0x700000;
			else
				base = 0;
			break;
		case avoid_anywhere:
			if (!i)
				base = -0x720000;
			else
				base = -0x1000;
			break;
		case dontlike:
			base = 0;
			break;
		case acceptable:
			base = 0x200;
			break;
		case like:
			/* a bit better only */
			base = 0x201;
			break;
	}
	if (base < 0) {
		*score = base;
		*score_end = base;
		return;
	}
	/* at most 256 iterations here, otherwise base would be negative */
	for(k0=spec0->start;k0 <= spec0->end;k0 += spec0->step) {
		for(k1=spec1->start;k1 <= spec1->end;k1 += spec1->step) {
		    SPEC_FOREACH(spec0, k0, spec1, k1) {
			num_introduced += filter_isset(m, i, a);
			num_end_introduced += filter_end_isset(m, i, a);
		    } SPEC_END_FOR;
		}
	}
	*score = base - num_introduced;
	*score_end = base - num_end_introduced;
	if (badness == avoid_first && i) {
		/* what is bad to begin with, is bad at end too */
		*score_end -= 0x1000;
	}
}

struct choice {
	enum badness base;
	unsigned begin;
	unsigned len;
};

static inline void add_choice(struct choice *choices, unsigned *cnt, unsigned i, unsigned ie, enum badness badness)
{
	struct choice *choice;
	int i_neg = -1;
	assert(ie < MAXPATLEN);
	if (ie < i+1)
		return;
	if (*cnt >= MAX_CHOICES)
		return;
	if (badness > avoid_first && *cnt >= (MAX_CHOICES >> 1)) {
		unsigned j;
		/* replace very bad picks if we're full */
		for (j=0;j<*cnt;j++) {
			if (choices[j].base < badness) {
				if (i_neg == -1 || choices[j].base < choices[i_neg].base) {
					i_neg = j;
				}
			}
		}
	}
	if (i_neg != -1) {
		choice = &choices[i_neg];
	} else {
		choice = &choices[(*cnt)++];
	}
	choice->begin = i;
	choice->len = ie - i + 1;
	choice->base = badness;
}

static inline int32_t spec_iter(const struct char_spec *spec)
{
    unsigned count;
    assert(spec->step);
    count = (spec->step + spec->end - spec->start)/spec->step;
    if (spec->negative) /* all chars except itself are added */
	count *= 254;
    return count;
}

int  filter_add_acpatt(struct filter *m, const struct cli_ac_patt *pat)
{
	unsigned i, j = 0, stop = 0, l=0;
	uint16_t k0, k1;

	struct char_spec chars[MAXPATLEN];
	enum badness char_badness[MAXPATLEN];
	unsigned char patc[MAXPATLEN];
	unsigned altcnt = 0;
	int32_t best_score = -0x7fffffff;
	unsigned best_score_i = 0;
	unsigned best_score_len = 0;
	struct char_spec *spec0 = NULL, *spec1 = NULL;

	struct choice choices[MAX_CHOICES];
	unsigned choices_cnt = 0;
	unsigned prefix_len = pat->prefix_length[0];
	unsigned speci;

	j = MIN(prefix_len + pat->length[0], MAXPATLEN);
	for(i=0;i<j;i++) {
		const uint16_t p = i < prefix_len ? pat->prefix[i] : pat->pattern[i - prefix_len];
		if ((p&CLI_MATCH_METADATA) != CLI_MATCH_CHAR)
			break;
		patc[i] = (uint8_t)p;
	}
	if (i == j) {
		/* all static, use add_static it has better heuristics for this
		 * case */
		return filter_add_static(m, patc, j, pat->virname);
	}
	cli_perf_log_count(TRIE_ORIG_LEN, j > 8 ? 8 : j);
	i = 0;
	if (!prefix_len) {
	    while ((pat->pattern[i] & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL) {
		/* we support only ALT_CHAR, skip the rest */
		if (pat->special_table[altcnt]->type == 1)
		    break;
		altcnt++;
		i++;
	    }
	}
	/* transform AC characters into our representation */
	for (speci=0;i<j && !stop; speci++,i++) {
		struct char_spec *spec = &chars[speci];
		const uint16_t p = i < prefix_len ? pat->prefix[i] : pat->pattern[i - prefix_len];
		spec->alt = NULL;
		spec->negative = 0;
		switch (p & CLI_MATCH_METADATA) {
			case CLI_MATCH_CHAR:
				spec->start = spec->end = (uint8_t)p;
				spec->step  = 1;
				break;
			case CLI_MATCH_NOCASE:
				if ((uint8_t)p >= 'a' && (uint8_t)p <= 'z') {
					spec->start = (uint8_t)p - ('a' - 'A');
					spec->end   = (uint8_t)p;
					spec->step  = ('a' - 'A');
				}
				else if ((uint8_t)p >= 'A' && (uint8_t)p <= 'Z') {
					spec->start = (uint8_t)p;
					spec->end   = (uint8_t)p + ('a' - 'A');
					spec->step  = ('a' - 'A');
				}
				else {
					spec->start = spec->end = (uint8_t)p;
					spec->step  = 1;
				}
				break;
			case CLI_MATCH_IGNORE:
				spec->start = 0x00;
				spec->end   = 0xff;
				spec->step  = 1;
				break;
			case CLI_MATCH_SPECIAL:
				assert(pat->special_table);
				/* assert(altcnt < pat->alt); */
				assert(pat->special_table[altcnt]);
				spec->negative = pat->special_table[altcnt]->negative;
				switch (pat->special_table[altcnt++]->type) {
				    case 1: /* ALT_CHAR */
					spec->start = 0;
					spec->end = pat->special_table[altcnt-1]->num - 1;
					spec->step = 1;
					spec->alt = pat->special_table[altcnt-1];
					break;
				    default:
					stop = 1;
					break;	/* TODO: should something be done here?
					 * */
				}
				break;
			case CLI_MATCH_NIBBLE_HIGH:
				spec->start = (p & 0xf0);
				spec->end   = spec->start | 0x0f;
				spec->step  = 1;
				break;
			case CLI_MATCH_NIBBLE_LOW:
				spec->start = (p & 0xf);
				spec->end   = 0xf0 | spec->start;
				spec->step  = 0x10;
				break;
			default:
				cli_errmsg("filtering: unknown wildcard character: %d\n", p);
				return -1;
		}
	}
	if (stop) --speci;
	j = speci;
	if (j < 2) {
		if (stop)
			cli_warnmsg("Don't know how to create filter for: %s\n",pat->virname);
		else
			cli_warnmsg("Subpattern too short: %s\n", pat->virname);
		return -1;
	}

	for(i=0;i<j-1;i++) {
		int32_t num_iter;
		/* new qgrams added to the filter */
		spec0 = &chars[i];
		spec1 = &chars[i+1];
		num_iter = spec_iter(spec0) * spec_iter(spec1);

		if (num_iter >= 0x100) {
			if (num_iter == 0x10000)
				char_badness[i] = reject;
			else
				char_badness[i] = avoid_anywhere;
		} else {
			int8_t binary = 0;
			enum badness scor = acceptable;
			for(k0=spec0->start;k0 <= spec0->end;k0 += spec0->step) {
				for(k1=spec1->start;k1 <= spec1->end;k1 += spec1->step) {
					unsigned char c0 = spec_ith_char(spec0, k0);
					unsigned char c1 = spec_ith_char(spec1, k1);
					if (spec0->negative || spec1->negative) {
					    scor = avoid_anywhere;
					    break;
					}
					if ((!c0 && !c1) || (c0 == 0xff && c1 == 0xff)) {
						scor = avoid_first;
						break;
					}
					if (c0 == c1) {
						scor = dontlike;
						break;
					}
					if ((c0 < 32 || c0 > 127) && (c1 < 32 || c1 >127))
						binary = 1;
				}
			}
			if (scor == acceptable && binary) {
				/* slightly favor binary */
				scor = like;
			}
			char_badness[i] = scor;
		}
	}

	/* try to choose best subpattern */

	/* calculating the score for all possible i start pos
	 * and all possible length is too slow, so choose best among N choices
	 * only */
	for (i=0;i<j-1 && choices_cnt < MAX_CHOICES;i++) {
		enum badness base0 = like, base1 = like;
		unsigned kend = MIN(j-1, (i + MAXSOPATLEN)&~1), k;
		int ki = -0xff;
		/* add 2 scores: pattern with max length, one where we stop at
		 * first negative, and one we stop at last positive, but never
		 * include reject */
		assert(kend-1 < j-1);
		if (char_badness[i]  == reject)
			continue;
		if ((char_badness[i] == avoid_anywhere || char_badness[i] == avoid_first)
				&& choices_cnt > 0)
			/* if we have another choice don't choose this */
			continue;
		while ((kend > i+3) && char_badness[kend-1] == reject) kend--;
		for (k=i;k<kend;k++) {
			enum badness badness = char_badness[k];
			if (badness < acceptable) {
				if (badness == reject) {
					/* this is a never pick */
					kend = k;
					break;
				}
				if (badness == avoid_first && k != i)
					badness = dontlike;
				if (k == i && badness == avoid_anywhere)
					badness = avoid_first;
				if (ki == -0xff)
					ki = k;
			}
			base0 = MIN(base0, badness);
			if (ki == -0xff)
				base1 = MIN(base1, badness);
		}
		add_choice(choices, &choices_cnt, i, kend, base0);
		if (ki > (int)i) {
			/* ki|ki+1|??| */
			/* try subpattern from after the wildcard */
			i = ki;
		}
		/* if score is positive, it replaces a negative choice */
	}
	for(l=0;l<choices_cnt;l++) {
		int32_t score;
		unsigned kend;
		unsigned k;

		i = choices[l].begin;
		kend = i + choices[l].len;
		score = 0;

		for(k = i; k < kend-1; k++) {
			unsigned p = k - i;
			int32_t iscore, score_end;
			assert(k < j);
			get_score(char_badness[k], p, m, &chars[k], &chars[k+1],
				  &iscore, &score_end);
			/* give more importance to the score of the characters
			 * at the beginning */
			/* TODO: tune magic number here */
			if (p < 6) {
				iscore *= (6-p);
				score_end *= (6-p);
			}
			score += iscore;
			if (score + score_end > best_score) {
				/* we may have negative scores, so truncating
				 * the pattern could actually get us a higher
				 * score */
				best_score = score + score_end;
				best_score_len = p + 2;
				best_score_i = i;
				assert(i + best_score_len <= j);
			}
		}
	}

	if (best_score <= -0x7fffffff) {
		cli_warnmsg("filter rejecting %s due to very bad score: %ld\n", pat->virname, (long)best_score);
		return -1;
	}
	if (choices_cnt == 0) {
		cli_warnmsg("filter rejecting %s because there are no viable choices", pat->virname);
		return -1;
	}
	assert(best_score_len >= 2);
	detailed_dbg("filter %s score: %ld, %u (+ %u)\n", pat->virname, (long)best_score, best_score_i, best_score_len);
	/* Shift-Or like preprocessing */
	assert(1 < best_score_len);
	for (i=0;i < best_score_len-1;i++) {
		spec0 = &chars[best_score_i + i];
		spec1 = &chars[best_score_i + i + 1];
		/* use overlapping little-endian 2-grams, overlapping because match can start
		 * at any position (including odd) */

		for(k0=spec0->start;k0 <= spec0->end;k0 += spec0->step) {
			for(k1=spec1->start;k1 <= spec1->end;k1 += spec1->step) {
			    SPEC_FOREACH(spec0, k0, spec1, k1) {
				if (!cc0 && !cc1 && !i) {
					detailed_dbg("filter (warning): subsignature begins with zero: %s\n",pat->virname);
				}
				filter_set_atpos(m, i, a);
			    } SPEC_END_FOR;
			}
		}
	}

	j  = best_score_len - 2;
	if (spec0 && spec1) {
	    for (k0=spec0->start;k0 <= spec0->end;k0 += spec0->step) {
		for (k1=spec1->start;k1 <= spec1->end;k1 += spec1->step) {
		    SPEC_FOREACH(spec0, k0, spec1, k1) {
			if (!cc0 && !cc1) {
			    detailed_dbg("filter (warning): subsignature ends with zero: %s\n",pat->virname);
			}
			filter_set_end(m, j, a);
		    } SPEC_END_FOR;
		}
	    }
	}
	return j+2;
}

/* state 11110011 means that we may have a match of length min 4, max 5 */

__hot__ int filter_search_ext(const struct filter *m, const unsigned char *data, unsigned long len, struct filter_match_info *inf)
{
	size_t j;
	uint8_t state = ~0;
	const uint8_t *B = m->B;
	const uint8_t *End = m->end;

	if (len < 2) return -1;
	/* look for first match */
	for (j=0; j < len-1;j++) {
		uint8_t match_state_end;
		const uint16_t q0 = cli_readint16( &data[j] );

		state = (state << 1) | B[q0];
		match_state_end = state | End[q0];
		if (match_state_end != 0xff) {
			inf->first_match = j;
      return 0;
		}
	}
  /* no match, inf is invalid */
  return -1;
}

/* this is like a FSM, with multiple active states at the same time.
 * each bit in "state" means an active state, when a char is encountered
 * we determine what states can remain active.
 * The FSM transition rules are expressed as bit-masks */
long filter_search(const struct filter *m, const unsigned char *data, unsigned long len)
{
	size_t j;
	uint8_t state = ~0;
	const uint8_t *B = m->B;
	const uint8_t *End = m->end;

	/* we use 2-grams, must be higher than 1 */
	if(len < 2) return -1;
	/* Shift-Or like search algorithm */
	for(j=0;j < len-1; j++) {
		const uint16_t q0 = cli_readint16( &data[j] );
		uint8_t match_end;
		state = (state << 1) | B[q0];
		/* state marks with a 0 bit all active states
		 * End[q0] marks with a 0 bit all states where the q-gram 'q' can end a pattern
		 * if we got two 0's at matching positions, it means we encountered a pattern's end */
		match_end = state | End[q0];
		if(match_end != 0xff) {

			/* if state is reachable, and this character can finish a pattern, assume match */
			/* to reduce false positives check if qgram can finish the pattern */
			/* return position of probable match */
			/* find first 0 starting from MSB, the position of that bit as counted from LSB, is the length of the
			 * longest pattern that could match */
			return j >= MAXSOPATLEN  ? j - MAXSOPATLEN : 0;
		}
	}
	/* no match */
	return -1;
}
