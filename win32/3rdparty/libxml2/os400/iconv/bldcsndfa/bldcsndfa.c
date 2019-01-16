/**
***     Build a deterministic finite automaton to associate CCSIDs with
***             character set names.
***
***     Compile on OS/400 with options SYSIFCOPT(*IFSIO).
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#include <iconv.h>


#ifdef OLDXML
#include "xml.h"
#else
#include <libxml/hash.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#endif


#ifdef __OS400__
#define iconv_open_error(cd)            ((cd).return_value == -1)
#define set_iconv_open_error(cd)        ((cd).return_value = -1)
#else
#define iconv_open_error(cd)            ((cd) == (iconv_t) -1)
#define set_iconv_open_error(cd)        ((cd) = (iconv_t) -1)
#endif


#define C_SOURCE_CCSID          500
#define C_UTF8_CCSID            1208


#define UTF8_SPACE      0x20
#define UTF8_HT         0x09
#define UTF8_0          0x30
#define UTF8_9          0x39
#define UTF8_A          0x41
#define UTF8_Z          0x5A
#define UTF8_a          0x61
#define UTF8_z          0x7A


#define GRANULE         128             /* Memory allocation granule. */

#define EPSILON         0x100           /* Token for empty transition. */


#ifndef OFFSETOF
#define OFFSETOF(t, f)  ((unsigned int) ((char *) &((t *) 0)->f - (char *) 0))
#endif

#ifndef OFFSETBY
#define OFFSETBY(t, p, o)       ((t *) ((char *) (p) + (unsigned int) (o)))
#endif


typedef struct t_transition     t_transition;   /* NFA/DFA transition. */
typedef struct t_state          t_state;        /* NFA/DFA state node. */
typedef struct t_symlist        t_symlist;      /* Symbol (i.e.: name) list. */
typedef struct t_chset          t_chset;        /* Character set. */
typedef struct t_stategroup     t_stategroup;   /* Optimization group. */
typedef unsigned char           utf8char;       /* UTF-8 character byte. */
typedef unsigned char           byte;           /* Untyped data byte. */


typedef struct {                        /* Set of pointers. */
        unsigned int    p_size;         /* Current allocated size. */
        unsigned int    p_card;         /* Current element count. */
        void *          p_set[1];       /* Element array. */
}               t_powerset;


struct t_transition {
        t_transition *  t_forwprev;     /* Head of forward transition list. */
        t_transition *  t_forwnext;     /* Tail of forward transition list. */
        t_transition *  t_backprev;     /* Head of backward transition list. */
        t_transition *  t_backnext;     /* Tail of backward transition list. */
        t_state *       t_from;         /* Incoming state. */
        t_state *       t_to;           /* Destination state. */
        unsigned short  t_token;        /* Transition token. */
        unsigned int    t_index;        /* Transition array index. */
};


struct t_state {
        t_state *       s_next;         /* Next state (for DFA construction). */
        t_state *       s_stack;        /* Unprocessed DFA states stack. */
        t_transition *  s_forward;      /* Forward transitions. */
        t_transition *  s_backward;     /* Backward transitions. */
        t_chset *       s_final;        /* Recognized character set. */
        t_powerset *    s_nfastates;    /* Corresponding NFA states. */
        unsigned int    s_index;        /* State index. */
};


struct t_symlist {
        t_symlist *     l_next;         /* Next name in list. */
        utf8char        l_symbol[1];    /* Name bytes. */
};


struct t_chset {
        t_chset *       c_next;         /* Next character set. */
        t_symlist *     c_names;        /* Character set name list. */
        iconv_t         c_fromUTF8;     /* Conversion from UTF-8. */
        unsigned int    c_ccsid;        /* IBM character set code. */
        unsigned int    c_mibenum;      /* IANA character code. */
};


struct t_stategroup {
        t_stategroup *  g_next;         /* Next group. */
        t_state *       g_member;       /* Group member (s_stack) list. */
        unsigned int    g_id;           /* Group ident. */
};



t_chset *       chset_list;             /* Character set list. */
t_state *       initial_state;          /* Initial NFA state. */
iconv_t         job2utf8;               /* Job CCSID to UTF-8 conversion. */
iconv_t         utf82job;               /* UTF-8 to job CCSID conversion. */
t_state *       dfa_states;             /* List of DFA states. */
unsigned int    groupid;                /* Group ident counter. */


/**
***     UTF-8 strings.
**/

#pragma convert(819)

static const utf8char   utf8_MIBenum[] = "MIBenum";
static const utf8char   utf8_mibenum[] = "mibenum";
static const utf8char   utf8_ibm_[] = "ibm-";
static const utf8char   utf8_IBMCCSID[] = "IBMCCSID";
static const utf8char   utf8_iana_[] = "iana-";
static const utf8char   utf8_Name[] = "Name";
static const utf8char   utf8_Pref_MIME_Name[] = "Preferred MIME Name";
static const utf8char   utf8_Aliases[] = "Aliases";
static const utf8char   utf8_html[] = "html";
static const utf8char   utf8_htmluri[] = "http://www.w3.org/1999/xhtml";
static const utf8char   utf8_A[] = "A";
static const utf8char   utf8_C[] = "C";
static const utf8char   utf8_M[] = "M";
static const utf8char   utf8_N[] = "N";
static const utf8char   utf8_P[] = "P";
static const utf8char   utf8_T[] = "T";
static const utf8char   utf8_ccsid[] = "ccsid";
static const utf8char   utf8_EBCDIC[] = "EBCDIC";
static const utf8char   utf8_ASCII[] = "ASCII";
static const utf8char   utf8_assocnodes[] = "/ccsid_mibenum/assoc[@ccsid]";
static const utf8char   utf8_aliastext[] =
                                "/ccsid_mibenum/assoc[@ccsid=$C]/alias/text()";
#ifdef OLDXML
static const utf8char   utf8_tablerows[] =
                        "//table[@id='table-character-sets-1']/*/tr";
static const utf8char   utf8_headerpos[] =
                "count(th[text()=$T]/preceding-sibling::th)+1";
static const utf8char   utf8_getmibenum[] = "number(td[$M])";
static const utf8char   utf8_getprefname[] = "string(td[$P])";
static const utf8char   utf8_getname[] = "string(td[$N])";
static const utf8char   utf8_getaliases[] = "td[$A]/text()";
#else
static const utf8char   utf8_tablerows[] =
                        "//html:table[@id='table-character-sets-1']/*/html:tr";
static const utf8char   utf8_headerpos[] =
                "count(html:th[text()=$T]/preceding-sibling::html:th)+1";
static const utf8char   utf8_getmibenum[] = "number(html:td[$M])";
static const utf8char   utf8_getprefname[] = "string(html:td[$P])";
static const utf8char   utf8_getname[] = "string(html:td[$N])";
static const utf8char   utf8_getaliases[] = "html:td[$A]/text()";
#endif

#pragma convert(0)


/**
***     UTF-8 character length table.
***
***     Index is first character byte, value is the character byte count.
**/

static signed char      utf8_chlen[] = {
/* 00-07 */     1,      1,      1,      1,      1,      1,      1,      1,
/* 08-0F */     1,      1,      1,      1,      1,      1,      1,      1,
/* 10-17 */     1,      1,      1,      1,      1,      1,      1,      1,
/* 18-1F */     1,      1,      1,      1,      1,      1,      1,      1,
/* 20-27 */     1,      1,      1,      1,      1,      1,      1,      1,
/* 28-2F */     1,      1,      1,      1,      1,      1,      1,      1,
/* 30-37 */     1,      1,      1,      1,      1,      1,      1,      1,
/* 38-3F */     1,      1,      1,      1,      1,      1,      1,      1,
/* 40-47 */     1,      1,      1,      1,      1,      1,      1,      1,
/* 48-4F */     1,      1,      1,      1,      1,      1,      1,      1,
/* 50-57 */     1,      1,      1,      1,      1,      1,      1,      1,
/* 58-5F */     1,      1,      1,      1,      1,      1,      1,      1,
/* 60-67 */     1,      1,      1,      1,      1,      1,      1,      1,
/* 68-6F */     1,      1,      1,      1,      1,      1,      1,      1,
/* 70-77 */     1,      1,      1,      1,      1,      1,      1,      1,
/* 78-7F */     1,      1,      1,      1,      1,      1,      1,      1,
/* 80-87 */     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
/* 88-8F */     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
/* 90-97 */     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
/* 98-9F */     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
/* A0-A7 */     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
/* A8-AF */     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
/* B0-B7 */     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
/* B8-BF */     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
/* C0-C7 */     2,      2,      2,      2,      2,      2,      2,      2,
/* C8-CF */     2,      2,      2,      2,      2,      2,      2,      2,
/* D0-D7 */     2,      2,      2,      2,      2,      2,      2,      2,
/* D8-DF */     2,      2,      2,      2,      2,      2,      2,      2,
/* E0-E7 */     3,      3,      3,      3,      3,      3,      3,      3,
/* E8-EF */     3,      3,      3,      3,      3,      3,      3,      3,
/* F0-F7 */     4,      4,      4,      4,      4,      4,      4,      4,
/* F8-FF */     5,      5,      5,      5,      6,      6,      -1,     -1
};



void
chknull(void * p)

{
        if (p)
                return;

        fprintf(stderr, "Not enough memory\n");
        exit(1);
}


void
makecode(char * buf, unsigned int ccsid)

{
        ccsid &= 0xFFFF;
        memset(buf, 0, 32);
        sprintf(buf, "IBMCCSID%05u0000000", ccsid);
}


iconv_t
iconv_open_ccsid(unsigned int ccsidout,
                                unsigned int ccsidin, unsigned int nullflag)

{
        char fromcode[33];
        char tocode[33];

        makecode(fromcode, ccsidin);
        makecode(tocode, ccsidout);
        memset(tocode + 13, 0, sizeof tocode - 13);

        if (nullflag)
                fromcode[18] = '1';

        return iconv_open(tocode, fromcode);
}


unsigned int
getnum(char * * cpp)

{
        unsigned int n;
        char * cp;

        cp = *cpp;
        n = 0;

        while (isdigit(*cp))
                n = 10 * n + *cp++ - '0';

        *cpp = cp;
        return n;
}


const utf8char *
hashBinaryKey(const byte * bytes, unsigned int len)

{
        const byte * bp;
        utf8char * key;
        utf8char * cp;
        unsigned int n;
        unsigned int n4;
        unsigned int i;

        /**
        ***     Encode binary data in character form to be used as hash
        ***             table key.
        **/

        n = (4 * len + 2) / 3;
        key = (utf8char *) malloc(n + 1);
        chknull(key);
        bp = bytes;
        cp = key;

        for (n4 = n >> 2; n4; n4--) {
                i = (bp[0] << 16) | (bp[1] << 8) | bp[2];
                *cp++ = 0x21 + ((i >> 18) & 0x3F);
                *cp++ = 0x21 + ((i >> 12) & 0x3F);
                *cp++ = 0x21 + ((i >> 6) & 0x3F);
                *cp++ = 0x21 + (i & 0x3F);
                bp += 3;
                }

        switch (n & 0x3) {

        case 2:
                *cp++ = 0x21 + ((*bp >> 2) & 0x3F);
                *cp++ = 0x21 + ((*bp << 4) & 0x3F);
                break;

        case 3:
                i = (bp[0] << 8) | bp[1];
                *cp++ = 0x21 + ((i >> 10) & 0x3F);
                *cp++ = 0x21 + ((i >> 4) & 0x3F);
                *cp++ = 0x21 + ((i << 2) & 0x3F);
                break;
                }

        *cp = '\0';
        return key;
}


void *
hash_get(xmlHashTablePtr h, const void * binkey, unsigned int len)

{
        const utf8char * key;
        void * result;

        key = hashBinaryKey((const byte *) binkey, len);
        result = xmlHashLookup(h, key);
        free((char *) key);
        return result;
}


int
hash_add(xmlHashTablePtr h, const void * binkey, unsigned int len, void * data)

{
        const utf8char * key;
        int result;

        key = hashBinaryKey((const byte *) binkey, len);
        result = xmlHashAddEntry(h, key, data);
        free((char *) key);
        return result;
}


xmlDocPtr
loadXMLFile(const char * filename)

{
        struct stat sbuf;
        byte * databuf;
        int fd;
        int i;
        xmlDocPtr doc;

        if (stat(filename, &sbuf))
                return (xmlDocPtr) NULL;

        databuf = malloc(sbuf.st_size + 4);

        if (!databuf)
                return (xmlDocPtr) NULL;

        fd = open(filename, O_RDONLY
#ifdef O_BINARY
                                         | O_BINARY
#endif
                                                        );

        if (fd < 0) {
                free((char *) databuf);
                return (xmlDocPtr) NULL;
                }

        i = read(fd, (char *) databuf, sbuf.st_size);
        close(fd);

        if (i != sbuf.st_size) {
                free((char *) databuf);
                return (xmlDocPtr) NULL;
                }

        databuf[i] = databuf[i + 1] = databuf[i + 2] = databuf[i + 3] = 0;
        doc = xmlParseMemory((xmlChar *) databuf, i);
        free((char *) databuf);
        return doc;
}


int
match(char * * cpp, char * s)

{
        char * cp;
        int c1;
        int c2;

        cp = *cpp;

        for (cp = *cpp; c2 = *s++; cp++) {
                c1 = *cp;

                if (c1 != c2) {
                        if (isupper(c1))
                                c1 = tolower(c1);

                        if (isupper(c2))
                                c2 = tolower(c2);
                        }

                if (c1 != c2)
                        return 0;
                }

        c1 = *cp;

        while (c1 == ' ' || c1 == '\t')
                c1 = *++cp;

        *cpp = cp;
        return 1;
}


t_state *
newstate(void)

{
        t_state * s;

        s = (t_state *) malloc(sizeof *s);
        chknull(s);
        memset((char *) s, 0, sizeof *s);
        return s;
}


void
unlink_transition(t_transition * t)

{
        if (t->t_backnext)
                t->t_backnext->t_backprev = t->t_backprev;

        if (t->t_backprev)
                t->t_backprev->t_backnext = t->t_backnext;
        else if (t->t_to)
                t->t_to->s_backward = t->t_backnext;

        if (t->t_forwnext)
                t->t_forwnext->t_forwprev = t->t_forwprev;

        if (t->t_forwprev)
                t->t_forwprev->t_forwnext = t->t_forwnext;
        else if (t->t_from)
                t->t_from->s_forward = t->t_forwnext;

        t->t_backprev = (t_transition *) NULL;
        t->t_backnext = (t_transition *) NULL;
        t->t_forwprev = (t_transition *) NULL;
        t->t_forwnext = (t_transition *) NULL;
        t->t_from = (t_state *) NULL;
        t->t_to = (t_state *) NULL;
}


void
link_transition(t_transition * t, t_state * from, t_state * to)

{
        if (!from)
                from = t->t_from;

        if (!to)
                to = t->t_to;

        unlink_transition(t);

        if ((t->t_from = from)) {
                if ((t->t_forwnext = from->s_forward))
                        t->t_forwnext->t_forwprev = t;

                from->s_forward = t;
                }

        if ((t->t_to = to)) {
                if ((t->t_backnext = to->s_backward))
                        t->t_backnext->t_backprev = t;

                to->s_backward = t;
                }
}


t_transition *
newtransition(unsigned int token, t_state * from, t_state * to)

{
        t_transition * t;

        t = (t_transition *) malloc(sizeof *t);
        chknull(t);
        memset((char *) t, 0, sizeof *t);
        t->t_token = token;
        link_transition(t, from, to);
        return t;
}


t_transition *
uniquetransition(unsigned int token, t_state * from, t_state * to)

{
        t_transition * t;

        for (t = from->s_forward; t; t = t->t_forwnext)
                if (t->t_token == token && (t->t_to == to || !to))
                        return t;

        return to? newtransition(token, from, to): (t_transition *) NULL;
}


int
set_position(t_powerset * s, void * e)

{
        unsigned int l;
        unsigned int h;
        unsigned int m;
        int i;

        l = 0;
        h = s->p_card;

        while (l < h) {
                m = (l + h) >> 1;

                /**
                ***     If both pointers belong to different allocation arenas,
                ***             native comparison may find them neither
                ***             equal, nor greater, nor smaller.
                ***     We thus compare using memcmp() to get an orthogonal
                ***             result.
                **/

                i = memcmp(&e, s->p_set + m, sizeof e);

                if (i < 0)
                        h = m;
                else if (!i)
                        return m;
                else
                        l = m + 1;
                }

        return l;
}


t_powerset *
set_include(t_powerset * s, void * e)

{
        unsigned int pos;
        unsigned int n;

        if (!s) {
                s = (t_powerset *) malloc(sizeof *s +
                    GRANULE * sizeof s->p_set);
                chknull(s);
                s->p_size = GRANULE;
                s->p_set[GRANULE] = (t_state *) NULL;
                s->p_set[0] = e;
                s->p_card = 1;
                return s;
                }

        pos = set_position(s, e);

        if (pos < s->p_card && s->p_set[pos] == e)
                return s;

        if (s->p_card >= s->p_size) {
                s->p_size += GRANULE;
                s = (t_powerset *) realloc(s,
                    sizeof *s + s->p_size * sizeof s->p_set);
                chknull(s);
                s->p_set[s->p_size] = (t_state *) NULL;
                }

        n = s->p_card - pos;

        if (n)
                memmove((char *) (s->p_set + pos + 1),
                    (char *) (s->p_set + pos), n * sizeof s->p_set[0]);

        s->p_set[pos] = e;
        s->p_card++;
        return s;
}


t_state *
nfatransition(t_state * to, byte token)

{
        t_state * from;

        from = newstate();
        newtransition(token, from, to);
        return from;
}


static t_state *        nfadevelop(t_state * from, t_state * final, iconv_t icc,
                                const utf8char * name, unsigned int len);


void
nfaslice(t_state * * from, t_state * * to, iconv_t icc,
                const utf8char * chr, unsigned int chlen,
                const utf8char * name, unsigned int len, t_state * final)

{
        char * srcp;
        char * dstp;
        size_t srcc;
        size_t dstc;
        unsigned int cnt;
        t_state * f;
        t_state * t;
        t_transition * tp;
        byte bytebuf[8];

        srcp = (char *) chr;
        srcc = chlen;
        dstp = (char *) bytebuf;
        dstc = sizeof bytebuf;
        iconv(icc, &srcp, &srcc, &dstp, &dstc);
        dstp = (char *) bytebuf;
        cnt = sizeof bytebuf - dstc;
        t = *to;
        f = *from;

        /**
        ***     Check for end of string.
        **/

        if (!len)
                if (t && t != final)
                        uniquetransition(EPSILON, t, final);
                else
                        t = final;

        if (f)
                while (cnt) {
                        tp = uniquetransition(*dstp, f, (t_state *) NULL);

                        if (!tp)
                                break;

                        f = tp->t_to;
                        dstp++;
                        cnt--;
                        }

        if (!cnt) {
                if (!t)
                        t = nfadevelop(f, final, icc, name, len);

                *to = t;
                return;
                }

        if (!t) {
                t = nfadevelop((t_state *) NULL, final, icc, name, len);
                *to = t;
                }

        if (!f)
                *from = f = newstate();

        while (cnt > 1)
                t = nfatransition(t, dstp[--cnt]);

        newtransition(*dstp, f, t);
}


t_state *
nfadevelop(t_state * from, t_state * final, iconv_t icc,
                                        const utf8char * name, unsigned int len)

{
        int chlen;
        int i;
        t_state * to;
        int uccnt;
        int lccnt;
        utf8char chr;

        chlen = utf8_chlen[*name];

        for (i = 1; i < chlen; i++)
                if ((name[i] & 0xC0) != 0x80)
                        break;

        if (i != chlen) {
                fprintf(stderr,
                    "Invalid UTF8 character in character set name\n");
                return (t_state *) NULL;
                }

        to = (t_state *) NULL;
        nfaslice(&from, &to,
            icc, name, chlen, name + chlen, len - chlen, final);

        if (*name >= UTF8_a && *name <= UTF8_z)
                chr = *name - UTF8_a + UTF8_A;
        else if (*name >= UTF8_A && *name <= UTF8_Z)
                chr = *name - UTF8_A + UTF8_a;
        else
                return from;

        nfaslice(&from, &to, icc, &chr, 1, name + chlen, len - chlen, final);
        return from;
}



void
nfaenter(const utf8char * name, int len, t_chset * charset)

{
        t_chset * s;
        t_state * final;
        t_state * sp;
        t_symlist * lp;

        /**
        ***     Enter case-insensitive `name' in NFA in all known
        ***             character codes.
        ***     Redundant shift state changes as well as shift state
        ***             differences between uppercase and lowercase are
        ***             not handled.
        **/

        if (len < 0)
                len = strlen(name) + 1;

        for (lp = charset->c_names; lp; lp = lp->l_next)
                if (!memcmp(name, lp->l_symbol, len))
                        return;         /* Already entered. */

        lp = (t_symlist *) malloc(sizeof *lp + len);
        chknull(lp);
        memcpy(lp->l_symbol, name, len);
        lp->l_symbol[len] = '\0';
        lp->l_next = charset->c_names;
        charset->c_names = lp;
        final = newstate();
        final->s_final = charset;

        for (s = chset_list; s; s = s->c_next)
                if (!iconv_open_error(s->c_fromUTF8))
                        sp = nfadevelop(initial_state, final,
                            s->c_fromUTF8, name, len);
}


unsigned int
utf8_utostr(utf8char * s, unsigned int v)

{
        unsigned int d;
        unsigned int i;

        d = v / 10;
        v -= d * 10;
        i = d? utf8_utostr(s, d): 0;
        s[i++] = v + UTF8_0;
        s[i] = '\0';
        return i;
}


unsigned int
utf8_utostrpad(utf8char * s, unsigned int v, int digits)

{
        unsigned int i = utf8_utostr(s, v);
        utf8char pad = UTF8_SPACE;

        if (digits < 0) {
                pad = UTF8_0;
                digits = -digits;
                }

        if (i >= digits)
                return i;

        memmove(s + digits - i, s, i + 1);
        memset(s, pad, digits - i);
        return digits;
}


unsigned int
utf8_strtou(const utf8char * s)

{
        unsigned int v;

        while (*s == UTF8_SPACE || *s == UTF8_HT)
                s++;

        for (v = 0; *s >= UTF8_0 && *s <= UTF8_9;)
                v = 10 * v + *s++ - UTF8_0;

        return v;
}


unsigned int
getNumAttr(xmlNodePtr node, const xmlChar * name)

{
        const xmlChar * s;
        unsigned int val;

        s = xmlGetProp(node, name);

        if (!s)
                return 0;

        val = utf8_strtou(s);
        xmlFree((xmlChar *) s);
        return val;
}


void
read_assocs(const char * filename)

{
        xmlDocPtr doc;
        xmlXPathContextPtr ctxt;
        xmlXPathObjectPtr obj;
        xmlNodePtr node;
        t_chset * sp;
        int i;
        unsigned int ccsid;
        unsigned int mibenum;
        utf8char symbuf[32];

        doc = loadXMLFile(filename);

        if (!doc) {
                fprintf(stderr, "Cannot load file %s\n", filename);
                exit(1);
                }

        ctxt = xmlXPathNewContext(doc);
        obj = xmlXPathEval(utf8_assocnodes, ctxt);

        if (!obj || obj->type != XPATH_NODESET || !obj->nodesetval ||
            !obj->nodesetval->nodeTab || !obj->nodesetval->nodeNr) {
                fprintf(stderr, "No association found in %s\n", filename);
                exit(1);
                }

        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
                node = obj->nodesetval->nodeTab[i];
                ccsid = getNumAttr(node, utf8_ccsid);
                mibenum = getNumAttr(node, utf8_mibenum);

                /**
                ***     Check for duplicate.
                **/

                for (sp = chset_list; sp; sp = sp->c_next)
                        if (ccsid && ccsid == sp->c_ccsid ||
                            mibenum && mibenum == sp->c_mibenum) {
                                fprintf(stderr, "Duplicate character set: ");
                                fprintf(stderr, "CCSID = %u/%u, ",
                                    ccsid, sp->c_ccsid);
                                fprintf(stderr, "MIBenum = %u/%u\n",
                                    mibenum, sp->c_mibenum);
                                break;
                                }

                if (sp)
                        continue;

                /**
                ***     Allocate the new character set.
                **/

                sp = (t_chset *) malloc(sizeof *sp);
                chknull(sp);
                memset(sp, 0, sizeof *sp);

                if (!ccsid)     /* Do not attempt with current job CCSID. */
                        set_iconv_open_error(sp->c_fromUTF8);
                else {
                        sp->c_fromUTF8 =
                            iconv_open_ccsid(ccsid, C_UTF8_CCSID, 0);

                        if (iconv_open_error(sp->c_fromUTF8) == -1)
                                fprintf(stderr,
                                    "Cannot convert into CCSID %u: ignored\n",
                                    ccsid);
                        }

                sp->c_ccsid = ccsid;
                sp->c_mibenum = mibenum;
                sp->c_next = chset_list;
                chset_list = sp;
                }

        xmlXPathFreeObject(obj);

        /**
        ***     Enter aliases.
        **/

        for (sp = chset_list; sp; sp = sp->c_next) {
                strcpy(symbuf, utf8_ibm_);
                utf8_utostr(symbuf + 4, sp->c_ccsid);
                nfaenter(symbuf, -1, sp);
                strcpy(symbuf, utf8_IBMCCSID);
                utf8_utostrpad(symbuf + 8, sp->c_ccsid, -5);
                nfaenter(symbuf, 13, sp);       /* Not null-terminated. */

                if (sp->c_mibenum) {
                        strcpy(symbuf, utf8_iana_);
                        utf8_utostr(symbuf + 5, sp->c_mibenum);
                        nfaenter(symbuf, -1, sp);
                        }

                xmlXPathRegisterVariable(ctxt, utf8_C,
                    xmlXPathNewFloat((double) sp->c_ccsid));
                obj = xmlXPathEval(utf8_aliastext, ctxt);

                if (!obj || obj->type != XPATH_NODESET) {
                        fprintf(stderr, "getAlias failed in %s\n", filename);
                        exit(1);
                        }

                if (obj->nodesetval &&
                    obj->nodesetval->nodeTab && obj->nodesetval->nodeNr) {
                        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
                                node = obj->nodesetval->nodeTab[i];
                                nfaenter(node->content, -1, sp);
                                }
                        }

                xmlXPathFreeObject(obj);
                }

        xmlXPathFreeContext(ctxt);
        xmlFreeDoc(doc);
}


unsigned int
columnPosition(xmlXPathContextPtr ctxt, const xmlChar * header)

{
        xmlXPathObjectPtr obj;
        unsigned int res = 0;

        xmlXPathRegisterVariable(ctxt, utf8_T, xmlXPathNewString(header));
        obj = xmlXPathEval(utf8_headerpos, ctxt);

        if (obj) {
                if (obj->type == XPATH_NUMBER)
                        res = (unsigned int) obj->floatval;

                xmlXPathFreeObject(obj);
                }

        return res;
}


void
read_iana(const char * filename)

{
        xmlDocPtr doc;
        xmlXPathContextPtr ctxt;
        xmlXPathObjectPtr obj1;
        xmlXPathObjectPtr obj2;
        xmlNodePtr node;
        int prefnamecol;
        int namecol;
        int mibenumcol;
        int aliascol;
        int mibenum;
        t_chset * sp;
        int n;
        int i;

        doc = loadXMLFile(filename);

        if (!doc) {
                fprintf(stderr, "Cannot load file %s\n", filename);
                exit(1);
                }

        ctxt = xmlXPathNewContext(doc);

#ifndef OLDXML
        xmlXPathRegisterNs(ctxt, utf8_html, utf8_htmluri);
#endif

        obj1 = xmlXPathEval(utf8_tablerows, ctxt);

        if (!obj1 || obj1->type != XPATH_NODESET || !obj1->nodesetval ||
            !obj1->nodesetval->nodeTab || obj1->nodesetval->nodeNr <= 1) {
                fprintf(stderr, "No data in %s\n", filename);
                exit(1);
                }

        /**
        ***     Identify columns.
        **/

        xmlXPathSetContextNode(obj1->nodesetval->nodeTab[0], ctxt);
        prefnamecol = columnPosition(ctxt, utf8_Pref_MIME_Name);
        namecol = columnPosition(ctxt, utf8_Name);
        mibenumcol = columnPosition(ctxt, utf8_MIBenum);
        aliascol = columnPosition(ctxt, utf8_Aliases);

        if (!prefnamecol || !namecol || !mibenumcol || !aliascol) {
                fprintf(stderr, "Key column(s) missing in %s\n", filename);
                exit(1);
                }

        xmlXPathRegisterVariable(ctxt, utf8_P,
            xmlXPathNewFloat((double) prefnamecol));
        xmlXPathRegisterVariable(ctxt, utf8_N,
            xmlXPathNewFloat((double) namecol));
        xmlXPathRegisterVariable(ctxt, utf8_M,
            xmlXPathNewFloat((double) mibenumcol));
        xmlXPathRegisterVariable(ctxt, utf8_A,
            xmlXPathNewFloat((double) aliascol));

        /**
        ***     Process each row.
        **/

        for (n = 1; n < obj1->nodesetval->nodeNr; n++) {
                xmlXPathSetContextNode(obj1->nodesetval->nodeTab[n], ctxt);

                /**
                ***     Get the MIBenum from current row.
                */

                obj2 = xmlXPathEval(utf8_getmibenum, ctxt);

                if (!obj2 || obj2->type != XPATH_NUMBER) {
                        fprintf(stderr, "get MIBenum failed at row %u\n", n);
                        exit(1);
                        }

                if (xmlXPathIsNaN(obj2->floatval) ||
                    obj2->floatval < 1.0 || obj2->floatval > 65535.0 ||
                    ((unsigned int) obj2->floatval) != obj2->floatval) {
                        fprintf(stderr, "invalid MIBenum at row %u\n", n);
                        xmlXPathFreeObject(obj2);
                        continue;
                        }

                mibenum = obj2->floatval;
                xmlXPathFreeObject(obj2);

                /**
                ***     Search the associations for a corresponding CCSID.
                **/

                for (sp = chset_list; sp; sp = sp->c_next)
                        if (sp->c_mibenum == mibenum)
                                break;

                if (!sp)
                        continue;       /* No CCSID for this MIBenum. */

                /**
                ***     Process preferred MIME name.
                **/

                obj2 = xmlXPathEval(utf8_getprefname, ctxt);

                if (!obj2 || obj2->type != XPATH_STRING) {
                        fprintf(stderr,
                            "get Preferred_MIME_Name failed at row %u\n", n);
                        exit(1);
                        }

                if (obj2->stringval && obj2->stringval[0])
                        nfaenter(obj2->stringval, -1, sp);

                xmlXPathFreeObject(obj2);

                /**
                ***     Process name.
                **/

                obj2 = xmlXPathEval(utf8_getname, ctxt);

                if (!obj2 || obj2->type != XPATH_STRING) {
                        fprintf(stderr, "get name failed at row %u\n", n);
                        exit(1);
                        }

                if (obj2->stringval && obj2->stringval[0])
                        nfaenter(obj2->stringval, -1, sp);

                xmlXPathFreeObject(obj2);

                /**
                ***     Process aliases.
                **/

                obj2 = xmlXPathEval(utf8_getaliases, ctxt);

                if (!obj2 || obj2->type != XPATH_NODESET) {
                        fprintf(stderr, "get aliases failed at row %u\n", n);
                        exit(1);
                        }

                if (obj2->nodesetval && obj2->nodesetval->nodeTab)
                        for (i = 0; i < obj2->nodesetval->nodeNr; i++) {
                                node = obj2->nodesetval->nodeTab[i];

                                if (node && node->content && node->content[0])
                                        nfaenter(node->content, -1, sp);
                                }

                xmlXPathFreeObject(obj2);
                }

        xmlXPathFreeObject(obj1);
        xmlXPathFreeContext(ctxt);
        xmlFreeDoc(doc);
}


t_powerset *    closureset(t_powerset * dst, t_powerset * src);


t_powerset *
closure(t_powerset * dst, t_state * src)

{
        t_transition * t;
        unsigned int oldcard;

        if (src->s_nfastates) {
                /**
                ***     Is a DFA state: return closure of set of equivalent
                ***             NFA states.
                **/

                return closureset(dst, src->s_nfastates);
                }

        /**
        ***     Compute closure of NFA state.
        **/

        dst = set_include(dst, src);

        for (t = src->s_forward; t; t = t->t_forwnext)
                if (t->t_token == EPSILON) {
                        oldcard = dst->p_card;
                        dst = set_include(dst, t->t_to);

                        if (oldcard != dst->p_card)
                                dst = closure(dst, t->t_to);
                        }

        return dst;
}


t_powerset *
closureset(t_powerset * dst, t_powerset * src)

{
        unsigned int i;

        for (i = 0; i < src->p_card; i++)
                dst = closure(dst, (t_state *) src->p_set[i]);

        return dst;
}


t_state *
get_dfa_state(t_state * * stack,
                        t_powerset * nfastates, xmlHashTablePtr sethash)

{
        t_state * s;

        if (s = hash_get(sethash, nfastates->p_set,
            nfastates->p_card * sizeof nfastates->p_set[0])) {
                /**
                ***     DFA state already present.
                ***     Release the NFA state set and return
                ***             the address of the old DFA state.
                **/

                free((char *) nfastates);
                return s;
                }

        /**
        ***     Build the new state.
        **/

        s = newstate();
        s->s_nfastates = nfastates;
        s->s_next = dfa_states;
        dfa_states = s;
        s->s_stack = *stack;
        *stack = s;

        /**
        ***     Enter it in hash.
        **/

        if (hash_add(sethash, nfastates->p_set,
            nfastates->p_card * sizeof nfastates->p_set[0], s))
                chknull(NULL);          /* Memory allocation error. */

        return s;
}


int
transcmp(const void * p1, const void * p2)

{
        t_transition * t1;
        t_transition * t2;

        t1 = *(t_transition * *) p1;
        t2 = *(t_transition * *) p2;
        return ((int) t1->t_token) - ((int) t2->t_token);
}


void
builddfa(void)

{
        t_powerset * transset;
        t_powerset * stateset;
        t_state * s;
        t_state * s2;
        unsigned int n;
        unsigned int i;
        unsigned int token;
        t_transition * t;
        t_state * stack;
        xmlHashTablePtr sethash;
        unsigned int nst;

        transset = set_include(NULL, NULL);
        chknull(transset);
        stateset = set_include(NULL, NULL);
        chknull(stateset);
        sethash = xmlHashCreate(1);
        chknull(sethash);
        dfa_states = (t_state *) NULL;
        stack = (t_state *) NULL;
        nst = 0;

        /**
        ***     Build the DFA initial state.
        **/

        get_dfa_state(&stack, closure(NULL, initial_state), sethash);

        /**
        ***     Build the other DFA states by looking at each
        ***             possible transition from stacked DFA states.
        **/

        do {
                if (!(++nst % 100))
                        fprintf(stderr, "%u DFA states\n", nst);

                s = stack;
                stack = s->s_stack;
                s->s_stack = (t_state *) NULL;

                /**
                ***     Build a set of all non-epsilon transitions from this
                ***             state.
                **/

                transset->p_card = 0;

                for (n = 0; n < s->s_nfastates->p_card; n++) {
                        s2 = s->s_nfastates->p_set[n];

                        for (t = s2->s_forward; t; t = t->t_forwnext)
                                if (t->t_token != EPSILON) {
                                        transset = set_include(transset, t);
                                        chknull(transset);
                                        }
                        }

                /**
                ***     Sort transitions by token.
                **/

                qsort(transset->p_set, transset->p_card,
                    sizeof transset->p_set[0], transcmp);

                /**
                ***     Process all transitions, grouping them by token.
                **/

                stateset->p_card = 0;
                token = EPSILON;

                for (i = 0; i < transset->p_card; i++) {
                        t = transset->p_set[i];

                        if (token != t->t_token) {
                                if (stateset->p_card) {
                                        /**
                                        ***     Get the equivalent DFA state
                                        ***             and create transition.
                                        **/

                                        newtransition(token, s,
                                            get_dfa_state(&stack,
                                            closureset(NULL, stateset),
                                            sethash));
                                        stateset->p_card = 0;
                                        }

                                token = t->t_token;
                                }

                        stateset = set_include(stateset, t->t_to);
                        }

                if (stateset->p_card)
                        newtransition(token, s, get_dfa_state(&stack,
                            closureset(NULL, stateset), sethash));
        } while (stack);

        free((char *) transset);
        free((char *) stateset);
        xmlHashFree(sethash, NULL);

        /**
        ***     Reverse the state list to get the initial state first,
        ***             check for ambiguous prefixes, determine final states,
        ***             destroy NFA state sets.
        **/

        while (s = dfa_states) {
                dfa_states = s->s_next;
                s->s_next = stack;
                stack = s;
                stateset = s->s_nfastates;
                s->s_nfastates = (t_powerset *) NULL;

                for (n = 0; n < stateset->p_card; n++) {
                        s2 = (t_state *) stateset->p_set[n];

                        if (s2->s_final) {
                                if (s->s_final && s->s_final != s2->s_final)
                                        fprintf(stderr,
                                            "Ambiguous name for CCSIDs %u/%u\n",
                                            s->s_final->c_ccsid,
                                            s2->s_final->c_ccsid);

                                s->s_final = s2->s_final;
                                }
                        }

                free((char *) stateset);
                }

        dfa_states = stack;
}


void
deletenfa(void)

{
        t_transition * t;
        t_state * s;
        t_state * u;
        t_state * stack;

        stack = initial_state;
        stack->s_stack = (t_state *) NULL;

        while ((s = stack)) {
                stack = s->s_stack;

                while ((t = s->s_forward)) {
                        u = t->t_to;
                        unlink_transition(t);
                        free((char *) t);

                        if (!u->s_backward) {
                                u->s_stack = stack;
                                stack = u;
                                }
                        }

                free((char *) s);
                }
}


t_stategroup *
newgroup(void)

{
        t_stategroup * g;

        g = (t_stategroup *) malloc(sizeof *g);
        chknull(g);
        memset((char *) g, 0, sizeof *g);
        g->g_id = groupid++;
        return g;
}


void
optimizedfa(void)

{
        unsigned int i;
        xmlHashTablePtr h;
        t_state * s1;
        t_state * s2;
        t_state * finstates;
        t_state * * sp;
        t_stategroup * g1;
        t_stategroup * g2;
        t_stategroup * ghead;
        t_transition * t1;
        t_transition * t2;
        unsigned int done;
        unsigned int startgroup;
        unsigned int gtrans[1 << (8 * sizeof(unsigned char))];

        /**
        ***     Reduce DFA state count.
        **/

        groupid = 0;
        ghead = (t_stategroup *) NULL;

        /**
        ***     First split: non-final and each distinct final states.
        **/

        h = xmlHashCreate(4);
        chknull(h);

        for (s1 = dfa_states; s1; s1 = s1->s_next) {
                if (!(g1 = hash_get(h, &s1->s_final, sizeof s1->s_final))) {
                        g1 = newgroup();
                        g1->g_next = ghead;
                        ghead = g1;

                        if (hash_add(h, &s1->s_final, sizeof s1->s_final, g1))
                                chknull(NULL);  /* Memory allocation error. */
                        }

                s1->s_index = g1->g_id;
                s1->s_stack = g1->g_member;
                g1->g_member = s1;
                }

        xmlHashFree(h, NULL);

        /**
        ***     Subsequent splits: states that have the same forward
        ***             transition tokens to states in the same group.
        **/

        do {
                done = 1;

                for (g2 = ghead; g2; g2 = g2->g_next) {
                        s1 = g2->g_member;

                        if (!s1->s_stack)
                                continue;

                        h = xmlHashCreate(1);
                        chknull(h);

                        /**
                        ***     Build the group transition map.
                        **/

                        memset((char *) gtrans, ~0, sizeof gtrans);

                        for (t1 = s1->s_forward; t1; t1 = t1->t_forwnext)
                                gtrans[t1->t_token] = t1->t_to->s_index;

                        if (hash_add(h, gtrans, sizeof gtrans, g2))
                                chknull(NULL);

                        /**
                        ***     Process other states in group.
                        **/

                        sp = &s1->s_stack;
                        s1 = *sp;

                        do {
                                *sp = s1->s_stack;

                                /**
                                ***     Build the transition map.
                                **/

                                memset((char *) gtrans, ~0, sizeof gtrans);

                                for (t1 = s1->s_forward;
                                    t1; t1 = t1->t_forwnext)
                                        gtrans[t1->t_token] = t1->t_to->s_index;

                                g1 = hash_get(h, gtrans, sizeof gtrans);

                                if (g1 == g2) {
                                        *sp = s1;
                                        sp = &s1->s_stack;
                                        }
                                else {
                                        if (!g1) {
                                                g1 = newgroup();
                                                g1->g_next = ghead;
                                                ghead = g1;

                                                if (hash_add(h, gtrans,
                                                    sizeof gtrans, g1))
                                                        chknull(NULL);
                                                }

                                        s1->s_index = g1->g_id;
                                        s1->s_stack = g1->g_member;
                                        g1->g_member = s1;
                                        done = 0;
                                        }
                        } while (s1 = *sp);

                        xmlHashFree(h, NULL);
                        }
        } while (!done);

        /**
        ***     Establish group leaders and remap transitions.
        **/

        startgroup = dfa_states->s_index;

        for (g1 = ghead; g1; g1 = g1->g_next)
                for (s1 = g1->g_member->s_stack; s1; s1 = s1->s_stack)
                        for (t1 = s1->s_backward; t1; t1 = t2) {
                                t2 = t1->t_backnext;
                                link_transition(t1, NULL, g1->g_member);
                                }

        /**
        ***     Remove redundant states and transitions.
        **/

        for (g1 = ghead; g1; g1 = g1->g_next) {
                g1->g_member->s_next = (t_state *) NULL;

                while ((s1 = g1->g_member->s_stack)) {
                        g1->g_member->s_stack = s1->s_stack;

                        for (t1 = s1->s_forward; t1; t1 = t2) {
                                t2 = t1->t_forwnext;
                                unlink_transition(t1);
                                free((char *) t1);
                                }

                        free((char *) s1);
                        }
                }

        /**
        ***     Remove group support and relink DFA states.
        **/

        dfa_states = (t_state *) NULL;
        s2 = (t_state *) NULL;
        finstates = (t_state *) NULL;

        while (g1 = ghead) {
                ghead = g1->g_next;
                s1 = g1->g_member;

                if (g1->g_id == startgroup)
                        dfa_states = s1;        /* Keep start state first. */
                else if (s1->s_final) {         /* Then final states. */
                        s1->s_next = finstates;
                        finstates = s1;
                        }
                else {                  /* Finish with non-final states. */
                        s1->s_next = s2;
                        s2 = s1;
                        }

                free((char *) g1);
                }

        for (dfa_states->s_next = finstates; finstates->s_next;)
                finstates = finstates->s_next;

        finstates->s_next = s2;
}


const char *
inttype(unsigned long max)

{
        int i;

        for (i = 0; max; i++)
                max >>= 1;

        if (i > 8 * sizeof(unsigned int))
                return "unsigned long";

        if (i > 8 * sizeof(unsigned short))
                return "unsigned int";

        if (i > 8 * sizeof(unsigned char))
                return "unsigned short";

        return "unsigned char";
}


listids(FILE * fp)

{
        unsigned int pos;
        t_chset * cp;
        t_symlist * lp;
        char * srcp;
        char * dstp;
        size_t srcc;
        size_t dstc;
        char buf[80];

        fprintf(fp, "/**\n***     CCSID   For arg   Recognized name.\n");
        pos = 0;

        for (cp = chset_list; cp; cp = cp->c_next) {
                if (pos) {
                        fprintf(fp, "\n");
                        pos = 0;
                        }

                if (!cp->c_names)
                        continue;

                pos = fprintf(fp, "***     %5u      %c     ", cp->c_ccsid,
                    iconv_open_error(cp->c_fromUTF8)? ' ': 'X');

                for (lp = cp->c_names; lp; lp = lp->l_next) {
                        srcp = (char *) lp->l_symbol;
                        srcc = strlen(srcp);
                        dstp = buf;
                        dstc = sizeof buf;
                        iconv(utf82job, &srcp, &srcc, &dstp, &dstc);
                        srcc = dstp - buf;

                        if (pos + srcc > 79) {
                                fprintf(fp, "\n***%22c", ' ');
                                pos = 25;
                                }

                        pos += fprintf(fp, " %.*s", srcc, buf);
                        }
                }

        if (pos)
                fprintf(fp, "\n");

        fprintf(fp, "**/\n\n");
}


void
generate(FILE * fp)

{
        unsigned int nstates;
        unsigned int ntrans;
        unsigned int maxfinal;
        t_state * s;
        t_transition * t;
        unsigned int i;
        unsigned int pos;
        char * ns;

        /**
        ***     Assign indexes to states and transitions.
        **/

        nstates = 0;
        ntrans = 0;
        maxfinal = 0;

        for (s = dfa_states; s; s = s->s_next) {
                s->s_index = nstates++;

                if (s->s_final)
                        maxfinal = nstates;

                for (t = s->s_forward; t; t = t->t_forwnext)
                        t->t_index = ntrans++;
                }

        fprintf(fp,
            "/**\n***     %u states, %u finals, %u transitions.\n**/\n\n",
            nstates, maxfinal, ntrans);
        fprintf(stderr, "%u states, %u finals, %u transitions.\n",
            nstates, maxfinal, ntrans);

        /**
        ***     Generate types.
        **/

        fprintf(fp, "typedef unsigned short          t_ccsid;\n");
        fprintf(fp, "typedef %-23s t_staterange;\n", inttype(nstates));
        fprintf(fp, "typedef %-23s t_transrange;\n\n", inttype(ntrans));

        /**
        ***     Generate first transition index for each state.
        **/

        fprintf(fp, "static t_transrange     trans_array[] = {\n");
        pos = 0;
        ntrans = 0;

        for (s = dfa_states; s; s = s->s_next) {
                pos += fprintf(fp, " %u,", ntrans);

                if (pos > 72) {
                        fprintf(fp, "\n");
                        pos = 0;
                        }

                for (t = s->s_forward; t; t = t->t_forwnext)
                        ntrans++;
                }

        fprintf(fp, " %u\n};\n\n", ntrans);

        /**
        ***     Generate final state info.
        **/

        fprintf(fp, "static t_ccsid          final_array[] = {\n");
        pos = 0;
        ns ="";
        i = 0;

        for (s = dfa_states; s && i++ < maxfinal; s = s->s_next) {
                pos += fprintf(fp, "%s", ns);
                ns = ",";

                if (pos > 72) {
                        fprintf(fp, "\n");
                        pos = 0;
                        }

                pos += fprintf(fp, " %u",
                    s->s_final? s->s_final->c_ccsid + 1: 0);
                }

        fprintf(fp, "\n};\n\n");

        /**
        ***     Generate goto table.
        **/

        fprintf(fp, "static t_staterange     goto_array[] = {\n");
        pos = 0;

        for (s = dfa_states; s; s = s->s_next)
                for (t = s->s_forward; t; t = t->t_forwnext) {
                        pos += fprintf(fp, " %u,", t->t_to->s_index);

                        if (pos > 72) {
                                fprintf(fp, "\n");
                                pos = 0;
                                }
                        }

        fprintf(fp, " %u\n};\n\n", nstates);

        /**
        ***     Generate transition label table.
        **/

        fprintf(fp, "static unsigned char    label_array[] = {\n");
        pos = 0;
        ns ="";

        for (s = dfa_states; s; s = s->s_next)
                for (t = s->s_forward; t; t = t->t_forwnext) {
                        pos += fprintf(fp, "%s", ns);
                        ns = ",";

                        if (pos > 72) {
                                fprintf(fp, "\n");
                                pos = 0;
                                }

                        pos += fprintf(fp, " 0x%02X", t->t_token);
                        }

        fprintf(fp, "\n};\n", nstates);
}


main(argc, argv)
int argc;
char * * argv;

{
        FILE * fp;
        t_chset * csp;
        char symbuf[20];

        chset_list = (t_chset *) NULL;
        initial_state = newstate();
        job2utf8 = iconv_open_ccsid(C_UTF8_CCSID, C_SOURCE_CCSID, 0);
        utf82job = iconv_open_ccsid(C_SOURCE_CCSID, C_UTF8_CCSID, 0);

        if (argc != 4) {
                fprintf(stderr, "Usage: %s <ccsid-mibenum file> ", *argv);
                fprintf(stderr, "<iana-character-set file> <output file>\n");
                exit(1);
                }

        /**
        ***     Read CCSID/MIBenum associations. Define special names.
        **/

        read_assocs(argv[1]);

        /**
        ***     Read character set names and establish the case-independent
        ***             name DFA in all possible CCSIDs.
        **/

        read_iana(argv[2]);

        /**
        ***     Build DFA from NFA.
        **/

        builddfa();

        /**
        ***     Delete NFA.
        **/

        deletenfa();

        /**
        ***     Minimize the DFA state count.
        **/

        optimizedfa();

        /**
        ***     Generate the table.
        **/

        fp = fopen(argv[3], "w+");

        if (!fp) {
                perror(argv[3]);
                exit(1);
                }

        fprintf(fp, "/**\n");
        fprintf(fp, "***     Character set names table.\n");
        fprintf(fp, "***     Generated by program BLDCSNDFA from");
        fprintf(fp, " IANA character set assignment file\n");
        fprintf(fp, "***          and CCSID/MIBenum equivalence file.\n");
        fprintf(fp, "***     *** Do not edit by hand ***\n");
        fprintf(fp, "**/\n\n");
        listids(fp);
        generate(fp);

        if (ferror(fp)) {
                perror(argv[3]);
                fclose(fp);
                exit(1);
                }

        fclose(fp);
        iconv_close(job2utf8);
        iconv_close(utf82job);
        exit(0);
}
