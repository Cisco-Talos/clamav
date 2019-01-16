/**
***     XMLLINT command response program.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qshell.h>


/* Variable-length string, with 16-bit length. */
typedef struct {
        short           len;
        char            string[5000];
}               vary2;


/* Variable-length string, with 32-bit length. */
typedef struct {
        int             len;
        char            string[5000];
}               vary4;


/* Multiple occurrence parameter list. */
#define paramlist(itemsize, itemtype)                                   \
        _Packed struct {                                                \
                short           len;                                    \
                union {                                                 \
                         char           _pad[itemsize];                 \
                        itemtype        param;                          \
                }               item[1];                                \
        }


/* Arguments from CL command. */
typedef struct {
        char *          pgm;            /* Program name. */
        vary2 *         stmf;           /* XML file name or URL. */
        vary2 *         dtd;            /* DTD location or public identifier. */
        char *          dtdvalid;       /* *DTDURL or *DTDFPI. */
        vary2 *         schema;         /* Schema file name or URL. */
        vary2 *         schemakind;     /* --schema/--relaxng/--schematron. */
        vary2 *         outstmf;        /* Output stream file name. */
        vary2 *         xpath;          /* XPath filter. */
        vary2 *         pattern;        /* Reader filter pattern. */
        paramlist(5000 + 2, vary2) * path; /* Path for resources. */
        vary2 *         pretty;         /* Pretty-print style. */
        unsigned long * maxmem;         /* Maximum dynamic memory. */
        vary2 *         encoding;       /* Output encoding. */
        paramlist(20 + 2, vary2) * options; /* Other options. */
}               arguments;


/* Definition of QSHELL program. */
extern void     qshell(vary4 * cmd);
#pragma linkage(qshell, OS)
#pragma map(qshell, "QSHELL/QZSHQSHC")


static void
vary4nappend(vary4 * dst, const char * src, size_t len)

{
        if (len > sizeof(dst->string) - dst->len)
                len = sizeof(dst->string) - dst->len;

        if (len) {
                memcpy(dst->string + dst->len, src, len);
                dst->len += len;
                }
}


static void
vary4append(vary4 * dst, const char * src)

{
        vary4nappend(dst, src, strlen(src));
}


static void
vary4arg(vary4 * dst, const char * arg)

{
        vary4nappend(dst, " ", 1);
        vary4append(dst, arg);
}


static void
vary4varg(vary4 * dst, vary2 * arg)

{
        vary4nappend(dst, " ", 1);
        vary4nappend(dst, arg->string, arg->len);
}


static void
vary4vescape(vary4 * dst, vary2 * arg)

{
        int i;

        for (i = 0; i < arg->len; i++)
                if (arg->string[i] == '\'')
                        vary4nappend(dst, "'\"'\"'", 5);
                else
                        vary4nappend(dst, arg->string + i, 1);
}


static void
vary4vargquote(vary4 * dst, vary2 * arg)

{
        vary4nappend(dst, " '", 2);
        vary4vescape(dst, arg);
        vary4nappend(dst, "'", 1);
}


int
main(int argsc, arguments * args)

{
        vary4 cmd;
        int i;
        char textbuf[20];
        char * lang;

        /* find length of library name. */
        for (i = 0; i < 10 && args->pgm[i] && args->pgm[i] != '/'; i++)
                ;

        /* Store program name in command buffer. */
        cmd.len = 0;
        vary4append(&cmd, "/QSYS.LIB/");
        vary4nappend(&cmd, args->pgm, i);
        vary4append(&cmd, ".LIB/XMLLINT.PGM");

        /* Map command arguments to standard xmllint argument vector. */

        if (args->dtd && args->dtd->len) {
                if (args->dtdvalid && args->dtdvalid[4] == 'F')
                        vary4arg(&cmd, "--dtdvalidfpi");
                else
                        vary4arg(&cmd, "--dtdvalid");

                vary4vargquote(&cmd, args->dtd);
                }

        if (args->schema && args->schema->len) {
                vary4varg(&cmd, args->schemakind);
                vary4vargquote(&cmd, args->schema);
                }

        if (args->outstmf && args->outstmf->len) {
                vary4arg(&cmd, "--output");
                vary4vargquote(&cmd, args->outstmf);

                if (args->encoding && args->encoding->len) {
                        vary4arg(&cmd, "--encoding");
                        vary4vargquote(&cmd, args->encoding);
                        }
                }

        if (args->xpath && args->xpath->len) {
                vary4arg(&cmd, "--xpath");
                vary4vargquote(&cmd, args->xpath);
                }

        if (args->pattern && args->pattern->len) {
                vary4arg(&cmd, "--pattern");
                vary4vargquote(&cmd, args->pattern);
                }

        if (args->path && args->path->len) {
                vary4arg(&cmd, "--path '");
                vary4vescape(&cmd, &args->path->item[0].param);
                for (i = 1; i < args->path->len; i++) {
                        vary4nappend(&cmd, ":", 1);
                        vary4vescape(&cmd, &args->path->item[i].param);
                        }
                vary4nappend(&cmd, "'", 1);
                }

        if (args->pretty && args->pretty->len &&
            args->pretty->string[0] != '0') {
                vary4arg(&cmd, "--pretty");
                vary4varg(&cmd, args->pretty);
                }

        if (args->maxmem && *args->maxmem) {
                snprintf(textbuf, sizeof textbuf, "%lu", *args->maxmem);
                vary4arg(&cmd, "--maxmem");
                vary4arg(&cmd, textbuf);
                }

        for (i = 0; i < args->options->len; i++)
                vary4varg(&cmd, &args->options->item[i].param);

        vary4vargquote(&cmd, args->stmf);

        /* Execute the shell command. */
        qshell(&cmd);

        /* Terminate. */
        exit(0);
}
