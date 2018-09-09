/**
***     XMLCATALOG command response program.
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
                _Packed union {                                         \
                         char           _pad[itemsize];                 \
                        itemtype        param;                          \
                }               item[1];                                \
        }

/* Add element list structure. */
typedef struct {
        short           elcount;        /* Element count (=3). */
        paramlist(16, char) type;       /* vary2(16). */
        paramlist(256, char) origin;    /* vary2(256). */
        paramlist(256, char) replace;   /* vary2(256). */
}               addelement;

/* SGML add element list structure. */
typedef struct {
        short           elcount;        /* Element count (=3). */
        paramlist(256, char) catalog;   /* vary2(256). */
        paramlist(256, char) ident;     /* vary2(256). */
}               sgmladdelement;


/* Arguments from CL command. */
typedef struct {
        char *          pgm;            /* Program name. */
        vary2 *         instmf;         /* Input catalog file name. */
        vary2 *         kind;           /* Catalog kind. */
        vary2 *         outstmf;        /* Output catalog file name. */
        vary2 *         convert;        /* Convert SGML to XML. */
        vary2 *         superupd;       /* --no-super-update. */
        vary2 *         verbose;        /* Verbose output. */
        paramlist(256 + 2, vary2) * delete; /* Identifiers to delete. */
        paramlist(2, unsigned short) * add; /* Items to add. */
        paramlist(2, unsigned short) * sgmladd; /* SGML items to add. */
        paramlist(256 + 2, vary2) * resolve; /* Identifiers to resolve. */
        paramlist(5000 + 2, vary2) * catalog; /* Additional catalog files. */
}               arguments;


/* Definition of QSHELL program. */
extern void     qshell(vary4 * cmd);
#pragma linkage(qshell, OS)
#pragma map(qshell, "QSHELL/QZSHQSHC")

/* Macro to handle displacements. */
#define OFFSETBY(t, p, n)       ((t *) (((char *) (p)) + (n)))


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
        char c;
        addelement * aelp;
        sgmladdelement * saelp;

        /* Specify additional catalogs. */
        cmd.len = 0;
        if (args->catalog->len) {
                for (i = 0; i < args->catalog->len &&
                            !args->catalog->item[i].param.len; i++)
                        ;

                vary4append(&cmd, "XML_CATALOG_FILES=");
                if (i < args->catalog->len) {
                        c = '\'';
                        for (i = 0; i < args->catalog->len; i++) {
                                if (!args->catalog->item[i].param.len)
                                        continue;
                                vary4nappend(&cmd, &c, 1);
                                c = ' ';
                                vary4vescape(&cmd,
                                            &args->catalog->item[i].param);
                                }
                        vary4nappend(&cmd, "'", 1);
                        }
                vary4nappend(&cmd, " ", 1);
                }

        /* find length of library name. */
        for (i = 0; i < 10 && args->pgm[i] && args->pgm[i] != '/'; i++)
                ;

        /* Store program name in command buffer. */
        vary4append(&cmd, "/QSYS.LIB/");
        vary4nappend(&cmd, args->pgm, i);
        vary4append(&cmd, ".LIB/XMLCATALOG.PGM");

        /* Map command arguments to standard xmlcatalog argument vector. */
        if (args->kind && args->kind->len)
                vary4varg(&cmd, args->kind);

        if (args->verbose && args->verbose->len)
                vary4varg(&cmd, args->verbose);

        if (args->delete)
                for (i = 0; i < args->delete->len; i++) {
                        vary4arg(&cmd, "--del");
                        vary4vargquote(&cmd, &args->delete->item[i].param);
                        }

        if (args->kind && args->kind->len) {
                /* Process SGML-specific parameters. */
                if (args->superupd && args->superupd->len)
                        vary4varg(&cmd, args->superupd);

                if (args->sgmladd)
                        for (i = 0; i < args->sgmladd->len; i++) {
                                saelp = OFFSETBY(sgmladdelement, args->sgmladd,
                                                args->sgmladd->item[i].param);
                                if (!((vary2 *) &saelp->catalog)->len)
                                        continue;
                                vary4arg(&cmd, "--add");
                                vary4vargquote(&cmd, (vary2 *) &saelp->catalog);
                                vary4vargquote(&cmd, (vary2 *) &saelp->ident);
                                }
                }
        else {
                /* Process XML-specific parameters. */
                if (args->convert && args->convert->len)
                        vary4varg(&cmd, args->convert);

                if (args->add)
                        for (i = 0; i < args->add->len; i++) {
                                aelp = OFFSETBY(addelement, args->add,
                                                args->add->item[i].param);
                                if (!((vary2 *) &aelp->origin)->len)
                                        continue;
                                vary4arg(&cmd, "--add");
                                vary4varg(&cmd, (vary2 *) &aelp->type);
                                vary4vargquote(&cmd, (vary2 *) &aelp->origin);
                                vary4vargquote(&cmd, (vary2 *) &aelp->replace);
                                }
                }

        /* Avoid INSTMF(*NEW) and OUTSMTF(*INSTMF). */
        if (args->outstmf && args->outstmf->len && !args->outstmf->string[0])
                if (args->instmf && args->instmf->len)
                        args->outstmf = args->instmf;
                else
                        args->outstmf = NULL;

        /* If INSTMF(*NEW) and OUTSTMF(somepath), Use --create --noout and
           somepath as (unexisting) input file. */
        if (args->outstmf && args->outstmf->len)
                if (!args->instmf || !args->instmf->len) {
                        vary4arg(&cmd, "--create");
                        vary4arg(&cmd, "--noout");
                        args->instmf = args->outstmf;
                        args->outstmf = NULL;
                        }

        /* If output to input file, use --noout option. */
        if (args->instmf && args->outstmf && args->instmf->len &&
            args->instmf->len == args->outstmf->len &&
            !strncmp(args->instmf->string, args->outstmf->string,
                     args->instmf->len)) {
                vary4arg(&cmd, "--noout");
                args->outstmf = NULL;
                }

        /* If no input file create catalog, else specify the input file name. */
        /* Specify the input file name: my be a dummy one. */
        if (!args->instmf || !args->instmf->len) {
                vary4arg(&cmd, "--create -");
                vary4arg(&cmd, ".dmyxmlcatalog");
                }
        else {
                vary4arg(&cmd, "-");
                vary4vargquote(&cmd, args->instmf);
                }

        /* Query entities. */

        if (args->resolve)
                for (i = 0; i < args->resolve->len; i++)
                        vary4vargquote(&cmd, &args->resolve->item[i].param);

        /* Redirect output if requested. */
        if (args->outstmf && args->outstmf->len) {
                vary4arg(&cmd, ">");
                vary4vargquote(&cmd, args->outstmf);
                }

        /* Execute the shell command. */
        qshell(&cmd);

        /* Terminate. */
        exit(0);
}
