/**
***     QADRT/QADRTMAIN2 substitution program.
***     This is needed because the IBM-provided QADRTMAIN2 does not
***     properly translate arguments by default or if no locale is provided.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <errno.h>
#include <locale.h>

/* Do not use qadrt.h since it defines unneeded static procedures. */
extern void     QadrtInit(void);
extern int      QadrtFreeConversionTable(void);
extern int      QadrtFreeEnviron(void);
extern char *   setlocale_a(int, const char *);


/* The ASCII main program. */
extern int      main_a(int argc, char * * argv);

/* Global values of original EBCDIC arguments. */
int             ebcdic_argc;
char * *        ebcdic_argv;


int
main(int argc, char * * argv)

{
        int i;
        int j;
        iconv_t cd;
        size_t bytecount = 0;
        char * inbuf;
        char * outbuf;
        size_t inbytesleft;
        size_t outbytesleft;
        char dummybuf[128];
        char tocode[32];
        char fromcode[32];

        ebcdic_argc = argc;
        ebcdic_argv = argv;

        /* Build the encoding converter. */
        strncpy(tocode, "IBMCCSID01208", sizeof tocode);
        strncpy(fromcode, "IBMCCSID000000000010", sizeof fromcode);
        cd = iconv_open(tocode, fromcode);

        /* Measure the arguments. */
        for (i = 0; i < argc; i++) {
                inbuf = argv[i];
                do {
                        inbytesleft = 0;
                        outbuf = dummybuf;
                        outbytesleft = sizeof dummybuf;
                        j = iconv(cd,
                                  &inbuf, &inbytesleft, &outbuf, &outbytesleft);
                        bytecount += outbuf - dummybuf;
                } while (j == -1 && errno == E2BIG);
                /* Reset the shift state. */
                iconv(cd, NULL, &inbytesleft, &outbuf, &outbytesleft);
                }

        /* Allocate memory for the ASCII arguments and vector. */
        argv = (char * *) malloc((argc + 1) * sizeof *argv + bytecount);

        /* Build the vector and convert argument encoding. */
        outbuf = (char *) (argv + argc + 1);
        outbytesleft = bytecount;

        for (i = 0; i < argc; i++) {
                argv[i] = outbuf;
                inbuf = ebcdic_argv[i];
                inbytesleft = 0;
                iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
                iconv(cd, NULL, &inbytesleft, &outbuf, &outbytesleft);
                }

        iconv_close(cd);
        argv[argc] = NULL;

        /* Try setting the locale regardless of QADRT_ENV_LOCALE. */
        setlocale_a(LC_ALL, "");

        /* Call the program. */
        i = main_a(argc, argv);

        /* Clean-up allocated items. */
        free((char *) argv);
        QadrtFreeConversionTable();
        QadrtFreeEnviron();

        /* Terminate. */
        return i;
}
