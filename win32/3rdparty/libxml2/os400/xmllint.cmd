/*      XMLLINT CL command.                                                   */
/*                                                                            */
/*      See Copyright for the status of this software.                        */
/*                                                                            */
/*      Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.          */

/*      Interface to program XMLLINTCL                                        */

             CMD        PROMPT('XML tool')

             /* XML input file location. */

             PARM       KWD(STMF) TYPE(*PNAME) LEN(5000) VARY(*YES *INT2)      +
                          CASE(*MIXED) EXPR(*YES) MIN(1)                       +
                          CHOICE('Stream file path')                           +
                          PROMPT('XML Stream file')

             /* DTD location. */

             PARM       KWD(DTD) TYPE(*PNAME) LEN(5000) VARY(*YES *INT2)       +
                          CASE(*MIXED) EXPR(*YES) PASSVAL(*NULL)               +
                          CHOICE('ID, URL or stream file path')                +
                          PROMPT('DTD id, URL or file path')

             PARM       KWD(DTDLOCATOR) TYPE(*CHAR) LEN(8) DFT(*DTDURL)        +
                          SPCVAL(*DTDURL *DTDFPI) EXPR(*YES) RSTD(*YES)        +
                          PROMPT('DTD locator is URL/FPI')

             /* Schema location. */

             PARM       KWD(SCHEMA) TYPE(*PNAME) LEN(5000) VARY(*YES *INT2)    +
                          CASE(*MIXED) EXPR(*YES) PASSVAL(*NULL)               +
                          CHOICE('URL or stream file path')                    +
                          PROMPT('Schema URL or stream file path')

             PARM       KWD(SCHEMAKIND) TYPE(*CHAR) LEN(12) VARY(*YES *INT2)   +
                          RSTD(*YES) DFT(*XSD)                                 +
                          PROMPT('Validating schema kind')                     +
                          CHOICE('Keyword') SPCVAL(                            +
                            (*XSD               '--schema')                    +
                            (*RELAXNG           '--relaxng')                   +
                            (*SCHEMATRON        '--schematron')                +
                          )

             /* Output location. */

             PARM       KWD(OUTSTMF) TYPE(*PNAME) LEN(5000) VARY(*YES *INT2)   +
                          CASE(*MIXED) EXPR(*YES) PASSVAL(*NULL)               +
                          CHOICE('Stream file path')                           +
                          PROMPT('Output stream file path')

             /* Other parameters with arguments. */

             PARM       KWD(XPATH) TYPE(*CHAR) LEN(5000) VARY(*YES *INT2)      +
                          CASE(*MIXED) EXPR(*YES) PASSVAL(*NULL)               +
                          CHOICE('XPath expression')                           +
                          PROMPT('XPath filter')

             PARM       KWD(PATTERN) TYPE(*CHAR) LEN(5000) VARY(*YES *INT2)    +
                          CASE(*MIXED) EXPR(*YES) PASSVAL(*NULL)               +
                          CHOICE('Reader pattern')                             +
                          PROMPT('Reader node filter')

             /* Paths for resources. */

             PARM       KWD(PATH) TYPE(*PNAME) LEN(5000) VARY(*YES *INT2)      +
                          CASE(*MIXED) EXPR(*YES) MAX(64)                      +
                          CHOICE('IFS directory path')                         +
                          PROMPT('Path for resources')

             PARM       KWD(PRETTY) TYPE(*CHAR) LEN(11) VARY(*YES *INT2)       +
                          RSTD(*YES) DFT(*NONE)                                +
                          PROMPT('Pretty-print style')                         +
                          CHOICE('Keyword') SPCVAL(                            +
                            (*NONE              '0')                           +
                            (*FORMAT            '1')                           +
                            (*WHITESPACE        '2')                           +
                          )

             PARM       KWD(MAXMEM) TYPE(*UINT4) EXPR(*YES) DFT(0)             +
                          CHOICE('Number of bytes')                            +
                          PROMPT('Maximum dynamic memory')

             PARM       KWD(ENCODING) TYPE(*CHAR) LEN(32) VARY(*YES *INT2)     +
                          CASE(*MIXED) EXPR(*YES) PASSVAL(*NULL)               +
                          PMTCTL(ENCODING) CHOICE('Encoding name')             +
                          PROMPT('Output character encoding')
ENCODING:    PMTCTL     CTL(OUTSTMF) COND(*SPCFD)

             /* Boolean options. */
             /* --shell is not supported from command mode. */

             PARM       KWD(OPTIONS) TYPE(*CHAR) LEN(20) VARY(*YES *INT2)      +
                          MAX(50) RSTD(*YES) PROMPT('Options')                 +
                          CHOICE('Keyword') SPCVAL(                            +
                            (*VERSION         '--version')                     +
                            (*DEBUG           '--debug')                       +
                            (*DEBUGENT        '--debugent')                    +
                            (*COPY            '--copy')                        +
                            (*RECOVER         '--recover')                     +
                            (*HUGE            '--huge')                        +
                            (*NOENT           '--noent')                       +
                            (*NOENC           '--noenc')                       +
                            (*NOOUT           '--noout')                       +
                            (*LOADTRACE       '--load-trace')                  +
                            (*NONET           '--nonet')                       +
                            (*NOCOMPACT       '--nocompact')                   +
                            (*HTMLOUT         '--htmlout')                     +
                            (*NOWRAP          '--nowrap')                      +
                            (*VALID           '--valid')                       +
                            (*POSTVALID       '--postvalid')                   +
                            (*TIMING          '--timing')                      +
                            (*REPEAT          '--repeat')                      +
                            (*INSERT          '--insert')                      +
                            (*COMPRESS        '--compress')                    +
                            (*HTML            '--html')                        +
                            (*XMLOUT          '--xmlout')                      +
                            (*NODEFDTD        '--nodefdtd')                    +
                            (*PUSH            '--push')                        +
                            (*PUSHSMALL       '--pushsmall')                   +
                            (*MEMORY          '--memory')                      +
                            (*NOWARNING       '--nowarning')                   +
                            (*NOBLANKS        '--noblanks')                    +
                            (*NOCDATA         '--nocdata')                     +
                            (*FORMAT          '--format')                      +
                            (*DROPDTD         '--dropdtd')                     +
                            (*NSCLEAN         '--nsclean')                     +
                            (*TESTIO          '--testIO')                      +
                            (*CATALOGS        '--catalogs')                    +
                            (*NOCATALOGS      '--nocatalogs')                  +
                            (*AUTO            '--auto')                        +
                            (*XINCLUDE        '--xinclude')                    +
                            (*NOXINCLUDENODE  '--noxincludenode')              +
                            (*NOFIXUPBASEURIS '--nofixup-base-uris')           +
                            (*LOADDTD         '--loaddtd')                     +
                            (*DTDATTR         '--dtdattr')                     +
                            (*STREAM          '--stream')                      +
                            (*WALKER          '--walker')                      +
                            (*CHKREGISTER     '--chkregister')                 +
                            (*C14N            '--c14n')                        +
                            (*C14N11          '--c14n11')                      +
                            (*EXCC14N         '--exc-c14n')                    +
                            (*SAX1            '--sax1')                        +
                            (*SAX             '--sax')                         +
                            (*OLDXML10        '--oldxml10')                    +
                          )
