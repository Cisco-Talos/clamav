/*      XMLCATALOG CL command.                                                */
/*                                                                            */
/*      See Copyright for the status of this software.                        */
/*                                                                            */
/*      Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.          */

/*      Interface to program XMLCATLGCL                                       */

             CMD        PROMPT('XML/SGML catalog  tool')

             /* Catalog file path. */

             PARM       KWD(INSTMF) TYPE(*PNAME) LEN(5000) VARY(*YES *INT2)    +
                          CASE(*MIXED) EXPR(*YES) MIN(1) SPCVAL((*NEW ''))     +
                          CHOICE('Stream file path')                           +
                          PROMPT('XML/SGML catalog file')

             /* Catalog kind: XML/SGML. */

             PARM       KWD(KIND) TYPE(*CHAR) LEN(7) VARY(*YES *INT2)          +
                          EXPR(*YES) RSTD(*YES) DFT(*XML)                      +
                          SPCVAL((*XML '') (*SGML '--sgml'))                   +
                          PROMPT('Catalog kind')

             /* Output file. */

             PARM       KWD(OUTSTMF) TYPE(*PNAME) LEN(5000) VARY(*YES *INT2)   +
                          CASE(*MIXED) EXPR(*YES) DFT(*STDOUT)                 +
                          SPCVAL((*STDOUT '') (*INSTMF X'00'))                 +
                          CHOICE('*STDOUT, *INSTMF or file path')              +
                          PROMPT('Output stream file path')

             /* Convert SGML to XML catalog. */

             PARM       KWD(CONVERT) TYPE(*CHAR) LEN(10) VARY(*YES *INT2)      +
                          RSTD(*YES) SPCVAL((*YES '--convert') (*NO ''))       +
                          EXPR(*YES) DFT(*NO) PMTCTL(TYPEXML)                  +
                          PROMPT('Convert SGML to XML catalog')

             /* SGML super catalog update. */

             PARM       KWD(SUPERUPD) TYPE(*CHAR) LEN(17) VARY(*YES *INT2)     +
                          SPCVAL((*YES '') (*NO '--no-super-update'))          +
                          EXPR(*YES) DFT(*YES) RSTD(*YES) PMTCTL(TYPESGML)     +
                          PROMPT('Update the SGML super catalog')

             /* Verbose/debug output. */

             PARM       KWD(VERBOSE) TYPE(*CHAR) LEN(4) VARY(*YES *INT2)       +
                          RSTD(*YES) SPCVAL((*YES '-v') (*NO ''))              +
                          EXPR(*YES) DFT(*NO)                                  +
                          PROMPT('Output debugging information')

             /* Interactive shell not supported. */

             /* Values to delete. */

             PARM       KWD(DELETE) TYPE(*PNAME) LEN(256) VARY(*YES *INT2)     +
                          CASE(*MIXED) MAX(64) EXPR(*YES)                      +
                          CHOICE('Identifier value')                           +
                          PROMPT('Delete System/URI identifier')

             /* Values to add. */

             PARM       KWD(ADD) TYPE(XMLELEM) MAX(10) PMTCTL(TYPEXML)         +
                          PROMPT('Add definition')
XMLELEM:     ELEM       TYPE(*CHAR) LEN(16) VARY(*YES *INT2) DFT(*PUBLIC)      +
                          PROMPT('Entry type')                                 +
                          EXPR(*YES) RSTD(*YES) SPCVAL(                        +
                            (*PUBLIC         'public')                         +
                            (*SYSTEM         'system')                         +
                            (*URI            'uri')                            +
                            (*REWRITESYSTEM  'rewriteSystem')                  +
                            (*REWRITEURI     'rewriteURI')                     +
                            (*DELEGATEPUBLIC 'delegatePublic')                 +
                            (*DELEGATESYSTEM 'delegateSystem')                 +
                            (*DELEGATEURI    'delegateURI')                    +
                            (*NEXTCATALOG    'nextCatalog')                    +
                          )
             ELEM       TYPE(*PNAME) LEN(256) VARY(*YES *INT2) EXPR(*YES)      +
                          CASE(*MIXED) PROMPT('Original reference/file name')
             ELEM       TYPE(*PNAME) LEN(256) VARY(*YES *INT2) EXPR(*YES)      +
                          CASE(*MIXED) PROMPT('Replacement entity URI')

             PARM       KWD(SGMLADD) TYPE(SGMLELEM) MAX(10)                    +
                          PMTCTL(TYPESGML) PROMPT('Add SGML definition')
SGMLELEM:    ELEM       TYPE(*PNAME) LEN(256) VARY(*YES *INT2) EXPR(*YES)      +
                          CASE(*MIXED) PROMPT('SGML catalog file name')
             ELEM       TYPE(*PNAME) LEN(256) VARY(*YES *INT2) EXPR(*YES)      +
                          CASE(*MIXED) PROMPT('SGML definition')

             /* Entities to resolve. */

             PARM       KWD(ENTITY) TYPE(*PNAME) LEN(256) VARY(*YES *INT2)     +
                          CASE(*MIXED) EXPR(*YES) MAX(150)                     +
                          PROMPT('Resolve entity')

             /* Additional catalog files. */

             PARM       KWD(CATALOG) TYPE(*PNAME) LEN(5000) VARY(*YES *INT2)   +
                          CASE(*MIXED) EXPR(*YES) MAX(150) DFT(*DEFAULT)       +
                          CHOICE('Catalog stream file path')                   +
                          PROMPT('Additional catalog file') SPCVAL(            +
                            (*DEFAULT       '/etc/xml/catalog')                +
                            (*NONE          '')                                +
                          )


             /* Conditional prompting. */

TYPEXML:     PMTCTL     CTL(KIND) COND((*EQ ''))
TYPESGML:    PMTCTL     CTL(KIND) COND((*NE ''))
