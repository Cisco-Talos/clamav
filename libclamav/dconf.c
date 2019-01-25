/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <zlib.h>

#include "clamav.h"
#include "dconf.h"
#include "readdb.h"
#include "str.h"
#include "others.h"

#include "mpool.h"

struct dconf_module {
    const char  *mname;     /* module name */
    const char  *sname;     /* submodule name */
    uint32_t    bflag;      /* bit flag */
    uint8_t state;      /* default state (on/off) */
};

#ifdef CL_EXPERIMENTAL
#define DCONF_ENABLE_EXPERIMENTAL 1
#else
#define DCONF_ENABLE_EXPERIMENTAL 0
#endif

static struct dconf_module modules[] = {

    { "PE",     "PARITE",       PE_CONF_PARITE,     1 },
    { "PE",     "KRIZ",     PE_CONF_KRIZ,       1 },
    { "PE",     "MAGISTR",      PE_CONF_MAGISTR,        1 },
    { "PE",     "POLIPOS",      PE_CONF_POLIPOS,        1 },
    { "PE",     "MD5SECT",      PE_CONF_MD5SECT,        1 },
    { "PE",     "UPX",      PE_CONF_UPX,        1 },
    { "PE",     "FSG",      PE_CONF_FSG,        1 },
    { "PE",     "SWIZZOR",      PE_CONF_SWIZZOR,        0 },

    { "PE",     "PETITE",       PE_CONF_PETITE,     1 },
    { "PE",     "PESPIN",       PE_CONF_PESPIN,     1 },
    { "PE",     "YC",       PE_CONF_YC,         1 },
    { "PE",     "WWPACK",       PE_CONF_WWPACK,     1 },

    { "PE",     "NSPACK",       PE_CONF_NSPACK,     1 },
    { "PE",     "MEW",      PE_CONF_MEW,        1 },
    { "PE",     "UPACK",        PE_CONF_UPACK,      1 },
    { "PE",     "ASPACK",       PE_CONF_ASPACK,     1 },
    { "PE",     "CATALOG",      PE_CONF_CATALOG,        1 },
    { "PE",     "CERTS",        PE_CONF_CERTS,      1 },
    { "PE",     "MATCHICON",    PE_CONF_MATCHICON,       1 },
    { "PE",     "IMPTBL",       PE_CONF_IMPTBL,          1 },

    { "ELF",        NULL,       0x1,            1 },

    { "MACHO",      NULL,       0x1,            1 },

    { "ARCHIVE",    "RAR",      ARCH_CONF_RAR,      1 },
    { "ARCHIVE",    "ZIP",      ARCH_CONF_ZIP,      1 },
    { "ARCHIVE",    "GZIP",     ARCH_CONF_GZ,       1 },
    { "ARCHIVE",    "BZIP",     ARCH_CONF_BZ,       1 },
    { "ARCHIVE",    "ARJ",          ARCH_CONF_ARJ,      1 },
    { "ARCHIVE",    "SZDD",     ARCH_CONF_SZDD,     1 },
    { "ARCHIVE",    "CAB",      ARCH_CONF_CAB,      1 },
    { "ARCHIVE",    "CHM",      ARCH_CONF_CHM,      1 },
    { "ARCHIVE",    "OLE2",     ARCH_CONF_OLE2,     1 },
    { "ARCHIVE",    "TAR",      ARCH_CONF_TAR,      1 },
    { "ARCHIVE",    "CPIO",     ARCH_CONF_CPIO,     1 },
    { "ARCHIVE",    "BINHEX",       ARCH_CONF_BINHEX,       1 },
    { "ARCHIVE",    "SIS",      ARCH_CONF_SIS,      1 },
    { "ARCHIVE",    "NSIS",     ARCH_CONF_NSIS,     1 },
    { "ARCHIVE",    "AUTOIT",       ARCH_CONF_AUTOIT,       1 },
    { "ARCHIVE",    "ISHIELD",      ARCH_CONF_ISHIELD,      1 },
    { "ARCHIVE",    "7zip",     ARCH_CONF_7Z,       1 },
    { "ARCHIVE",    "ISO9660",      ARCH_CONF_ISO9660,      1 },
    { "ARCHIVE",    "DMG",      ARCH_CONF_DMG,      1 },
    { "ARCHIVE",    "XAR",      ARCH_CONF_XAR,      1 },
    { "ARCHIVE",    "HFSPLUS",      ARCH_CONF_HFSPLUS,      1 },
    { "ARCHIVE",    "XZ",       ARCH_CONF_XZ,       1 },
    { "ARCHIVE",    "PASSWD",   ARCH_CONF_PASSWD,   1 },
    { "ARCHIVE",    "MBR",      ARCH_CONF_MBR,      1 },
    { "ARCHIVE",    "GPT",      ARCH_CONF_GPT,      1 },
    { "ARCHIVE",    "APM",      ARCH_CONF_APM,      1 },

    { "DOCUMENT",   "HTML",     DOC_CONF_HTML,      1 },
    { "DOCUMENT",   "RTF",      DOC_CONF_RTF,       1 },
    { "DOCUMENT",   "PDF",      DOC_CONF_PDF,       1 },
    { "DOCUMENT",   "SCRIPT",       DOC_CONF_SCRIPT,        1 },
    { "DOCUMENT",   "HTMLSKIPRAW",  DOC_CONF_HTML_SKIPRAW,  1 },
    { "DOCUMENT",   "JSNORM",       DOC_CONF_JSNORM,        1 },
    { "DOCUMENT",   "SWF",      DOC_CONF_SWF,       1 },
    { "DOCUMENT",   "OOXML",    DOC_CONF_OOXML,     1 },
    { "DOCUMENT",   "MSPML",    DOC_CONF_MSXML,     1 },
    { "DOCUMENT",   "HWP",      DOC_CONF_HWP,       1 },

    { "MAIL",       "MBOX",     MAIL_CONF_MBOX,     1 },
    { "MAIL",       "TNEF",     MAIL_CONF_TNEF,     1 },

    { "OTHER",      "UUENCODED",    OTHER_CONF_UUENC,       1 },
    { "OTHER",      "SCRENC",       OTHER_CONF_SCRENC,      1 },
    { "OTHER",      "RIFF",     OTHER_CONF_RIFF,        1 },
    { "OTHER",      "JPEG",     OTHER_CONF_JPEG,        1 },
    { "OTHER",      "CRYPTFF",      OTHER_CONF_CRYPTFF,     1 },
    { "OTHER",      "DLP",      OTHER_CONF_DLP,     1 },
    { "OTHER",      "MYDOOMLOG",    OTHER_CONF_MYDOOMLOG,   1 },
    { "OTHER",      "PREFILTERING", OTHER_CONF_PREFILTERING,1 },
    { "OTHER",      "PDFNAMEOBJ",   OTHER_CONF_PDFNAMEOBJ,  1 },
    { "OTHER",      "PRTNINTXN",   OTHER_CONF_PRTNINTXN,  1 },
    { "OTHER",      "LZW",      OTHER_CONF_LZW,     1 },

    { "PHISHING",   "ENGINE",       PHISHING_CONF_ENGINE,   1 },
    { "PHISHING",   "ENTCONV",      PHISHING_CONF_ENTCONV,  1 },

    { "BYTECODE",   "INTERPRETER",  BYTECODE_INTERPRETER,   1 },
    { "BYTECODE",   "JIT X86",      BYTECODE_JIT_X86,       1 },
    { "BYTECODE",   "JIT PPC",      BYTECODE_JIT_PPC,       1 },
    { "BYTECODE",   "JIT ARM",      BYTECODE_JIT_ARM,       0 },

    { "STATS",      "DISABLED",     DCONF_STATS_DISABLED,   0 },
    { "STATS",      "PESECTION DISABLED", DCONF_STATS_PE_SECTION_DISABLED, 0 },

    { "PCRE",       "SUPPORT",      PCRE_CONF_SUPPORT,   1 },
    { "PCRE",       "OPTIONS",      PCRE_CONF_OPTIONS,   1 },
    { "PCRE",       "GLOBAL",       PCRE_CONF_GLOBAL,    1 },

    { NULL,     NULL,       0,              0 }
};

#ifdef USE_MPOOL 
struct cli_dconf *cli_dconf_init(mpool_t *mempool)
#else
struct cli_dconf *cli_dconf_init(void)
#endif
{
    unsigned int i;
    struct cli_dconf *dconf;

    dconf = (struct cli_dconf *) mpool_calloc(mempool, sizeof(struct cli_dconf), 1);
    if(!dconf)
        return NULL;

    for(i = 0; modules[i].mname; i++) {
        if(!strcmp(modules[i].mname, "PE")) {
            if(modules[i].state)
                dconf->pe |= modules[i].bflag;

        } else if(!strcmp(modules[i].mname, "ELF")) {
            if(modules[i].state)
                dconf->elf |= modules[i].bflag;

        } else if(!strcmp(modules[i].mname, "MACHO")) {
            if(modules[i].state)
                dconf->macho |= modules[i].bflag;

        } else if(!strcmp(modules[i].mname, "ARCHIVE")) {
            if(modules[i].state)
                dconf->archive |= modules[i].bflag;

        } else if(!strcmp(modules[i].mname, "DOCUMENT")) {
            if(modules[i].state)
                dconf->doc |= modules[i].bflag;

        } else if(!strcmp(modules[i].mname, "MAIL")) {
            if(modules[i].state)
                dconf->mail |= modules[i].bflag;

        } else if(!strcmp(modules[i].mname, "OTHER")) {
            if(modules[i].state)
                dconf->other |= modules[i].bflag;
        } else if(!strcmp(modules[i].mname, "PHISHING")) {
            if(modules[i].state)
                dconf->phishing |= modules[i].bflag;
        } else if(!strcmp(modules[i].mname, "BYTECODE")) {
            if (modules[i].state)
                dconf->bytecode |= modules[i].bflag;
        } else if (!strcmp(modules[i].mname, "STATS")) {
            if (modules[i].state)
                dconf->stats |= modules[i].bflag;
        } else if (!strcmp(modules[i].mname, "PCRE")) {
            if (modules[i].state)
                dconf->pcre |= modules[i].bflag;
        }
    }

    return dconf;
}

void cli_dconf_print(struct cli_dconf *dconf)
{
    unsigned int pe = 0, elf = 0, macho = 0, arch = 0, doc = 0, mail = 0;
    unsigned int other = 0, phishing = 0, i, bytecode=0, stats=0, pcre=0;


    cli_dbgmsg("Dynamic engine configuration settings:\n");
    cli_dbgmsg("--------------------------------------\n");

    for(i = 0; modules[i].mname; i++) {
        if(!strcmp(modules[i].mname, "PE")) {
            if(!pe) {
                cli_dbgmsg("Module PE: %s\n", dconf->pe ? "On" : "Off");
                pe = 1;
            }

            if(dconf->pe)
                cli_dbgmsg("   * Submodule %10s:\t%s\n", modules[i].sname, (dconf->pe & modules[i].bflag) ? "On" : "** Off **");
            else
                continue;
        } else if(!strcmp(modules[i].mname, "ELF")) {
            if(!elf) {
                cli_dbgmsg("Module ELF: %s\n", dconf->elf ? "On" : "Off");
                elf = 1;
            }
        } else if(!strcmp(modules[i].mname, "MACHO")) {
            if(!macho) {
                cli_dbgmsg("Module MACHO: %s\n", dconf->elf ? "On" : "Off");
                macho = 1;
            }
        } else if(!strcmp(modules[i].mname, "ARCHIVE")) {
            if(!arch) {
                cli_dbgmsg("Module ARCHIVE: %s\n", dconf->archive ? "On" : "Off");
                arch = 1;
            }

            if(dconf->archive)
                cli_dbgmsg("   * Submodule %10s:\t%s\n", modules[i].sname, (dconf->archive & modules[i].bflag) ? "On" : "** Off **");
            else
                continue;
        } else if(!strcmp(modules[i].mname, "DOCUMENT")) {
            if(!doc) {
                cli_dbgmsg("Module DOCUMENT: %s\n", dconf->doc ? "On" : "Off");
                doc = 1;
            }

            if(dconf->doc)
                cli_dbgmsg("   * Submodule %10s:\t%s\n", modules[i].sname, (dconf->doc & modules[i].bflag) ? "On" : "** Off **");
            else
                continue;
        } else if(!strcmp(modules[i].mname, "MAIL")) {
            if(!mail) {
                cli_dbgmsg("Module MAIL: %s\n", dconf->mail ? "On" : "Off");
                mail = 1;
            }

            if(dconf->mail)
                cli_dbgmsg("   * Submodule %10s:\t%s\n", modules[i].sname, (dconf->mail & modules[i].bflag) ? "On" : "** Off **");
            else
                continue;
        } else if(!strcmp(modules[i].mname, "OTHER")) {
            if(!other) {
                cli_dbgmsg("Module OTHER: %s\n", dconf->other ? "On" : "Off");
                other = 1;
            }

            if(dconf->other)
                cli_dbgmsg("   * Submodule %10s:\t%s\n", modules[i].sname, (dconf->other & modules[i].bflag) ? "On" : "** Off **");
            else
                continue;
        } else if(!strcmp(modules[i].mname, "PHISHING")) {
            if(!phishing) {
                cli_dbgmsg("Module PHISHING %s\n", dconf->phishing ? "On" : "Off");
                phishing = 1;
            }

            if(dconf->phishing)
                cli_dbgmsg("   * Submodule %10s:\t%s\n", modules[i].sname, (dconf->phishing & modules[i].bflag) ? "On" : "** Off **");
            else
                continue;
        } else if(!strcmp(modules[i].mname, "BYTECODE")) {
            if(!bytecode) {
                cli_dbgmsg("Module BYTECODE %s\n", dconf->bytecode ? "On" : "Off");
                bytecode = 1;
            }

            if(dconf->bytecode)
                cli_dbgmsg("   * Submodule %10s:\t%s\n", modules[i].sname, (dconf->bytecode & modules[i].bflag) ? "On" : "** Off **");
            else
                continue;
        } else if (!strcmp(modules[i].mname, "STATS")) {
            if (!stats) {
                cli_dbgmsg("Module STATS %s\n", dconf->stats ? "On" : "Off");
                stats = 1;
            }

            if (dconf->stats)
                cli_dbgmsg("   * Submodule %10s:\t%s\n", modules[i].sname, (dconf->stats & modules[i].bflag) ? "On" : "** Off **");
            else
                continue;
        } else if (!strcmp(modules[i].mname, "PCRE")) {
#if HAVE_PCRE
            if (!pcre) {
                cli_dbgmsg("Module PCRE %s\n", dconf->pcre ? "On" : "Off");
                pcre = 1;
            }

            if (dconf->pcre)
                cli_dbgmsg("   * Submodule %10s:\t%s\n", modules[i].sname, (dconf->pcre & modules[i].bflag) ? "On" : "** Off **");
            else
                continue;
#else
            if (!pcre) {
                cli_dbgmsg("Module PCRE Off\n");
                pcre = 1;
            }

            continue;
#endif
        }
    }
}

static int chkflevel(const char *entry, int field)
{
    char *pt;


    if((pt = cli_strtok(entry, field, ":"))) { /* min version */
        if(!isdigit(*pt)) {
            free(pt);
            return 0;
        }

        if((unsigned int) atoi(pt) > CL_FLEVEL_DCONF) {
            free(pt);
            return 0;
        }

        free(pt);

        if((pt = cli_strtok(entry, field + 1, ":"))) { /* max version */
            if(!isdigit(*pt)) {
                free(pt);
                return 0;
            }

            if((unsigned int) atoi(pt) < CL_FLEVEL_DCONF) {
                free(pt);
                return 0;
            }

            free(pt);
        }
    }

    return 1;
}

int cli_dconf_load(FILE *fs, struct cl_engine *engine, unsigned int options, struct cli_dbio *dbio)
{
    char buffer[FILEBUFF];
    unsigned int line = 0;
    int ret = 0;
    uint32_t val;

    UNUSEDPARAM(options);

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
        line++;
        cli_chomp(buffer);

        if(!strncmp(buffer, "PE:", 3) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 3, "0x%x", &val) == 1) {
                engine->dconf->pe = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "ELF:", 4) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 4, "0x%x", &val) == 1) {
                engine->dconf->elf = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "MACHO:", 6) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 6, "0x%x", &val) == 1) {
                engine->dconf->macho = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "ARCHIVE:", 8) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 8, "0x%x", &val) == 1) {
                engine->dconf->archive = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "DOCUMENT:", 9) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 9, "0x%x", &val) == 1) {
                engine->dconf->doc = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "MAIL:", 5) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 5, "0x%x", &val) == 1) {
                engine->dconf->mail = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "OTHER:", 6) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 6, "0x%x", &val) == 1) {
                engine->dconf->other = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "PHISHING:", 9) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 9, "0x%x", &val) == 1) {
                engine->dconf->phishing = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "BYTECODE:", 9) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 9, "0x%x", &val) == 1) {
                engine->dconf->bytecode = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "STATS:", 6) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 6, "0x%x", &val) == 1) {
                engine->dconf->stats = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }

        if(!strncmp(buffer, "PCRE:", 5) && chkflevel(buffer, 2)) {
            if(sscanf(buffer + 5, "0x%x", &val) == 1) {
                engine->dconf->pcre = val;
            } else {
                ret = CL_EMALFDB;
                break;
            }
        }
    }

    if(ret) {
        cli_errmsg("Problem parsing configuration file at line %u\n", line);
        return ret;
    }

    return CL_SUCCESS;
}
