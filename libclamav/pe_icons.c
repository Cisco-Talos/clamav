/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#include <string.h>
#include <math.h>

#include "clamav.h"
#include "pe_icons.h"
#include "others.h"

#define READ32(x) cli_readint32(&(x))
#define READ16(x) cli_readint16(&(x))

#define USE_FLOATS
#ifdef USE_FLOATS
#  define LABDIFF(x) labdiff(x)
#else
#  define LABDIFF(x) labdiff2(x)
#endif

/* #define LOGPARSEICONDETAILS */

struct ICON_ENV {
    cli_ctx *ctx;
    unsigned int gcnt, hcnt; /* gcnt -> number of icon groups parsed, hcnt -> "actual" image count */
    uint32_t lastg;
    int result;

    icon_groupset *set;
    uint32_t resdir_rva;
    struct cli_exe_section *exe_sections;
    uint16_t nsections;
    uint32_t hdr_size;

    uint32_t icnt; /* number of icon entries parsed, declared images */
    uint32_t max_icons;

    uint32_t err_oof;   /* parseicon: offset to icon is out of file */
    uint32_t err_bhoof; /* parseicon: bmp header is out of file */
    uint32_t err_bhts;  /* parseicon: BMP header too small */
    uint32_t err_tstl;  /* parseicon: Image too small or too big */
    uint32_t err_insl;  /* parseicon: Image not square enough */
};

int cli_groupiconscan(struct ICON_ENV *icon_env, uint32_t rva);

static int groupicon_scan_cb(void *ptr, uint32_t type, uint32_t name, uint32_t lang, uint32_t rva) {
    struct ICON_ENV *icon_env = ptr;
    int ret = CL_CLEAN;

    UNUSEDPARAM(type);
    UNUSEDPARAM(lang);

    cli_dbgmsg("groupicon_cb: scanning group %x\n", name);
    if(!icon_env->gcnt || icon_env->lastg == name) {
        icon_env->gcnt++;
        icon_env->lastg = name;

        /* scan icon group */
        ret = cli_groupiconscan(icon_env, rva);
        if (ret != CL_CLEAN)
            return 1;

        return 0;
    }

    return 1;
}

static int parseicon(struct ICON_ENV *icon_env, uint32_t rva);

static int icon_scan_cb(void *ptr, uint32_t type, uint32_t name, uint32_t lang, uint32_t rva) {
    struct ICON_ENV *icon_env = ptr;

    UNUSEDPARAM(type);
    UNUSEDPARAM(lang);
    UNUSEDPARAM(name);

    /* scan icon */
    icon_env->result = parseicon(icon_env, rva);
    icon_env->hcnt++;

    if (icon_env->result != CL_CLEAN)
        return 1;

    return 0;
}

int cli_scanicon(icon_groupset *set, uint32_t resdir_rva, cli_ctx *ctx, struct cli_exe_section *exe_sections, uint16_t nsections, uint32_t hdr_size) {
    struct ICON_ENV icon_env;
    fmap_t *map = *ctx->fmap;
    uint32_t err_total = 0;

    icon_env.ctx = ctx;
    icon_env.gcnt = 0;
    icon_env.hcnt = 0;
    icon_env.icnt = 0;
    icon_env.lastg = 0;
    icon_env.result = CL_CLEAN;

    icon_env.set = set;
    icon_env.resdir_rva = resdir_rva;
    icon_env.exe_sections = exe_sections;
    icon_env.nsections = nsections;
    icon_env.hdr_size = hdr_size;

    icon_env.max_icons = ctx->engine->maxiconspe;

    icon_env.err_oof = 0;
    icon_env.err_bhoof = 0;
    icon_env.err_bhts = 0;
    icon_env.err_tstl = 0;
    icon_env.err_insl = 0;

    /* icon group scan callback --> groupicon_scan_cb() */
    findres(14, 0xffffffff, resdir_rva, map, exe_sections, nsections, hdr_size, groupicon_scan_cb, &icon_env);

    /* CL_EMAXSIZE is used to track the icon limit */
    if (icon_env.result == CL_EMAXSIZE)
        cli_dbgmsg("cli_scanicon: max icon count reached\n");

    cli_dbgmsg("cli_scanicon: scanned a total of %u[%u actual] icons across %u groups\n", icon_env.icnt, icon_env.hcnt, icon_env.gcnt);
    if (icon_env.hcnt < icon_env.icnt)
        cli_warnmsg("cli_scanicon: found %u invalid icon entries of %u total\n", icon_env.icnt-icon_env.hcnt, icon_env.icnt);

    err_total = icon_env.err_oof + icon_env.err_bhoof + icon_env.err_bhts + icon_env.err_tstl + icon_env.err_insl;
    if (err_total > 0) {
        cli_dbgmsg("cli_scanicon: detected %u total image parsing issues\n", err_total);
        if (icon_env.err_oof > 0)
            cli_dbgmsg("cli_scanicon: detected %u cases of 'parseicon: offset to icon is out of file'\n", icon_env.err_oof);
        if (icon_env.err_bhoof > 0)
            cli_dbgmsg("cli_scanicon: detected %u cases of 'parseicon: bmp header is out of file'\n", icon_env.err_bhoof);
        if (icon_env.err_bhts > 0)
            cli_dbgmsg("cli_scanicon: detected %u cases of 'parseicon: BMP header too small'\n", icon_env.err_bhts);
        if (icon_env.err_tstl > 0)
            cli_dbgmsg("cli_scanicon: detected %u cases of 'parseicon: Image too small or too big'\n", icon_env.err_tstl);
        if (icon_env.err_insl > 0)
            cli_dbgmsg("cli_scanicon: detected %u cases of 'parseicon: Image not square enough'\n", icon_env.err_insl);
    }

    /* ignore all error returns (previous behavior) */
    if (icon_env.result == CL_VIRUS)
        return CL_VIRUS;

    return CL_CLEAN;
}

int cli_groupiconscan(struct ICON_ENV *icon_env, uint32_t rva)
{
    /* import environment */
    uint32_t resdir_rva = icon_env->resdir_rva;
    cli_ctx *ctx = icon_env->ctx;
    struct cli_exe_section *exe_sections = icon_env->exe_sections;
    uint16_t nsections = icon_env->nsections;
    uint32_t hdr_size = icon_env->hdr_size;

    int err = 0;
    fmap_t *map = *ctx->fmap;
    const uint8_t *grp = fmap_need_off_once(map, cli_rawaddr(rva, exe_sections, nsections, (unsigned int *)(&err), map->len, hdr_size), 16);

    if(grp && !err) {
        uint32_t gsz = cli_readint32(grp + 4);
        if(gsz>6) {
            uint32_t icnt, raddr;
            unsigned int piconcnt;
            struct icondir {
                uint8_t w;
                uint8_t h;
                uint8_t palcnt;
                uint8_t rsvd;
                uint16_t planes;
                uint16_t depth;
                uint32_t sz;
                uint16_t id;
            } *dir;

            raddr = cli_rawaddr(cli_readint32(grp), exe_sections, nsections, (unsigned int *)(&err), map->len, hdr_size);
            cli_dbgmsg("cli_scanicon: icon group @%x\n", raddr);
            grp = fmap_need_off_once(map, raddr, gsz);
            if(grp && !err) {
                icnt = cli_readint32(grp+2) >> 16;

                grp += 6;
                gsz -= 6;

                while(icnt && gsz >= 14 /* && (remaining amount of icons) */) {
                    piconcnt = icon_env->hcnt;

                    dir = (struct icondir *)grp;
                    cli_dbgmsg("cli_scanicon: Icongrp @%x - %ux%ux%u - (id=%x, rsvd=%u, planes=%u, palcnt=%u, sz=%x)\n", rva, dir->w, dir->h, cli_readint16(&dir->depth), cli_readint16(&dir->id), cli_readint16(&dir->planes), dir->palcnt, dir->rsvd, cli_readint32(&dir->sz));

                    /* icon scan callback --> icon_scan_cb() */
                    findres(3, cli_readint16(&dir->id), resdir_rva, map, exe_sections, nsections, hdr_size, icon_scan_cb, icon_env);
                    if (icon_env->result != CL_CLEAN)
                        return icon_env->result;

                    if (piconcnt == icon_env->hcnt)
                        cli_dbgmsg("cli_scanicon: invalid icon entry %u in group @%x\n", dir->id, rva);

                    icon_env->icnt++;
                    icnt--;

                    if (icon_env->icnt >= icon_env->max_icons) {
                        icon_env->result = CL_EMAXSIZE;
                        return icon_env->result;
                    }

                    grp += 14;
                    gsz -= 14;
                }

                if (icnt != 0)
                    cli_dbgmsg("cli_scanicon: could not find %u icons\n", icnt);
                if (gsz != 0)
                    cli_dbgmsg("cli_scanicon: could not parse %u bytes of icon entries\n", gsz);
            }
        }
    }

    return icon_env->result;
}




/* static const int gaussk[]={1,10,45,120,210,252,210,120,45,10,1}; */
static const int gaussk[]={1,2,1};
static const int gkernsz = (sizeof(gaussk) / sizeof(gaussk[0]));

#ifndef USE_FLOATS
    static const uint32_t rtable[256][3] = {
        {0x00000000,0x00000000,0x00000000}, {0x00033475,0x0001a70c,0x00002675},
        {0x000668e9,0x00034e18,0x00004ceb}, {0x00099d5e,0x0004f525,0x00007360},
        {0x000cd1d3,0x00069c31,0x000099d6}, {0x00100648,0x0008433d,0x0000c04b},
        {0x00133abc,0x0009ea49,0x0000e6c1}, {0x00166f31,0x000b9156,0x00010d36},
        {0x0019a3a6,0x000d3862,0x000133ac}, {0x001cd81b,0x000edf6e,0x00015a21},
        {0x00200c8f,0x0010867a,0x00018097}, {0x002355ef,0x00123850,0x0001a807},
        {0x0026d1df,0x00140438,0x0001d1d7}, {0x002a7f1c,0x0015e98b,0x0001fdf5},
        {0x002e5e65,0x0017e8ad,0x00022c6d}, {0x00327076,0x001a01fd,0x00025d46},
        {0x0036b606,0x001c35dc,0x00029088}, {0x003b2fca,0x001e84a5,0x0002c63e},
        {0x003fde72,0x0020eeb3,0x0002fe6d}, {0x0044c2aa,0x00237461,0x00033920},
        {0x0049dd1d,0x00261604,0x0003765d}, {0x004f2e71,0x0028d3f3,0x0003b62d},
        {0x0054b749,0x002bae83,0x0003f898}, {0x005a7848,0x002ea606,0x00043da3},
        {0x0060720a,0x0031bace,0x00048559}, {0x0066a52c,0x0034ed2c,0x0004cfbe},
        {0x006d1247,0x00383d6e,0x00051cdb}, {0x0073b9f3,0x003babe2,0x00056cb7},
        {0x007a9cc3,0x003f38d6,0x0005bf59}, {0x0081bb4a,0x0042e494,0x000614c8},
        {0x0089161a,0x0046af67,0x00066d09}, {0x0090adbf,0x004a9998,0x0006c825},
        {0x009882c8,0x004ea371,0x00072622}, {0x00a095be,0x0052cd38,0x00078705},
        {0x00a8e72b,0x00571734,0x0007ead6}, {0x00b17796,0x005b81ab,0x0008519b},
        {0x00ba4783,0x00600ce2,0x0008bb5a}, {0x00c35778,0x0064b91c,0x0009281a},
        {0x00cca7f6,0x0069869d,0x000997e0}, {0x00d6397e,0x006e75a7,0x000a0ab2},
        {0x00e00c90,0x0073867c,0x000a8097}, {0x00ea21a8,0x0078b95d,0x000af994},
        {0x00f47945,0x007e0e8a,0x000b75af}, {0x00ff13e0,0x00838642,0x000bf4ef},
        {0x0109f1f4,0x008920c5,0x000c7758}, {0x011513f9,0x008ede4f,0x000cfcf0},
        {0x01207a66,0x0094bf20,0x000d85bd}, {0x012c25b2,0x009ac373,0x000e11c5},
        {0x01381652,0x00a0eb85,0x000ea10c}, {0x01444cb8,0x00a73792,0x000f3399},
        {0x0150c959,0x00ada7d5,0x000fc970}, {0x015d8ca4,0x00b43c89,0x00106298},
        {0x016a970c,0x00baf5e6,0x0010ff15}, {0x0177e8ff,0x00c1d428,0x00119eec},
        {0x018582ed,0x00c8d786,0x00124223}, {0x01936541,0x00d0003a,0x0012e8bf},
        {0x01a19069,0x00d74e7b,0x001392c5}, {0x01b004d1,0x00dec280,0x0014403a},
        {0x01bec2e3,0x00e65c82,0x0014f123}, {0x01cdcb08,0x00ee1cb5,0x0015a585},
        {0x01dd1dab,0x00f60351,0x00165d64}, {0x01ecbb32,0x00fe108b,0x001718c7},
        {0x01fca405,0x01064498,0x0017d7b1}, {0x020cd88a,0x010e9fad,0x00189a27},
        {0x021d5927,0x011721fe,0x0019602e}, {0x022e2641,0x011fcbc0,0x001a29cc},
        {0x023f403c,0x01289d25,0x001af703}, {0x0250a77a,0x01319661,0x001bc7da},
        {0x02625c5f,0x013ab7a8,0x001c9c55}, {0x02745f4c,0x0144012a,0x001d7478},
        {0x0286b0a2,0x014d731b,0x001e5048}, {0x029950c2,0x01570dab,0x001f2fca},
        {0x02ac400b,0x0160d10d,0x00201301}, {0x02bf7edc,0x016abd71,0x0020f9f3},
        {0x02d30d94,0x0174d308,0x0021e4a4}, {0x02e6ec90,0x017f1203,0x0022d318},
        {0x02fb1c2e,0x01897a90,0x0023c553}, {0x030f9cc9,0x01940ce0,0x0024bb5a},
        {0x03246ebe,0x019ec923,0x0025b532}, {0x03399268,0x01a9af87,0x0026b2de},
        {0x034f0822,0x01b4c03b,0x0027b462}, {0x0364d045,0x01bffb6d,0x0028b9c4},
        {0x037aeb2a,0x01cb614c,0x0029c307}, {0x0391592c,0x01d6f205,0x002ad02f},
        {0x03a81aa2,0x01e2adc6,0x002be141}, {0x03bf2fe4,0x01ee94bc,0x002cf640},
        {0x03d6994a,0x01faa715,0x002e0f30}, {0x03ee5729,0x0206e4fc,0x002f2c17},
        {0x040669d9,0x02134e9f,0x00304cf7}, {0x041ed1ae,0x021fe429,0x003171d5},
        {0x04378eff,0x022ca5c7,0x00329ab5}, {0x0450a220,0x023993a5,0x0033c79b},
        {0x046a0b65,0x0246aded,0x0034f88a}, {0x0483cb22,0x0253f4ca,0x00362d87},
        {0x049de1aa,0x02616869,0x00376695}, {0x04b84f50,0x026f08f3,0x0038a3b9},
        {0x04d31467,0x027cd692,0x0039e4f6}, {0x04ee3140,0x028ad173,0x003b2a50},
        {0x0509a62c,0x0298f9bd,0x003c73cb}, {0x0525737d,0x02a74f9b,0x003dc16b},
        {0x05419984,0x02b5d337,0x003f1334}, {0x055e1890,0x02c484b9,0x00406928},
        {0x057af0f1,0x02d3644b,0x0041c34d}, {0x059822f6,0x02e27217,0x004321a5},
        {0x05b5aef0,0x02f1ae43,0x00448435}, {0x05d3952b,0x030118fa,0x0045eaff},
        {0x05f1d5f6,0x0310b263,0x00475609}, {0x0610719f,0x03207aa7,0x0048c555},
        {0x062f6873,0x033071ec,0x004a38e7}, {0x064ebabf,0x0340985c,0x004bb0c3},
        {0x066e68d0,0x0350ee1d,0x004d2ceb}, {0x068e72f1,0x03617357,0x004ead65},
        {0x06aed96f,0x03722830,0x00503233}, {0x06cf9c96,0x03830cd0,0x0051bb59},
        {0x06f0bcaf,0x0394215e,0x005348da}, {0x07123a07,0x03a565ff,0x0054daba},
        {0x073414e7,0x03b6dadb,0x005670fd}, {0x07564d99,0x03c88018,0x00580ba5},
        {0x0778e468,0x03da55da,0x0059aab7}, {0x079bd99c,0x03ec5c4a,0x005b4e35},
        {0x07bf2d7f,0x03fe938b,0x005cf624}, {0x07e2e059,0x0410fbc4,0x005ea286},
        {0x0806f273,0x0423951a,0x0060535f}, {0x082b6414,0x04365fb1,0x006208b3},
        {0x08503586,0x04495bb0,0x0063c284}, {0x0875670e,0x045c893b,0x006580d7},
        {0x089af8f4,0x046fe876,0x006743ae}, {0x08c0eb80,0x04837986,0x00690b0c},
        {0x08e73ef6,0x04973c90,0x006ad6f6}, {0x090df39f,0x04ab31b7,0x006ca76e},
        {0x093509bf,0x04bf5920,0x006e7c77}, {0x095c819c,0x04d3b2ef,0x00705616},
        {0x09845b7d,0x04e83f47,0x0072344c}, {0x09ac97a4,0x04fcfe4c,0x0074171e},
        {0x09d53659,0x0511f021,0x0075fe8f}, {0x09fe37de,0x052714ea,0x0077eaa1},
        {0x0a279c78,0x053c6cca,0x0079db58}, {0x0a51646c,0x0551f7e4,0x007bd0b8},
        {0x0a7b8ffc,0x0567b65b,0x007dcac2}, {0x0aa61f6d,0x057da852,0x007fc97c},
        {0x0ad11301,0x0593cdeb,0x0081cce7}, {0x0afc6afb,0x05aa2748,0x0083d507},
        {0x0b28279e,0x05c0b48d,0x0085e1de}, {0x0b54492c,0x05d775db,0x0087f371},
        {0x0b80cfe8,0x05ee6b54,0x008a09c2}, {0x0badbc13,0x0605951a,0x008c24d4},
        {0x0bdb0dee,0x061cf350,0x008e44aa}, {0x0c08c5bc,0x06348617,0x00906948},
        {0x0c36e3bd,0x064c4d90,0x009292b0}, {0x0c656832,0x066449dc,0x0094c0e5},
        {0x0c94535c,0x067c7b1f,0x0096f3ec}, {0x0cc3a57b,0x0694e177,0x00992bc5},
        {0x0cf35ecf,0x06ad7d07,0x009b6875}, {0x0d237f99,0x06c64df0,0x009da9ff},
        {0x0d540818,0x06df5451,0x009ff064}, {0x0d84f88a,0x06f8904d,0x00a23baa},
        {0x0db65131,0x07120204,0x00a48bd2}, {0x0de8124a,0x072ba995,0x00a6e0df},
        {0x0e1a3c15,0x07458722,0x00a93ad5}, {0x0e4cced0,0x075f9acb,0x00ab99b5},
        {0x0e7fcab9,0x0779e4b0,0x00adfd84}, {0x0eb3300f,0x079464f1,0x00b06644},
        {0x0ee6ff0f,0x07af1bad,0x00b2d3f8}, {0x0f1b37f7,0x07ca0906,0x00b546a3},
        {0x0f4fdb05,0x07e52d19,0x00b7be48}, {0x0f84e876,0x08008808,0x00ba3ae9},
        {0x0fba6087,0x081c19f2,0x00bcbc8a}, {0x0ff04375,0x0837e2f5,0x00bf432e},
        {0x1026917d,0x0853e331,0x00c1ced6}, {0x105d4ada,0x08701ac6,0x00c45f86},
        {0x10946fca,0x088c89d3,0x00c6f542}, {0x10cc0089,0x08a93076,0x00c9900b},
        {0x1103fd52,0x08c60ece,0x00cc2fe4}, {0x113c6661,0x08e324fa,0x00ced4d1},
        {0x11753bf2,0x0900731a,0x00d17ed4}, {0x11ae7e40,0x091df94a,0x00d42def},
        {0x11e82d85,0x093bb7ab,0x00d6e227}, {0x122249fe,0x0959ae5a,0x00d99b7d},
        {0x125cd3e4,0x0977dd75,0x00dc59f3}, {0x1297cb73,0x0996451b,0x00df1d8e},
        {0x12d330e4,0x09b4e56a,0x00e1e64f}, {0x130f0472,0x09d3be80,0x00e4b43a},
        {0x134b4657,0x09f2d07b,0x00e78751}, {0x1387f6cd,0x0a121b78,0x00ea5f97},
        {0x13c5160d,0x0a319f96,0x00ed3d0e}, {0x1402a451,0x0a515cf2,0x00f01fb9},
        {0x1440a1d2,0x0a7153a9,0x00f3079b}, {0x147f0eca,0x0a9183da,0x00f5f4b7},
        {0x14bdeb71,0x0ab1eda0,0x00f8e70f}, {0x14fd3800,0x0ad2911b,0x00fbdea5},
        {0x153cf4b0,0x0af36e66,0x00fedb7e}, {0x157d21ba,0x0b1485a0,0x0101dd9a},
        {0x15bdbf54,0x0b35d6e4,0x0104e4fd}, {0x15fecdb9,0x0b576251,0x0107f1aa},
        {0x16404d1f,0x0b792802,0x010b03a3}, {0x16823dbf,0x0b9b2815,0x010e1aeb},
        {0x16c49fd0,0x0bbd62a7,0x01113784}, {0x1707738a,0x0bdfd7d3,0x01145970},
        {0x174ab923,0x0c0287b7,0x011780b4}, {0x178e70d4,0x0c25726f,0x011aad50},
        {0x17d29ad3,0x0c489817,0x011ddf48}, {0x18173757,0x0c6bf8cc,0x0121169e},
        {0x185c4697,0x0c8f94aa,0x01245355}, {0x18a1c8c9,0x0cb36bcc,0x01279570},
        {0x18e7be24,0x0cd77e50,0x012adcf0}, {0x192e26dd,0x0cfbcc51,0x012e29d9},
        {0x1975032d,0x0d2055ea,0x01317c2d}, {0x19bc5347,0x0d451b38,0x0134d3ee},
        {0x1a041762,0x0d6a1c57,0x0138311f}, {0x1a4c4fb3,0x0d8f5962,0x013b93c3},
        {0x1a94fc71,0x0db4d275,0x013efbdc}, {0x1ade1dd0,0x0dda87aa,0x0142696d},
        {0x1b27b406,0x0e00791f,0x0145dc77}, {0x1b71bf48,0x0e26a6ee,0x014954fe},
        {0x1bbc3fca,0x0e4d1132,0x014cd305}, {0x1c0735c3,0x0e73b807,0x0150568c},
        {0x1c52a165,0x0e9a9b87,0x0153df98}, {0x1c9e82e6,0x0ec1bbcf,0x01576e2a},
        {0x1ceada7b,0x0ee918f8,0x015b0245}, {0x1d37a857,0x0f10b31e,0x015e9beb},
        {0x1d84ecae,0x0f388a5d,0x01623b20}, {0x1dd2a7b6,0x0f609ecd,0x0165dfe4},
        {0x1e20d9a0,0x0f88f08b,0x01698a3b}, {0x1e6f82a2,0x0fb17fb1,0x016d3a27},
        {0x1ebea2ef,0x0fda4c59,0x0170efab}, {0x1f0e3aba,0x1003569f,0x0174aac9},
        {0x1f5e4a37,0x102c9e9c,0x01786b83}, {0x1faed199,0x1056246b,0x017c31db},
        {0x1fffd112,0x107fe827,0x017ffdd5}, {0x205148d7,0x10a9e9e9,0x0183cf72},
        {0x20a33919,0x10d429cc,0x0187a6b5}, {0x20f5a20b,0x10fea7ea,0x018b83a1},
        {0x214883e1,0x1129645d,0x018f6637}, {0x219bdecc,0x11545f3f,0x01934e7a},
        {0x21efb2ff,0x117f98aa,0x01973c6d}, {0x224400ac,0x11ab10b9,0x019b3011},
        {0x2298c805,0x11d6c783,0x019f2969}, {0x22ee093c,0x1202bd25,0x01a32878},
        {0x2343c484,0x122ef1b6,0x01a72d3f}, {0x2399fa0c,0x125b6552,0x01ab37c2},
        {0x23f0aa09,0x12881811,0x01af4802}, {0x2447d4aa,0x12b50a0d,0x01b35e01},
        {0x249f7a21,0x12e23b5f,0x01b779c3}, {0x24f79a9f,0x130fac21,0x01bb9b49},
        {0x25503656,0x133d5c6d,0x01bfc296}, {0x25a94d77,0x136b4c5b,0x01c3efab},
        {0x2602e032,0x13997c04,0x01c8228c}, {0x265ceeb9,0x13c7eb83,0x01cc5b3a},
        {0x26b7793c,0x13f69aef,0x01d099b9}, {0x27127feb,0x14258a63,0x01d4de09},
        {0x276e02f8,0x1454b9f6,0x01d9282e}, {0x27ca0292,0x148429c2,0x01dd7829},
        {0x28267ee9,0x14b3d9e1,0x01e1cdfd}, {0x2883782f,0x14e3ca69,0x01e629ac},
        {0x28e0ee92,0x1513fb76,0x01ea8b39}, {0x293ee243,0x15446d1e,0x01eef2a6},
    };

    static const uint32_t gtable[256][3] = {
        {0x00000000,0x00000000,0x00000000}, {0x0002c74a,0x00058e94,0x0000ed19},
        {0x00058e94,0x000b1d27,0x0001da31}, {0x000855dd,0x0010abbb,0x0002c74a},
        {0x000b1d27,0x00163a4f,0x0003b462}, {0x000de471,0x001bc8e2,0x0004a17b},
        {0x0010abbb,0x00215776,0x00058e94}, {0x00137305,0x0026e60a,0x00067bac},
        {0x00163a4f,0x002c749d,0x000768c5}, {0x00190198,0x00320331,0x000855dd},
        {0x001bc8e2,0x003791c5,0x000942f6}, {0x001ea24f,0x003d449e,0x000a361a},
        {0x0021a791,0x00434f22,0x000b37db}, {0x0024d791,0x0049af21,0x000c47db},
        {0x002832f4,0x005065e8,0x000d6651}, {0x002bba5d,0x005774ba,0x000e9374},
        {0x002f6e6c,0x005edcd8,0x000fcf79}, {0x00334fbc,0x00669f78,0x00111a94},
        {0x00375ee6,0x006ebdcd,0x001274f7}, {0x003b9c81,0x00773902,0x0013ded5},
        {0x0040091f,0x0080123d,0x0015585f}, {0x0044a550,0x00894aa0,0x0016e1c5},
        {0x004971a3,0x0092e346,0x00187b36}, {0x004e6ea3,0x009cdd46,0x001a24e1},
        {0x00539cda,0x00a739b4,0x001bdef3}, {0x0058fcce,0x00b1f99c,0x001da999},
        {0x005e8f05,0x00bd1e09,0x001f8501}, {0x00645400,0x00c8a801,0x00217155},
        {0x006a4c43,0x00d49885,0x00236ec0}, {0x0070784a,0x00e0f094,0x00257d6d},
        {0x0076d894,0x00edb128,0x00279d86}, {0x007d6d9c,0x00fadb38,0x0029cf33},
        {0x008437dc,0x01086fb7,0x002c129e}, {0x008b37cc,0x01166f97,0x002e67ee},
        {0x00926de3,0x0124dbc5,0x0030cf4b}, {0x0099da96,0x0133b52b,0x003348dc},
        {0x00a17e58,0x0142fcb1,0x0035d4c7}, {0x00a9599d,0x0152b33b,0x00387333},
        {0x00b16cd5,0x0162d9aa,0x003b2446}, {0x00b9b870,0x017370df,0x003de824},
        {0x00c23cdb,0x018479b7,0x0040bef3}, {0x00cafa85,0x0195f50a,0x0043a8d6},
        {0x00d3f1d9,0x01a7e3b2,0x0046a5f2}, {0x00dd2341,0x01ba4683,0x0049b66a},
        {0x00e68f28,0x01cd1e50,0x004cda61}, {0x00f035f6,0x01e06bec,0x005011fb},
        {0x00fa1812,0x01f43024,0x00535d5a}, {0x010435e3,0x02086bc6,0x0056bc9f},
        {0x010e8fce,0x021d1f9b,0x005a2fee}, {0x01192637,0x02324c6d,0x005db766},
        {0x0123f982,0x0247f303,0x00615329}, {0x012f0a11,0x025e1421,0x00650359},
        {0x013a5846,0x0274b08b,0x0068c815}, {0x0145e481,0x028bc902,0x006ca17e},
        {0x0151af22,0x02a35e45,0x00708fb4}, {0x015db889,0x02bb7112,0x007492d6},
        {0x016a0112,0x02d40225,0x0078ab04}, {0x0176891d,0x02ed1239,0x007cd85d},
        {0x01835103,0x0306a207,0x00811aff}, {0x01905923,0x0320b246,0x00857309},
        {0x019da1d6,0x033b43ac,0x0089e09a}, {0x01ab2b77,0x035656ee,0x008e63d0},
        {0x01b8f65f,0x0371ecbd,0x0092fcc8}, {0x01c702e6,0x038e05cd,0x0097ab9f},
        {0x01d55166,0x03aaa2cc,0x009c7074}, {0x01e3e235,0x03c7c46a,0x00a14b64},
        {0x01f2b5aa,0x03e56b54,0x00a63c8b}, {0x0201cc1b,0x04039836,0x00ab4406},
        {0x021125de,0x04224bbb,0x00b061f1}, {0x0220c346,0x0441868c,0x00b59669},
        {0x0230a4a9,0x04614952,0x00bae18a}, {0x0240ca5a,0x048194b4,0x00c04370},
        {0x025134ac,0x04a26957,0x00c5bc36}, {0x0261e3f0,0x04c3c7e1,0x00cb4bf7},
        {0x0272d87a,0x04e5b0f5,0x00d0f2d0}, {0x0284129a,0x05082535,0x00d6b0da},
        {0x029592a1,0x052b2543,0x00dc8632}, {0x02a758df,0x054eb1bf,0x00e272f1},
        {0x02b965a4,0x0572cb48,0x00e87732}, {0x02cbb93e,0x0597727c,0x00ee9310},
        {0x02de53fd,0x05bca7fa,0x00f4c6a5}, {0x02f1362e,0x05e26c5b,0x00fb120b},
        {0x0304601f,0x0608c03d,0x0101755b}, {0x0317d21c,0x062fa439,0x0107f0af},
        {0x032b8c74,0x065718e7,0x010e8422}, {0x033f8f71,0x067f1ee2,0x01152fcb},
        {0x0353db5f,0x06a7b6be,0x011bf3c5}, {0x0368708a,0x06d0e114,0x0122d029},
        {0x037d4f3c,0x06fa9e79,0x0129c50f}, {0x039277c0,0x0724ef81,0x0130d290},
        {0x03a7ea60,0x074fd4c0,0x0137f8c5}, {0x03bda764,0x077b4ec8,0x013f37c6},
        {0x03d3af16,0x07a75e2d,0x01468fac}, {0x03ea01bf,0x07d4037f,0x014e008f},
        {0x04009fa7,0x08013f4e,0x01558a87}, {0x04178915,0x082f122a,0x015d2dab},
        {0x042ebe51,0x085d7ca3,0x0164ea15}, {0x04463fa2,0x088c7f45,0x016cbfda},
        {0x045e0d4f,0x08bc1a9e,0x0174af14}, {0x0476279e,0x08ec4f3b,0x017cb7d8},
        {0x048e8ed4,0x091d1da8,0x0184da3f}, {0x04a74337,0x094e866e,0x018d1660},
        {0x04c0450d,0x09808a1a,0x01956c52}, {0x04d9949a,0x09b32933,0x019ddc2c},
        {0x04f33222,0x09e66444,0x01a66604}, {0x050d1de9,0x0a1a3bd3,0x01af09f1},
        {0x05275834,0x0a4eb069,0x01b7c809}, {0x0541e146,0x0a83c28c,0x01c0a064},
        {0x055cb961,0x0ab972c3,0x01c99318}, {0x0577e0c9,0x0aefc192,0x01d2a03a},
        {0x059357bf,0x0b26af7f,0x01dbc7e2}, {0x05af1e87,0x0b5e3d0d,0x01e50a24},
        {0x05cb3561,0x0b966ac1,0x01ee6717}, {0x05e79c8e,0x0bcf391d,0x01f7ded1},
        {0x06045451,0x0c08a8a3,0x02017167}, {0x06215cea,0x0c42b9d4,0x020b1eef},
        {0x063eb699,0x0c7d6d33,0x0214e77f}, {0x065c619f,0x0cb8c33f,0x021ecb2b},
        {0x067a5e3c,0x0cf4bc78,0x0228ca0a}, {0x0698acae,0x0d31595d,0x0232e430},
        {0x06b74d37,0x0d6e9a6d,0x023d19b2}, {0x06d64013,0x0dac8026,0x02476aa6},
        {0x06f58583,0x0deb0b06,0x0251d721}, {0x07151dc5,0x0e2a3b89,0x025c5f37},
        {0x07350916,0x0e6a122d,0x026702fc}, {0x075547b6,0x0eaa8f6c,0x0271c287},
        {0x0775d9e1,0x0eebb3c3,0x027c9dea}, {0x0796bfd5,0x0f2d7fab,0x0287953b},
        {0x07b7f9d0,0x0f6ff3a0,0x0292a88f}, {0x07d9880d,0x0fb3101a,0x029dd7f8},
        {0x07fb6aca,0x0ff6d595,0x02a9238c}, {0x081da243,0x103b4487,0x02b48b5f},
        {0x08402eb5,0x10805d69,0x02c00f85}, {0x0863105a,0x10c620b4,0x02cbb011},
        {0x0886476f,0x110c8edd,0x02d76d18}, {0x08a9d42f,0x1153a85d,0x02e346ad},
        {0x08cdb6d5,0x119b6da9,0x02ef3ce4}, {0x08f1ef9c,0x11e3df37,0x02fb4fd1},
        {0x09167ebf,0x122cfd7d,0x03077f87}, {0x093b6478,0x1276c8ef,0x0313cc19},
        {0x0960a101,0x12c14202,0x0320359c}, {0x09863495,0x130c692a,0x032cbc23},
        {0x09ac1f6d,0x13583eda,0x03395fc0}, {0x09d261c3,0x13a4c385,0x03462087},
        {0x09f8fbcf,0x13f1f79e,0x0352fe8b}, {0x0a1fedcc,0x143fdb98,0x035ff9df},
        {0x0a4737f1,0x148e6fe3,0x036d1296}, {0x0a6eda79,0x14ddb4f1,0x037a48c3},
        {0x0a96d59a,0x152dab34,0x03879c78}, {0x0abf298d,0x157e531b,0x03950dc9},
        {0x0ae7d68b,0x15cfad17,0x03a29cc8}, {0x0b10dccb,0x1621b997,0x03b04988},
        {0x0b3a3c85,0x1674790a,0x03be141b}, {0x0b63f5f0,0x16c7ebe0,0x03cbfc94},
        {0x0b8e0943,0x171c1287,0x03da0304}, {0x0bb876b6,0x1770ed6c,0x03e82780},
        {0x0be33e7f,0x17c67cff,0x03f66a18}, {0x0c0e60d5,0x181cc1aa,0x0404cadf},
        {0x0c39ddef,0x1873bbdd,0x041349e7}, {0x0c65b601,0x18cb6c03,0x0421e742},
        {0x0c91e944,0x1923d288,0x0430a303}, {0x0cbe77ec,0x197cefd8,0x043f7d3b},
        {0x0ceb622f,0x19d6c45e,0x044e75fc}, {0x0d18a843,0x1a315086,0x045d8d57},
        {0x0d464a5d,0x1a8c94ba,0x046cc360}, {0x0d7448b2,0x1ae89164,0x047c1826},
        {0x0da2a377,0x1b4546ef,0x048b8bbd}, {0x0dd15ae2,0x1ba2b5c3,0x049b1e36},
        {0x0e006f25,0x1c00de4b,0x04aacfa1}, {0x0e2fe077,0x1c5fc0ee,0x04baa011},
        {0x0e5faf0b,0x1cbf5e16,0x04ca8f98}, {0x0e8fdb15,0x1d1fb62a,0x04da9e46},
        {0x0ec064c9,0x1d80c993,0x04eacc2c}, {0x0ef14c5c,0x1de298b8,0x04fb195d},
        {0x0f229200,0x1e452400,0x050b85e8}, {0x0f5435e9,0x1ea86bd1,0x051c11e0},
        {0x0f86384a,0x1f0c7094,0x052cbd56}, {0x0fb89957,0x1f7132ad,0x053d885a},
        {0x0feb5941,0x1fd6b283,0x054e72fd}, {0x101e783d,0x203cf07b,0x055f7d51},
        {0x1051f67d,0x20a3ecfa,0x0570a765}, {0x1085d433,0x210ba866,0x0581f14c},
        {0x10ba1191,0x21742322,0x05935b16}, {0x10eeaeca,0x21dd5d94,0x05a4e4d3},
        {0x1123ac0f,0x2247581f,0x05b68e95}, {0x11590993,0x22b21326,0x05c8586b},
        {0x118ec787,0x231d8f0e,0x05da4267}, {0x11c4e61d,0x2389cc39,0x05ec4c98},
        {0x11fb6585,0x23f6cb0b,0x05fe7710}, {0x123245f2,0x24648be5,0x0610c1df},
        {0x12698795,0x24d30f2a,0x06232d15}, {0x12a12a9e,0x2542553b,0x0635b8c2},
        {0x12d92f3e,0x25b25e7b,0x064864f7}, {0x131195a6,0x26232b4b,0x065b31c4},
        {0x134a5e06,0x2694bc0c,0x066e1f39}, {0x1383888f,0x2707111e,0x06812d66},
        {0x13bd1571,0x277a2ae2,0x06945c5c}, {0x13f704dc,0x27ee09b8,0x06a7ac2a},
        {0x14315700,0x2862ae01,0x06bb1ce1}, {0x146c0c0e,0x28d8181b,0x06ceae8f},
        {0x14a72433,0x294e4867,0x06e26146}, {0x14e29fa2,0x29c53f43,0x06f63515},
        {0x151e7e87,0x2a3cfd0f,0x070a2a0c}, {0x155ac114,0x2ab58228,0x071e403b},
        {0x15976777,0x2b2eceee,0x073277b1}, {0x15d471df,0x2ba8e3be,0x0746d07d},
        {0x1611e07b,0x2c23c0f6,0x075b4ab1}, {0x164fb37a,0x2c9f66f4,0x076fe65b},
        {0x168deb0a,0x2d1bd615,0x0784a38b}, {0x16cc875b,0x2d990eb6,0x07998250},
        {0x170b889a,0x2e171134,0x07ae82ba}, {0x174aeef6,0x2e95ddeb,0x07c3a4d8},
        {0x178aba9c,0x2f157539,0x07d8e8ba}, {0x17caebbc,0x2f95d778,0x07ee4e6f},
        {0x180b8282,0x30170504,0x0803d606}, {0x184c7f1d,0x3098fe3a,0x08197f8e},
        {0x188de1bb,0x311bc375,0x082f4b18}, {0x18cfaa88,0x319f550f,0x084538b1},
        {0x1911d9b2,0x3223b364,0x085b4869}, {0x19546f67,0x32a8dece,0x08717a50},
        {0x19976bd4,0x332ed7a8,0x0887ce74}, {0x19dacf26,0x33b59e4b,0x089e44e4},
        {0x1a1e9989,0x343d3312,0x08b4ddb0}, {0x1a62cb2b,0x34c59656,0x08cb98e5},
        {0x1aa76439,0x354ec872,0x08e27694}, {0x1aec64de,0x35d8c9bd,0x08f976cb},
        {0x1b31cd49,0x36639a91,0x09109998}, {0x1b779da4,0x36ef3b48,0x0927df0c},
        {0x1bbdd61c,0x377bac38,0x093f4733}, {0x1c0476de,0x3808edbc,0x0956d21e},
        {0x1c4b8015,0x3897002b,0x096e7fdb}, {0x1c92f1ee,0x3925e3dc,0x09865078},
        {0x1cdacc94,0x39b59928,0x099e4404}, {0x1d231033,0x3a462066,0x09b65a8e},
        {0x1d6bbcf7,0x3ad779ee,0x09ce9424}, {0x1db4d30b,0x3b69a616,0x09e6f0d5},
        {0x1dfe529b,0x3bfca535,0x09ff70af}, {0x1e483bd1,0x3c9077a2,0x0a1813c1},
        {0x1e928eda,0x3d251db4,0x0a30da19}, {0x1edd4be0,0x3dba97c0,0x0a49c3c5},
        {0x1f28730e,0x3e50e61d,0x0a62d0d4}, {0x1f740490,0x3ee80920,0x0a7c0154},
        {0x1fc00090,0x3f80011f,0x0a955554}, {0x200c6738,0x4018ce70,0x0aaecce1},
        {0x205938b4,0x40b27167,0x0ac86809}, {0x20a6752d,0x414cea5b,0x0ae226dc},
        {0x20f41ccf,0x41e8399f,0x0afc0967}, {0x21422fc4,0x42845f87,0x0b160fb8},
        {0x2190ae35,0x43215c6a,0x0b3039dd}, {0x21df984d,0x43bf309b,0x0b4a87e5},
        {0x222eee36,0x445ddc6d,0x0b64f9dd}, {0x227eb01a,0x44fd6035,0x0b7f8fd3},
        {0x22cede23,0x459dbc46,0x0b9a49d5}, {0x231f787a,0x463ef0f5,0x0bb527f2},
        {0x23707f4a,0x46e0fe93,0x0bd02a36}, {0x23c1f2bb,0x4783e575,0x0beb50b1},
    };

    static const uint32_t btable[256][3] = {
        {0x00000000,0x00000000,0x00000000}, {0x000166ed,0x00008f92,0x00076257},
        {0x0002cdda,0x00011f24,0x000ec4ae}, {0x000434c7,0x0001aeb6,0x00162705},
        {0x00059bb3,0x00023e48,0x001d895c}, {0x000702a0,0x0002cdda,0x0024ebb3},
        {0x0008698d,0x00035d6c,0x002c4e0a}, {0x0009d07a,0x0003ecfe,0x0033b061},
        {0x000b3767,0x00047c90,0x003b12b8}, {0x000c9e54,0x00050c22,0x0042750f},
        {0x000e0541,0x00059bb3,0x0049d765}, {0x000f7554,0x00062eef,0x005169ef},
        {0x0010fb87,0x0006cb03,0x005970f8}, {0x0012974a,0x00076fb7,0x0061e996},
        {0x001448f2,0x00081d2e,0x006ad585}, {0x001610d2,0x0008d387,0x00743673},
        {0x0017ef39,0x000992e4,0x007e0e09}, {0x0019e476,0x000a5b62,0x00885de4},
        {0x001bf0d6,0x000b2d23,0x0093279b}, {0x001e14a5,0x000c0842,0x009e6cbc},
        {0x0020502e,0x000cecdf,0x00aa2ece}, {0x0022a3b8,0x000ddb16,0x00b66f52},
        {0x00250f8c,0x000ed305,0x00c32fbf}, {0x002793f0,0x000fd4c7,0x00d0718a},
        {0x002a312a,0x0010e077,0x00de361f}, {0x002ce77d,0x0011f632,0x00ec7ee5},
        {0x002fb72c,0x00131612,0x00fb4d3d}, {0x0032a07a,0x00144031,0x010aa283},
        {0x0035a3a8,0x001574aa,0x011a800d}, {0x0038c0f6,0x0016b395,0x012ae72e},
        {0x003bf8a2,0x0017fd0e,0x013bd932}, {0x003f4aec,0x0019512b,0x014d5761},
        {0x0042b811,0x001ab007,0x015f6300}, {0x0046404d,0x001c19b8,0x0171fd4e},
        {0x0049e3dc,0x001d8e58,0x01852786}, {0x004da2fa,0x001f0dfe,0x0198e2e0},
        {0x00517de1,0x002098c0,0x01ad308f}, {0x005574cb,0x00222eb7,0x01c211c3},
        {0x005987f0,0x0023cff9,0x01d787a8}, {0x005db789,0x00257c9d,0x01ed9368},
        {0x006203cd,0x002734b9,0x02043626}, {0x00666cf5,0x0028f862,0x021b7106},
        {0x006af335,0x002ac7af,0x02334526}, {0x006f96c4,0x002ca2b5,0x024bb3a2},
        {0x007457d8,0x002e898a,0x0264bd92}, {0x007936a5,0x00307c42,0x027e640c},
        {0x007e335f,0x00327af3,0x0298a823}, {0x00834e39,0x003485b1,0x02b38ae6},
        {0x00888768,0x00369c90,0x02cf0d64}, {0x008ddf1d,0x0038bfa5,0x02eb30a7},
        {0x0093558b,0x003aef04,0x0307f5b8}, {0x0098eae4,0x003d2ac2,0x03255d9b},
        {0x009e9f58,0x003f72f0,0x03436954}, {0x00a47319,0x0041c7a3,0x036219e4},
        {0x00aa6656,0x004428ef,0x03817049}, {0x00b07940,0x004696e6,0x03a16d80},
        {0x00b6ac06,0x0049119c,0x03c21283}, {0x00bcfed8,0x004b9923,0x03e36049},
        {0x00c371e3,0x004e2d8e,0x040557c8}, {0x00ca0556,0x0050ceef,0x0427f9f4},
        {0x00d0b960,0x00537d59,0x044b47bf}, {0x00d78e2d,0x005638df,0x046f4218},
        {0x00de83ea,0x00590191,0x0493e9ee}, {0x00e59ac5,0x005bd782,0x04b9402a},
        {0x00ecd2ea,0x005ebac4,0x04df45b9}, {0x00f42c85,0x0061ab68,0x0505fb82},
        {0x00fba7c1,0x0064a981,0x052d626b}, {0x010344cb,0x0067b51e,0x05557b5a},
        {0x010b03cd,0x006ace52,0x057e4730}, {0x0112e4f2,0x006df52d,0x05a7c6d0},
        {0x011ae864,0x007129c2,0x05d1fb18}, {0x01230e4e,0x00746c1f,0x05fce4e8},
        {0x012b56d9,0x0077bc57,0x0628851b}, {0x0133c22f,0x007b1a79,0x0654dc8c},
        {0x013c507a,0x007e8697,0x0681ec15}, {0x014501e2,0x008200c1,0x06afb48d},
        {0x014dd690,0x00858906,0x06de36cb}, {0x0156ceac,0x00891f78,0x070d73a5},
        {0x015fea5f,0x008cc426,0x073d6bed}, {0x016929d1,0x00907720,0x076e2075},
        {0x01728d28,0x00943876,0x079f920f}, {0x017c148d,0x00980839,0x07d1c18a},
        {0x0185c027,0x009be676,0x0804afb3}, {0x018f901c,0x009fd33f,0x08385d59},
        {0x01998494,0x00a3cea2,0x086ccb46}, {0x01a39db4,0x00a7d8af,0x08a1fa45},
        {0x01addba3,0x00abf175,0x08d7eb1f}, {0x01b83e87,0x00b01903,0x090e9e9b},
        {0x01c2c685,0x00b44f69,0x09461581}, {0x01cd73c4,0x00b894b5,0x097e5095},
        {0x01d84667,0x00bce8f6,0x09b7509d}, {0x01e33e95,0x00c14c3c,0x09f1165b},
        {0x01ee5c72,0x00c5be94,0x0a2ba292}, {0x01f9a023,0x00ca400e,0x0a66f602},
        {0x020509cc,0x00ced0b8,0x0aa3116b}, {0x02109992,0x00d370a1,0x0adff58c},
        {0x021c4f98,0x00d81fd6,0x0b1da323}, {0x02282c02,0x00dcde67,0x0b5c1aec},
        {0x02342ef4,0x00e1ac62,0x0b9b5da4}, {0x02405892,0x00e689d4,0x0bdb6c05},
        {0x024ca8ff,0x00eb76cc,0x0c1c46c8}, {0x0259205d,0x00f07358,0x0c5deea6},
        {0x0265becf,0x00f57f86,0x0ca06457}, {0x02728479,0x00fa9b64,0x0ce3a892},
        {0x027f717d,0x00ffc6ff,0x0d27bc0c}, {0x028c85fd,0x01050265,0x0d6c9f7b},
        {0x0299c21c,0x010a4da5,0x0db25392}, {0x02a725fa,0x010fa8ca,0x0df8d904},
        {0x02b4b1bb,0x011513e4,0x0e403084}, {0x02c26580,0x011a8f00,0x0e885ac3},
        {0x02d0416a,0x01201a2a,0x0ed15871}, {0x02de459b,0x0125b571,0x0f1b2a3e},
        {0x02ec7233,0x012b60e1,0x0f65d0d9}, {0x02fac754,0x01311c88,0x0fb14cef},
        {0x03094520,0x0136e873,0x0ffd9f2d}, {0x0317ebb5,0x013cc4af,0x104ac840},
        {0x0326bb36,0x0142b149,0x1098c8d4}, {0x0335b3c1,0x0148ae4d,0x10e7a192},
        {0x0344d579,0x014ebbca,0x11375325}, {0x0354207c,0x0154d9cb,0x1187de35},
        {0x036394eb,0x015b085e,0x11d9436c}, {0x037332e5,0x0161478f,0x122b8370},
        {0x0382fa8b,0x0167976b,0x127e9ee8}, {0x0392ebfb,0x016df7fe,0x12d2967b},
        {0x03a30755,0x01746955,0x13276ace}, {0x03b34cb9,0x017aeb7d,0x137d1c85},
        {0x03c3bc45,0x01817e82,0x13d3ac44}, {0x03d45619,0x01882270,0x142b1aaf},
        {0x03e51a53,0x018ed754,0x14836867}, {0x03f60911,0x01959d3a,0x14dc9610},
        {0x04072274,0x019c742e,0x1536a449}, {0x04186698,0x01a35c3d,0x159193b4},
        {0x0429d59d,0x01aa5572,0x15ed64f0}, {0x043b6fa1,0x01b15fda,0x164a189c},
        {0x044d34c1,0x01b87b80,0x16a7af56}, {0x045f251c,0x01bfa872,0x170629bd},
        {0x047140d0,0x01c6e6b9,0x1765886e}, {0x048387f9,0x01ce3664,0x17c5cc05},
        {0x0495fab7,0x01d5977c,0x1826f51f}, {0x04a89926,0x01dd0a0f,0x18890455},
        {0x04bb6364,0x01e48e28,0x18ebfa44}, {0x04ce598d,0x01ec23d2,0x194fd785},
        {0x04e17bc0,0x01f3cb1a,0x19b49cb2}, {0x04f4ca19,0x01fb840a,0x1a1a4a64},
        {0x050844b5,0x02034eaf,0x1a80e132}, {0x051bebb0,0x020b2b13,0x1ae861b5},
        {0x052fbf29,0x02131944,0x1b50cc84}, {0x0543bf3a,0x021b194b,0x1bba2235},
        {0x0557ec02,0x02232b34,0x1c24635f}, {0x056c459b,0x022b4f0b,0x1c8f9097},
        {0x0580cc22,0x023384db,0x1cfbaa71}, {0x05957fb5,0x023bccaf,0x1d68b183},
        {0x05aa606d,0x02442692,0x1dd6a660}, {0x05bf6e68,0x024c9290,0x1e45899b},
        {0x05d4a9c2,0x025510b4,0x1eb55bc7}, {0x05ea1295,0x025da109,0x1f261d76},
        {0x05ffa8ff,0x02664399,0x1f97cf3a}, {0x06156d1a,0x026ef871,0x200a71a5},
        {0x062b5f01,0x0277bf9a,0x207e0546}, {0x06417ed1,0x02809920,0x20f28aaf},
        {0x0657cca4,0x0289850f,0x2168026e}, {0x066e4896,0x0292836f,0x21de6d13},
        {0x0684f2c2,0x029b944e,0x2255cb2c}, {0x069bcb43,0x02a4b7b4,0x22ce1d48},
        {0x06b2d233,0x02adedae,0x234763f5}, {0x06ca07ae,0x02b73646,0x23c19fc0},
        {0x06e16bce,0x02c09186,0x243cd134}, {0x06f8feae,0x02c9ff79,0x24b8f8e0},
        {0x0710c068,0x02d3802a,0x2536174e}, {0x0728b117,0x02dd13a3,0x25b42d0a},
        {0x0740d0d6,0x02e6b9ef,0x26333a9f}, {0x07591fbe,0x02f07319,0x26b34097},
        {0x07719de9,0x02fa3f2a,0x27343f7c}, {0x078a4b73,0x03041e2e,0x27b637d8},
        {0x07a32874,0x030e102e,0x28392a34}, {0x07bc3507,0x03181536,0x28bd1718},
        {0x07d57146,0x03222d4f,0x2941ff0e}, {0x07eedd4a,0x032c5884,0x29c7e29b},
        {0x0808792e,0x033696df,0x2a4ec249}, {0x0822450a,0x0340e86b,0x2ad69e9d},
        {0x083c40f9,0x034b4d30,0x2b5f781f}, {0x08566d13,0x0355c53b,0x2be94f54},
        {0x0870c973,0x03605094,0x2c7424c3}, {0x088b5631,0x036aef47,0x2cfff8f0},
        {0x08a61367,0x0375a15c,0x2d8ccc60}, {0x08c1012e,0x038066df,0x2e1a9f98},
        {0x08dc1f9e,0x038b3fd9,0x2ea9731c}, {0x08f76ed2,0x03962c54,0x2f39476f},
        {0x0912eee1,0x03a12c5a,0x2fca1d16}, {0x092e9fe6,0x03ac3ff5,0x305bf491},
        {0x094a81f7,0x03b76730,0x30eece65}, {0x0966952f,0x03c2a213,0x3182ab14},
        {0x0982d9a6,0x03cdf0a9,0x32178b1e}, {0x099f4f74,0x03d952fb,0x32ad6f06},
        {0x09bbf6b2,0x03e4c914,0x3344574c}, {0x09d8cf78,0x03f052fd,0x33dc4471},
        {0x09f5d9df,0x03fbf0c0,0x347536f5}, {0x0a1315ff,0x0407a266,0x350f2f58},
        {0x0a3083f0,0x041367fa,0x35aa2e19}, {0x0a4e23cb,0x041f4184,0x364633b9},
        {0x0a6bf5a6,0x042b2f0f,0x36e340b4}, {0x0a89f99b,0x043730a5,0x3781558b},
        {0x0aa82fc2,0x0443464d,0x382072ba}, {0x0ac69831,0x044f7014,0x38c098c0},
        {0x0ae53302,0x045bae01,0x3961c81a}, {0x0b04004b,0x0468001e,0x3a040145},
        {0x0b230024,0x04746675,0x3aa744be}, {0x0b4232a6,0x0480e10f,0x3b4b9301},
        {0x0b6197e7,0x048d6ff6,0x3bf0ec8a}, {0x0b812fff,0x049a1333,0x3c9751d4},
        {0x0ba0fb05,0x04a6cacf,0x3d3ec35b}, {0x0bc0f911,0x04b396d4,0x3de7419b},
        {0x0be12a3b,0x04c0774b,0x3e90cd0d}, {0x0c018e98,0x04cd6c3d,0x3f3b662c},
        {0x0c222641,0x04da75b4,0x3fe70d72}, {0x0c42f14d,0x04e793b8,0x4093c359},
        {0x0c63efd2,0x04f4c654,0x4141885a}, {0x0c8521e8,0x05020d90,0x41f05ced},
        {0x0ca687a5,0x050f6975,0x42a0418d}, {0x0cc82121,0x051cda0d,0x435136b1},
        {0x0ce9ee71,0x052a5f61,0x44033cd2}, {0x0d0befae,0x0537f979,0x44b65467},
        {0x0d2e24ee,0x0545a85f,0x456a7de7}, {0x0d508e46,0x05536c1c,0x461fb9ca},
        {0x0d732bcf,0x056144b9,0x46d60888}, {0x0d95fd9e,0x056f323f,0x478d6a95},
        {0x0db903c9,0x057d34b7,0x4845e069}, {0x0ddc3e68,0x058b4c2a,0x48ff6a7a},
        {0x0dffad91,0x059978a0,0x49ba093d}, {0x0e235159,0x05a7ba24,0x4a75bd29},
        {0x0e4729d8,0x05b610bd,0x4b3286b1}, {0x0e6b3722,0x05c47c74,0x4bf0664a},
        {0x0e8f794f,0x05d2fd53,0x4caf5c6a}, {0x0eb3f075,0x05e19362,0x4d6f6985},
        {0x0ed89ca9,0x05f03eaa,0x4e308e0e}, {0x0efd7e02,0x05feff34,0x4ef2ca79},
        {0x0f229495,0x060dd508,0x4fb61f3a}, {0x0f47e078,0x061cc030,0x507a8cc4},
        {0x0f6d61c1,0x062bc0b4,0x51401389}, {0x0f931886,0x063ad69c,0x5206b3fd},
        {0x0fb904dd,0x064a01f2,0x52ce6e91}, {0x0fdf26db,0x065942be,0x539743b7},
        {0x10057e95,0x06689909,0x546133e2}, {0x102c0c22,0x067804da,0x552c3f83},
        {0x1052cf97,0x0687863c,0x55f8670b}, {0x1079c909,0x06971d37,0x56c5aaeb},
        {0x10a0f88e,0x06a6c9d2,0x57940b94}, {0x10c85e3a,0x06b68c17,0x58638976},
        {0x10effa24,0x06c6640f,0x59342501}, {0x1117cc61,0x06d651c0,0x5a05dea6},
        {0x113fd505,0x06e65535,0x5ad8b6d4}, {0x11681427,0x06f66e76,0x5bacadfa},
        {0x119089da,0x07069d8a,0x5c81c488}, {0x11b93635,0x0716e27b,0x5d57faec},
        {0x11e2194b,0x07273d51,0x5e2f5196}, {0x120b3333,0x0737ae14,0x5f07c8f3},
    };
#endif

#ifdef USE_FLOATS
    static void lab(double r, double g, double b, double *L, double *A, double *B) {
        double x, y, z;
        r /= 255.0f;
        g /= 255.0f;
        b /= 255.0f;

        if (r > 0.04045f) r = pow(((r + 0.055f) / 1.055f), 2.4f);
        else r /= 12.92f;
        if (g > 0.04045f) g = pow(((g + 0.055f) / 1.055f), 2.4f);
        else g /= 12.92f;
        if (b > 0.04045f) b = pow(((b + 0.055f) / 1.055f), 2.4f);
        else b /= 12.92f;

        r *= 100.0f;
        g *= 100.0f;
        b *= 100.0f;

        x = r * 0.4124f + g * 0.3576f + b * 0.1805f;
        y = r * 0.2126f + g * 0.7152f + b * 0.0722f;
        z = r * 0.0193f + g * 0.1192f + b * 0.9505f;

        x /= 95.047f;
        y /= 100.000f;
        z /= 108.883f;

        if (x > 0.008856f) x = pow(x, 1.0f/3.0f);
        else x = (7.787f * x) + (16.0f / 116.0f);
        if (y > 0.008856f) y = pow(y, (1.0f/3.0f));
        else y = (7.787f * y) + (16.0f / 116.0f);
        if (z > 0.008856f) z = pow(z, (1.0f/3.0f));
        else z = (7.787f * z) + (16.0f / 116.0f);

        *L = (116.0f * y) - 16.0f;
        *A = 500.0f * (x - y);
        *B = 200.0f * (y - z);
    }
    
    static double labdiff(unsigned int rgb) {
        unsigned int r, g, b;
        const double L1 = 53.192777691077211f, A1 = 0.0031420942181448197f, B1 = -0.0062075877844014471f;
        double L2, A2, B2;

        r = (rgb>>16) & 0xff;
        g = (rgb>>8) & 0xff;
        b = rgb & 0xff;

        lab(r, g, b, &L2, &A2, &B2);

        return sqrt(pow(L1 - L2, 2.0f) + pow(A1 - A2, 2.0f) + pow(B1 - B2, 2.0f));
    }
#else
    static void lab2(uint32_t r, uint32_t g, uint32_t b, int32_t *L, int32_t *A, int32_t *B) {
        uint32_t xx,yy,zz;

        xx = rtable[r][0] + gtable[g][0] + btable[b][0];
        yy = rtable[r][1] + gtable[g][1] + btable[b][1];
        zz = rtable[r][2] + gtable[g][2] + btable[b][2];
        if (xx > 148587) {
        xx = (1<<24)*pow(xx/(95.047*(1<<24)), 1.0/3.0);
        }
        else {
        xx = xx * 24389/3132 + 2314099;
        }
        if (yy > 148587) {
        yy = (1<<24)*pow(yy/(100.0*(1<<24)), 1.0/3.0);
        }
        else {
        yy = yy * 24389/3132 + 2314099;
        }
        if (zz > 148587) {
        zz = (1<<24)*pow(zz/(108.883*(1<<24)), 1.0/3.0);
        }
        else {
        zz = zz * 24389/3132 + 2314099;
        }
        *L = (116*yy - 116*2314099);
        *A = 500/4*(xx - yy);
        *B = 200/4*(yy - zz);/* /4 to avoid overflow */
    }
    static uint32_t labdiff2(unsigned int b) {
        unsigned int r2, g2, b2;
        int32_t L1, A1, B1, L2, A2, B2;
        int64_t ld,ad,bd;

        r2 = (b>>16) & 0xff;
        g2 = (b>>8) & 0xff;
        b2 = b & 0xff;

        /* ref = 0x7f7f7f -> L*a*b ~ (53,0,0) */
        L1 = 53*(1<<24);
        A1 = 0;
        B1 = 0;
        lab2(r2, g2, b2, &L2, &A2, &B2);
        ld = L1 - L2;
        ld *= ld;
        ad = A1 - A2;
        ad *= ad;
        bd = B1 - B2;
        bd *= bd;
        ld += ad + bd;
        return ((uint32_t)(sqrt(ld/1024.0)))>>17;
    }
#endif

    static void makebmp(const char *step, const char *tempd, int w, int h, void *data)
    {
        unsigned int tmp1 = 0, tmp2 = 0, tmp3 = 0, tmp4 = 0, y;
        char *fname;
        FILE *f;

        if (!tempd)
            return;
        if (!(fname = cli_gentemp(tempd)))
            return;
        if (!(f = fopen(fname, "wb")))
        {
            cli_unlink(fname);
            cli_dbgmsg("makebmp: failed to create file %s\n", fname);
            free(fname);
            return;
        }
        cli_writeint32(&tmp1, 0x28 + 0xe + w * h * 4);
        cli_writeint32(&tmp2, (32 << 16) | 1);
        tmp3 = 0;
        cli_writeint32(&tmp4, w * h * 4);
        if (!fwrite("BM", 2, 1, f) ||
            !fwrite(&tmp1, 4, 1, f) ||
            !fwrite("aCaB\x36\x00\x00\x00\x28\x00\x00\x00", 12, 1, f) ||
            !fwrite(&w, 4, 1, f) ||
            !fwrite(&h, 4, 1, f) ||
            !fwrite(&tmp2, 4, 1, f) ||
            !fwrite(&tmp3, 4, 1, f) ||
            !fwrite(&tmp4, 4, 1, f) ||
            !fwrite("\1\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0", 16, 1, f))
        {
            fclose(f);
            cli_unlink(fname);
            free(fname);
            cli_dbgmsg("makebmp: failed to write output\n");
            return;
        }

        for (y = h - 1; y < (unsigned int)h; y--)
#if WORDS_BIGENDIAN == 0
            if (!fwrite(&((unsigned int *)data)[y * w], w * 4, 1, f))
                break;
#else
        {
            int x;
            for (x = 0; x < w; x++)
            {
                cli_writeint32(&tmp1, ((unsigned int *)data)[y * w]);
                if (!fwrite(&tmp1, 4, 1, f))
                    break;
            }
            if (x != w)
                break;
        }
#endif
        fclose(f);
        if (y < (unsigned int)h)
            cli_unlink(fname);
        else
            cli_dbgmsg("makebmp: Image %s dumped to %s\n", step, fname);
        free(fname);
    }

    static unsigned int matchpoint(unsigned int side, unsigned int *x1, unsigned int *y1, unsigned int *avg1, const unsigned int *x2, const unsigned int *y2, const unsigned int *avg2, unsigned int max)
    {
        unsigned int i, j, best, match = 0, ksize = side / 4;

        for (i = 0; i < 3; i++)
        {
            best = 0;
            for (j = 0; j < 3; j++)
            {
                /* approximately measure the distance from the best matching reference - avoid N*N total war */
                int diffx = (int)x1[i] - (int)x2[j];
                int diffy = ((int)y1[i] - (int)y2[j]);
                unsigned int diff = sqrt(diffx * diffx + diffy * diffy);
                if (diff > ksize * 3 / 4 || (unsigned int)abs((int)avg1[i] - (int)avg2[j]) > max / 5)
                    continue;

                diff = 100 - diff * 60 / (ksize * 3 / 4);
                if (diff > best)
                    best = diff;
            }
            match += best;
        }
        return match / 3;
    }

    static unsigned int matchbwpoint(unsigned int side, unsigned int *x1a, unsigned int *y1a, unsigned int *avg1a, unsigned int *x1b, unsigned int *y1b, unsigned int *avg1b, const unsigned int *x2a, const unsigned int *y2a, const unsigned int *avg2a, const unsigned int *x2b, const unsigned int *y2b, const unsigned int *avg2b)
    {
        unsigned int i, j, best, match = 0, ksize = side / 4;
        unsigned int x1[6], y1[6], avg1[6], x2[6], y2[6], avg2[6];

        for (i = 0; i < 3; i++)
        {
            x1[i] = x1a[i];
            y1[i] = y1a[i];
            avg1[i] = avg1a[i];
            x2[i] = x2a[i];
            y2[i] = y2a[i];
            avg2[i] = avg2a[i];

            x1[i + 3] = x1b[i];
            y1[i + 3] = y1b[i];
            avg1[i + 3] = avg1b[i];
            x2[i + 3] = x2b[i];
            y2[i + 3] = y2b[i];
            avg2[i + 3] = avg2b[i];
        }

        for (i = 0; i < 6; i++)
        {
            best = 0;
            for (j = 0; j < 6; j++)
            {
                /* approximately measure the distance from the best matching reference - avoid N*N total war */
                int diffx = (int)x1[i] - (int)x2[j];
                int diffy = ((int)y1[i] - (int)y2[j]);
                unsigned int diff = sqrt(diffx * diffx + diffy * diffy);
                if (diff > ksize * 3 / 4 || (unsigned int)abs((int)avg1[i] - (int)avg2[j]) > 255 / 5)
                    continue;

                diff = 100 - diff * 60 / (ksize * 3 / 4);
                if (diff > best)
                    best = diff;
            }
            match += best;
        }
        return match / 6;
    }

    static void hsv(unsigned int c, unsigned int *r, unsigned int *g, unsigned int *b, unsigned int *s, unsigned int *v, unsigned int *delta)
    {
        unsigned int min, max;
        *r = (c >> 16) & 0xff;
        *g = (c >> 8) & 0xff;
        *b = c & 0xff;
        min = MIN(*r, MIN(*g, *b));
        max = MAX(*r, MAX(*g, *b));
        *v = max;
        *delta = max - min;
        if (!*delta)
            *s = 0;
        else
            *s = 255 * (*delta) / max;
    }

    static int getmetrics(unsigned int side, unsigned int *imagedata, struct icomtr *res, const char *tempd)
    {
        unsigned int x, y, xk, yk, i, j, *tmp;
        unsigned int ksize = side / 4, bwonly = 0;
        unsigned int edge_avg[6], edge_x[6] = {0, 0, 0, 0, 0, 0}, edge_y[6] = {0, 0, 0, 0, 0, 0}, noedge_avg[6], noedge_x[6] = {0, 0, 0, 0, 0, 0}, noedge_y[6] = {0, 0, 0, 0, 0, 0};
        double *sobel;

        if (!(tmp = cli_malloc(side * side * 4 * 2)))
        {
            cli_errmsg("getmetrics: Unable to allocate memory for tmp %u\n", (side * side * 4 * 2));
            return CL_EMEM;
        }

        memset(res, 0, sizeof(*res));

        /* compute colored, gray, bright and dark areas, color presence */
        for (y = 0; y <= side - ksize; y++)
        {
            for (x = 0; x <= side - ksize; x++)
            {
                unsigned int colsum = 0, lightsum = 0;
                unsigned int r, g, b, s, v, delta;

                if (x == 0 && y == 0)
                {
                    /* Here we handle the 1st window which is fully calculated */
                    for (yk = 0; yk < ksize; yk++)
                    {
                        for (xk = 0; xk < ksize; xk++)
                        {
                            hsv(imagedata[yk * side + xk], &r, &g, &b, &s, &v, &delta);
                            colsum += (unsigned int)sqrt(s * s * v);
                            lightsum += v;

                            /* count colors (full square) */
                            if (s > 85 && v > 85)
                            {
                                res->ccount++;
                                res->rsum += 100 - 100 * abs((int)g - (int)b) / delta;
                                res->gsum += 100 - 100 * abs((int)r - (int)b) / delta;
                                res->bsum += 100 - 100 * abs((int)r - (int)g) / delta;
                            }
                        }
                    }
                }
                else if (x)
                { /* Here we incrementally calculate rows and columns
                  code is split as gcc produces faster code this way */
                    colsum = tmp[y * side + x - 1];
                    lightsum = tmp[side * side + y * side + x - 1];
                    for (yk = 0; yk < ksize; yk++)
                    {
                        /* remove previous column */
                        hsv(imagedata[(y + yk) * side + x - 1], &r, &g, &b, &s, &v, &delta);
                        colsum -= (unsigned int)sqrt(s * s * v);
                        lightsum -= v;
                        /* add next column */
                        hsv(imagedata[(y + yk) * side + x + ksize - 1], &r, &g, &b, &s, &v, &delta);
                        colsum += (unsigned int)sqrt(s * s * v);
                        lightsum += v;

                        /* count colors (full column or only the last px) */
                        if ((y == 0 || yk == ksize - 1) && s > 85 && v > 85)
                        {
                            res->ccount++;
                            res->rsum += 100 - 100 * abs((int)g - (int)b) / delta;
                            res->gsum += 100 - 100 * abs((int)r - (int)b) / delta;
                            res->bsum += 100 - 100 * abs((int)r - (int)g) / delta;
                        }
                    }
                }
                else
                {
                    colsum = tmp[(y - 1) * side];
                    lightsum = tmp[side * side + (y - 1) * side];
                    for (xk = 0; xk < ksize; xk++)
                    {
                        /* remove previous row */
                        hsv(imagedata[(y - 1) * side + xk], &r, &g, &b, &s, &v, &delta);
                        colsum -= (unsigned int)sqrt(s * s * v);
                        lightsum -= v;

                        /* add next row */
                        hsv(imagedata[(y + ksize - 1) * side + xk], &r, &g, &b, &s, &v, &delta);
                        colsum += (unsigned int)sqrt(s * s * v);
                        lightsum += v;

                        /* count colors (full row) */
                        if (s > 85 && v > 85)
                        {
                            res->ccount++;
                            res->rsum += 100 - 100 * abs((int)g - (int)b) / delta;
                            res->gsum += 100 - 100 * abs((int)r - (int)b) / delta;
                            res->bsum += 100 - 100 * abs((int)r - (int)g) / delta;
                        }
                    }
                }
                tmp[y * side + x] = colsum;
                tmp[side * side + y * side + x] = lightsum;
            }
        }

        /* extract top 3 non overlapping areas for: colored, gray, bright and dark areas, color presence */
        for (i = 0; i < 3; i++)
        {
            res->gray_avg[i] = 0xffffffff;
            res->dark_avg[i] = 0xffffffff;
            for (y = 0; y < side - ksize; y++)
            {
                for (x = 0; x < side - 1 - ksize; x++)
                {
                    unsigned int colsum = tmp[y * side + x], lightsum = tmp[side * side + y * side + x];

                    if (colsum > res->color_avg[i])
                    {
                        for (j = 0; j < i; j++)
                        {
                            if (x + ksize > res->color_x[j] && x < res->color_x[j] + ksize &&
                                y + ksize > res->color_y[j] && y < res->color_y[j] + ksize)
                                break;
                        }
                        if (j == i)
                        {
                            res->color_avg[i] = colsum;
                            res->color_x[i] = x;
                            res->color_y[i] = y;
                        }
                    }
                    if (colsum < res->gray_avg[i])
                    {
                        for (j = 0; j < i; j++)
                        {
                            if (x + ksize > res->gray_x[j] && x < res->gray_x[j] + ksize &&
                                y + ksize > res->gray_y[j] && y < res->gray_y[j] + ksize)
                                break;
                        }
                        if (j == i)
                        {
                            res->gray_avg[i] = colsum;
                            res->gray_x[i] = x;
                            res->gray_y[i] = y;
                        }
                    }
                    if (lightsum > res->bright_avg[i])
                    {
                        for (j = 0; j < i; j++)
                        {
                            if (x + ksize > res->bright_x[j] && x < res->bright_x[j] + ksize &&
                                y + ksize > res->bright_y[j] && y < res->bright_y[j] + ksize)
                                break;
                        }
                        if (j == i)
                        {
                            res->bright_avg[i] = lightsum;
                            res->bright_x[i] = x;
                            res->bright_y[i] = y;
                        }
                    }
                    if (lightsum < res->dark_avg[i])
                    {
                        for (j = 0; j < i; j++)
                        {
                            if (x + ksize > res->dark_x[j] && x < res->dark_x[j] + ksize &&
                                y + ksize > res->dark_y[j] && y < res->dark_y[j] + ksize)
                                break;
                        }
                        if (j == i)
                        {
                            res->dark_avg[i] = lightsum;
                            res->dark_x[i] = x;
                            res->dark_y[i] = y;
                        }
                    }
                }
            }
        }

        /* abs->avg */
        for (i = 0; i < 3; i++)
        {
            res->color_avg[i] /= ksize * ksize;
            res->gray_avg[i] /= ksize * ksize;
            res->bright_avg[i] /= ksize * ksize;
            res->dark_avg[i] /= ksize * ksize;
        }

        if (res->ccount * 100 / side / side > 5)
        {
            res->rsum /= res->ccount;
            res->gsum /= res->ccount;
            res->bsum /= res->ccount;
            res->ccount = res->ccount * 100 / side / side;
        }
        else
        {
            res->ccount = 0;
            res->rsum = 0;
            res->gsum = 0;
            res->bsum = 0;
            bwonly = 1;
        }

        /* Edge detection - Sobel */

        /* Sobel 1 - gradients */
        i = 0;
#ifdef USE_FLOATS
        sobel = cli_malloc(side * side * sizeof(double));
        if (!sobel)
        {
            cli_errmsg("getmetrics: Unable to allocate memory for edge detection %llu\n", (long long unsigned)(side * side * sizeof(double)));
            free(tmp);
            return CL_EMEM;
        }
#else
#define sobel imagedata
#endif
        for (y = 0; y < side; y++)
        {
            for (x = 0; x < side; x++)
            {
                sobel[y * side + x] = LABDIFF(imagedata[y * side + x]);
            }
        }
        for (y = 1; y < side - 1; y++)
        {
            for (x = 1; x < side - 1; x++)
            {
                unsigned int sob;
#ifdef USE_FLOATS
                double gx, gy;
#else
                unsigned int gx, gy;
#endif

                /* X matrix */
                gx = sobel[(y - 1) * side + (x - 1)];
                gx += sobel[(y + 0) * side + (x - 1)] * 2;
                gx += sobel[(y + 1) * side + (x - 1)];
                gx -= sobel[(y - 1) * side + (x + 1)];
                gx -= sobel[(y + 0) * side + (x + 1)] * 2;
                gx -= sobel[(y + 1) * side + (x + 1)];

                /* Y matrix */
                gy = sobel[(y - 1) * side + (x - 1)];
                gy += sobel[(y - 1) * side + (x + 0)] * 2;
                gy += sobel[(y - 1) * side + (x + 1)];
                gy -= sobel[(y + 1) * side + (x - 1)];
                gy -= sobel[(y + 1) * side + (x + 0)] * 2;
                gy -= sobel[(y + 1) * side + (x + 1)];

                sob = (int)sqrt(gx * gx + gy * gy);
                tmp[y * side + x] = sob;
                if (sob > i)
                    i = sob;
            }
        }
#ifdef USE_FLOATS
        free(sobel);
#endif

        /* Sobel 2 - norm to max */
        if (i)
        {
            for (y = 1; y < side - 1; y++)
            {
                for (x = 1; x < side - 1; x++)
                {
                    unsigned int c = tmp[y * side + x];
                    c = c * 255 / i;
                    imagedata[y * side + x] = 0xff000000 | c | (c << 8) | (c << 16);
                }
            }
        }

        /* black borders */
        for (x = 0; x < side; x++)
        {
            imagedata[x] = 0xff000000;
            imagedata[(side - 1) * side + x] = 0xff000000;
        }
        for (y = 0; y < side; y++)
        {
            imagedata[y * side] = 0xff000000;
            imagedata[y * side + side - 1] = 0xff000000;
        }
        makebmp("3-edge", tempd, side, side, imagedata);

        /* gaussian blur */
        for (y = 1; y < side - 1; y++)
        {
            for (x = 1; x < side - 1; x++)
            {
                unsigned int sum = 0, tot = 0;
                int disp;
                for (disp = -MIN((int)x, gkernsz / 2); disp <= MIN((int)(side - 1 - x), gkernsz / 2); disp++)
                {
                    unsigned int c = imagedata[y * side + x + disp] & 0xff;
                    sum += c * gaussk[disp + gkernsz / 2];
                    tot += gaussk[disp + gkernsz / 2];
                }
                sum /= tot;
                imagedata[y * side + x] &= 0xff;
                imagedata[y * side + x] |= sum << 8;
            }
        }
        i = 0;
        for (y = 1; y < side - 1; y++)
        {
            for (x = 1; x < side - 1; x++)
            {
                unsigned int sum = 0, tot = 0;
                int disp;
                for (disp = -MIN((int)y, gkernsz / 2); disp <= MIN((int)(side - 1 - y), gkernsz / 2); disp++)
                {
                    unsigned int c = (imagedata[(y + disp) * side + x] >> 8) & 0xff;
                    sum += c * gaussk[disp + gkernsz / 2];
                    tot += gaussk[disp + gkernsz / 2];
                }
                sum /= tot;
                if (sum > i)
                    i = sum;
                imagedata[y * side + x] = 0xff000000 | sum | (sum << 8) | (sum << 16);
            }
        }
        makebmp("4-gauss", tempd, side, side, imagedata);

        /* calculate edges */
        for (y = 0; y <= side - ksize; y++)
        {
            for (x = 0; x <= side - 1 - ksize; x++)
            {
                unsigned int sum = 0;

                if (x == 0 && y == 0)
                { /* 1st windows */
                    for (yk = 0; yk < ksize; yk++)
                    {
                        for (xk = 0; xk < ksize; xk++)
                            sum += imagedata[(y + yk) * side + x + xk] & 0xff;
                    }
                }
                else if (x)
                { /* next column */
                    sum = tmp[y * side + x - 1];
                    for (yk = 0; yk < ksize; yk++)
                    {
                        sum -= imagedata[(y + yk) * side + x - 1] & 0xff;
                        sum += imagedata[(y + yk) * side + x + ksize - 1] & 0xff;
                    }
                }
                else
                { /* next row */
                    sum = tmp[(y - 1) * side];
                    for (xk = 0; xk < ksize; xk++)
                    {
                        sum -= imagedata[(y - 1) * side + xk] & 0xff;
                        sum += imagedata[(y + ksize - 1) * side + xk] & 0xff;
                    }
                }
                tmp[y * side + x] = sum;
            }
        }

        /* calculate best and worst 3 (or 6) edged areas */
        for (i = 0; i < 3 * (bwonly + 1); i++)
        {
            edge_avg[i] = 0;
            noedge_avg[i] = 0xffffffff;
            for (y = 0; y < side - ksize; y++)
            {
                for (x = 0; x < side - 1 - ksize; x++)
                {
                    unsigned int sum = tmp[y * side + x];

                    if (sum > edge_avg[i])
                    {
                        for (j = 0; j < i; j++)
                        {
                            if (x + ksize > edge_x[j] && x < edge_x[j] + ksize &&
                                y + ksize > edge_y[j] && y < edge_y[j] + ksize)
                                break;
                        }
                        if (j == i)
                        {
                            edge_avg[i] = sum;
                            edge_x[i] = x;
                            edge_y[i] = y;
                        }
                    }
                    if (sum < noedge_avg[i])
                    {
                        for (j = 0; j < i; j++)
                        {
                            if (x + ksize > noedge_x[j] && x < noedge_x[j] + ksize &&
                                y + ksize > noedge_y[j] && y < noedge_y[j] + ksize)
                                break;
                        }
                        if (j == i)
                        {
                            noedge_avg[i] = sum;
                            noedge_x[i] = x;
                            noedge_y[i] = y;
                        }
                    }
                }
            }
        }

        free(tmp);

        /* abs->avg */
        for (i = 0; i < 3; i++)
        {
            res->edge_avg[i] = edge_avg[i] / ksize / ksize;
            res->edge_x[i] = edge_x[i];
            res->edge_y[i] = edge_y[i];
            res->noedge_avg[i] = noedge_avg[i] / ksize / ksize;
            res->noedge_x[i] = noedge_x[i];
            res->noedge_y[i] = noedge_y[i];
        }
        if (bwonly)
        {
            for (i = 0; i < 3; i++)
            {
                res->color_avg[i] = edge_avg[i + 3] / ksize / ksize;
                res->color_x[i] = edge_x[i + 3];
                res->color_y[i] = edge_y[i + 3];
                res->gray_avg[i] = noedge_avg[i + 3] / ksize / ksize;
                res->gray_x[i] = edge_x[i + 3];
                res->gray_y[i] = edge_y[i + 3];
            }
        }

        cli_dbgmsg("edge areas: %u@(%u,%u) %u@(%u,%u) %u@(%u,%u)\n", res->edge_avg[0], res->edge_x[0], res->edge_y[0], res->edge_avg[1], res->edge_x[1], res->edge_y[1], res->edge_avg[2], res->edge_x[2], res->edge_y[2]);
        cli_dbgmsg("noedge areas: %u@(%u,%u) %u@(%u,%u) %u@(%u,%u)\n", res->noedge_avg[0], res->noedge_x[0], res->noedge_y[0], res->noedge_avg[1], res->noedge_x[1], res->noedge_y[1], res->noedge_avg[2], res->noedge_x[2], res->noedge_y[2]);
        cli_dbgmsg("%s areas: %u@(%u,%u) %u@(%u,%u) %u@(%u,%u)\n", bwonly ? "edge(2nd)" : "color", res->color_avg[0], res->color_x[0], res->color_y[0], res->color_avg[1], res->color_x[1], res->color_y[1], res->color_avg[2], res->color_x[2], res->color_y[2]);
        cli_dbgmsg("%s areas: %u@(%u,%u) %u@(%u,%u) %u@(%u,%u)\n", bwonly ? "noedge(2nd)" : "gray", res->gray_avg[0], res->gray_x[0], res->gray_y[0], res->gray_avg[1], res->gray_x[1], res->gray_y[1], res->gray_avg[2], res->gray_x[2], res->gray_y[2]);
        cli_dbgmsg("bright areas: %u@(%u,%u) %u@(%u,%u) %u@(%u,%u)\n", res->bright_avg[0], res->bright_x[0], res->bright_y[0], res->bright_avg[1], res->bright_x[1], res->bright_y[1], res->bright_avg[2], res->bright_x[2], res->bright_y[2]);
        cli_dbgmsg("dark areas: %u@(%u,%u) %u@(%u,%u) %u@(%u,%u)\n", res->dark_avg[0], res->dark_x[0], res->dark_y[0], res->dark_avg[1], res->dark_x[1], res->dark_y[1], res->dark_avg[2], res->dark_x[2], res->dark_y[2]);
        if (!bwonly)
            cli_dbgmsg("color spread: %u,%u,%u %u%%\n", res->rsum, res->gsum, res->bsum, res->ccount);

        if (cli_debug_flag)
        {
#define ICOSIGSZ (2 + (3 + 2 + 2) * 3 * 2 + (2 + 2 + 2) * 3 * 4 + 2 + 2 + 2 + 2)
            char mstr[ICOSIGSZ + 1], *ptr = mstr;

            sprintf(ptr, "%02x", side);
            ptr += 2;
            for (i = 0; i < 3; i++)
            {
                sprintf(ptr, "%03x", res->color_avg[i]);
                ptr += 3;
                sprintf(ptr, "%02x", res->color_x[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->color_y[i]);
                ptr += 2;
            }
            for (i = 0; i < 3; i++)
            {
                sprintf(ptr, "%03x", res->gray_avg[i]);
                ptr += 3;
                sprintf(ptr, "%02x", res->gray_x[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->gray_y[i]);
                ptr += 2;
            }
            for (i = 0; i < 3; i++)
            {
                sprintf(ptr, "%02x", res->bright_avg[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->bright_x[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->bright_y[i]);
                ptr += 2;
            }
            for (i = 0; i < 3; i++)
            {
                sprintf(ptr, "%02x", res->dark_avg[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->dark_x[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->dark_y[i]);
                ptr += 2;
            }
            for (i = 0; i < 3; i++)
            {
                sprintf(ptr, "%02x", res->edge_avg[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->edge_x[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->edge_y[i]);
                ptr += 2;
            }
            for (i = 0; i < 3; i++)
            {
                sprintf(ptr, "%02x", res->noedge_avg[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->noedge_x[i]);
                ptr += 2;
                sprintf(ptr, "%02x", res->noedge_y[i]);
                ptr += 2;
            }
            sprintf(ptr, "%02x", res->rsum);
            ptr += 2;
            sprintf(ptr, "%02x", res->gsum);
            ptr += 2;
            sprintf(ptr, "%02x", res->bsum);
            ptr += 2;
            sprintf(ptr, "%02x", res->ccount);
            cli_dbgmsg("IDB SIGNATURE: ICON_NAME:GROUP1:GROUP2:%s\n", mstr);
        }

        return CL_CLEAN;
    }

    static int parseicon(struct ICON_ENV *icon_env, uint32_t rva)
    {
        icon_groupset *set = icon_env->set;
        cli_ctx *ctx = icon_env->ctx;
        struct cli_exe_section *exe_sections = icon_env->exe_sections;
        uint16_t nsections = icon_env->nsections;
        uint32_t hdr_size = icon_env->hdr_size;

        struct
        {
            unsigned int sz;
            unsigned int w;
            unsigned int h;
            unsigned short planes;
            unsigned short depth;
            unsigned int comp;
            unsigned int imagesize;
            unsigned int dpix;
            unsigned int dpiy;
            unsigned int used;
            unsigned int important;
        } bmphdr;

        struct icomtr metrics;
        const unsigned char *rawimage;
        const char *tempd;
        const uint32_t *palette = NULL;
        uint32_t *imagedata;
        unsigned int scanlinesz, andlinesz;
        unsigned int width, height, depth, x, y;
        unsigned int err, scalemode = 2, enginesize;
        fmap_t *map;
        uint32_t icoff;
        struct icon_matcher *matcher;
        unsigned int special_32_is_32 = 0;

        if (!ctx || !ctx->engine || !(matcher = ctx->engine->iconcheck))
            return CL_SUCCESS;
        map = *ctx->fmap;
        tempd = (cli_debug_flag && ctx->engine->keeptmp) ? (ctx->engine->tmpdir ? ctx->engine->tmpdir : cli_gettmpdir()) : NULL;
        icoff = cli_rawaddr(rva, exe_sections, nsections, &err, map->len, hdr_size);

        /* read the bitmap header */
        if (err || !(rawimage = fmap_need_off_once(map, icoff, 4)))
        {
            icon_env->err_oof++;
            //cli_dbgmsg("parseicon: offset to icon is out of file\n");
            return CL_SUCCESS;
        }

        rva = cli_readint32(rawimage);
        icoff = cli_rawaddr(rva, exe_sections, nsections, &err, map->len, hdr_size);
        if (err || fmap_readn(map, &bmphdr, icoff, sizeof(bmphdr)) != sizeof(bmphdr))
        {
            icon_env->err_bhoof++;
            //cli_dbgmsg("parseicon: bmp header is out of file\n");
            return CL_SUCCESS;
        }

        if ((size_t)READ32(bmphdr.sz) < sizeof(bmphdr))
        {
            icon_env->err_bhts++;
            //cli_dbgmsg("parseicon: BMP header too small\n");
            return CL_SUCCESS;
        }

        /* seek to the end of v4/v5 header */
        icoff += READ32(bmphdr.sz);

        width = READ32(bmphdr.w);
        height = READ32(bmphdr.h) / 2;
        depth = READ16(bmphdr.depth);
        if (width > 256 || height > 256 || width < 16 || height < 16)
        {
            icon_env->err_tstl++;
            //cli_dbgmsg("parseicon: Image too small or too big (%ux%u)\n", width, height);
            return CL_SUCCESS;
        }
        if (width < height * 3 / 4 || height < width * 3 / 4)
        {
            icon_env->err_insl++;
            //cli_dbgmsg("parseicon: Image not square enough (%ux%u)\n", width, height);
            return CL_SUCCESS;
        }

        /* scaling logic */
        if (width == height)
        {
            if (width == 16 || width == 24 || width == 32)
                scalemode = 0;
            else if (!(width % 32) || !(width % 24))
                scalemode = 1;
            else
                scalemode = 2;
        }

        cli_dbgmsg("parseicon: Bitmap - %ux%ux%u\n", width, height, depth);

        /* check color depth and load palette */
        switch (depth)
        {
        default:
        case 0:
            /* PNG OR JPEG */
            cli_dbgmsg("parseicon: PNG icons are not yet sported\n");
            return CL_SUCCESS;
        case 1:
        case 4:
        case 8:
            /* HAVE PALETTE */
            if (!(palette = fmap_need_off(map, icoff, (1 << depth) * sizeof(int))))
                return CL_SUCCESS;
            icoff += (1 << depth) * sizeof(int);
            /* for(j=0; j<pcolcnt; j++) */
            /* cli_dbgmsg("Palette[%u] = %08x\n", j, palette[j]); */
            break;
        case 16:
        case 24:
        case 32:
            /* NO PALETTE */
            break;
        }

        /* compute line sizes */
        scanlinesz = 4 * (width * depth / 32) + 4 * (width * depth % 32 != 0);
        andlinesz = ((depth & 0x1f) != 0) * (4 * (width / 32) + 4 * (width % 32 != 0));

        /* read the raw image */

        if (!(rawimage = fmap_need_off_once(map, icoff, height * (scanlinesz + andlinesz))))
        {
            if (palette)
                fmap_unneed_ptr(map, palette, (1 << depth) * sizeof(int));
            return CL_SUCCESS;
        }
        if (!(imagedata = cli_malloc(width * height * sizeof(*imagedata))))
        {
            if (palette)
                fmap_unneed_ptr(map, palette, (1 << depth) * sizeof(int));
            return CL_SUCCESS;
        }

        /* decode the image to an RGBA array */
        for (y = 0; y < height; y++)
        {
            unsigned int x_off = y * scanlinesz;
            switch (depth)
            {
            case 1:
            case 4:
            case 8:
            {
                unsigned int have = 0;
                unsigned char c = 0; // will be set in first loop
                for (x = 0; x < width; x++)
                {
                    if (!have)
                    {
                        c = rawimage[x_off++];
                        have = 8;
                    }
                    have -= depth;
                    imagedata[(height - 1 - y) * width + x] = READ32(palette[(c >> have) & ((1 << depth) - 1)]);
                }
                break;
            }
            case 16:
            {
                for (x = 0; x < width; x++)
                {
                    unsigned int b = (rawimage[x_off] & 0x1f);
                    unsigned int g = ((rawimage[x_off] >> 5) | ((rawimage[x_off + 1] & 0x3) << 3));
                    unsigned int r = (rawimage[x_off + 1] & 0xfc);
                    b = (b << 3) | (b >> 2);
                    g = ((g << 3) | (g >> 2)) << 11;
                    r = ((r << 3) | (r >> 2)) << 17;
                    imagedata[(height - 1 - y) * width + x] = r | g | b;
                    x_off += 2;
                }
                break;
            }
            case 24:
                for (x = 0; x < width; x++)
                {
                    unsigned int c = rawimage[x_off] | (rawimage[x_off + 1] << 8) | (rawimage[x_off + 2] << 16);
                    imagedata[(height - 1 - y) * width + x] = c;
                    x_off += 3;
                }
                break;
            case 32:
                for (x = 0; x < width; x++)
                {
                    unsigned int a = rawimage[x_off + 3] << 24;
                    imagedata[(height - 1 - y) * width + x] = rawimage[x_off] | (rawimage[x_off + 1] << 8) | (rawimage[x_off + 2] << 16) | a;
                    special_32_is_32 |= a;
                    x_off += 4;
                }
                break;
            }
        }

        if (palette)
            fmap_unneed_ptr(map, palette, (1 << depth) * sizeof(int));
        makebmp("0-noalpha", tempd, width, height, imagedata);

        if (depth == 32 && !special_32_is_32)
        { /* Sometimes it really is 24. Exploited live - see sample 0013839101 */
            andlinesz = 4 * (width / 32) + 4 * (width % 32 != 0);
            if (!(rawimage = fmap_need_off_once(map, icoff + height * scanlinesz, height * andlinesz)))
            {
                /* Likely a broken sample - 32bit icon with 24bit data and a broken mask:
           i could really break out here but i've got the full image, so i'm just forcing full alpha
           Found in samples: 0008777448, 0009116157, 0009116157 */
                for (y = 0; y < height; y++)
                    for (x = 0; x < width; x++)
                        imagedata[y * width + x] |= 0xff000000;
                special_32_is_32 = 1;
                cli_dbgmsg("parseicon: found a broken and stupid icon\n");
            }
            else
                cli_dbgmsg("parseicon: found a stupid icon\n");
        }
        else
            rawimage += height * scanlinesz;

        /* Set alpha on or off based on the mask */
        if ((depth & 0x1f) || !special_32_is_32)
        {
            for (y = 0; y < height; y++)
            {
                unsigned int x_off = y * andlinesz;
                unsigned int have = 0;
                unsigned char c = 0; // will be set in first loop
                for (x = 0; x < width; x++)
                {
                    if (!have)
                    {
                        c = rawimage[x_off++];
                        have = 8;
                    }
                    have--;
                    imagedata[(height - 1 - y) * width + x] |= (!((c >> have) & 1)) * 0xff000000;
                }
            }
        }
        makebmp("1-alpha-mask", tempd, width, height, imagedata);

        /* Blend alpha */
        for (y = 0; y < height; y++)
        {
            for (x = 0; x < width; x++)
            {
                unsigned int r, g, b, a;
                unsigned int c = imagedata[y * width + x];
                a = c >> 24;
                r = (c >> 16) & 0xff;
                g = (c >> 8) & 0xff;
                b = c & 0xff;
                r = 0xff - a + a * r / 0xff;
                g = 0xff - a + a * g / 0xff;
                b = 0xff - a + a * b / 0xff;
                imagedata[y * width + x] = 0xff000000 | (r << 16) | (g << 8) | b;
            }
        }

        switch (scalemode)
        {
        case 0:
            break;
        case 1:
            /* Fast 50% scaler with linear gamma */
            while (width > 32)
            {
                for (y = 0; y < height; y += 2)
                {
                    for (x = 0; x < width; x += 2)
                    {
                        unsigned int c1 = imagedata[y * width + x], c2 = imagedata[y * width + x + 1], c3 = imagedata[(y + 1) * width + x], c4 = imagedata[(y + 1) * width + x + 1];
                        c1 = (((c1 ^ c2) & 0xfefefefe) >> 1) + (c1 & c2);
                        c2 = (((c3 ^ c4) & 0xfefefefe) >> 1) + (c3 & c4);
                        imagedata[y / 2 * width / 2 + x / 2] = (((c1 ^ c2) & 0xfefefefe) >> 1) + (c1 & c2);
                    }
                }
                width /= 2;
                height /= 2;
                cli_dbgmsg("parseicon: Fast scaling to %ux%u\n", width, height);
            }
            break;
        case 2:
            /* Slow up/down scale */
            {
                double scalex, scaley;
                unsigned int newsize;
                uint32_t *newdata;

                if (abs((int)width - 32) + abs((int)height - 32) < abs((int)width - 24) + abs((int)height - 24))
                    newsize = 32;
                else if (abs((int)width - 24) + abs((int)height - 24) < abs((int)width - 16) + abs((int)height - 16))
                    newsize = 24;
                else
                    newsize = 16;
                scalex = (double)width / newsize;
                scaley = (double)height / newsize;
                if (!(newdata = cli_malloc(newsize * newsize * sizeof(*newdata))))
                {
                    cli_errmsg("parseicon: Unable to allocate memory for scaling image\n");
                    return CL_EMEM;
                }
                cli_dbgmsg("parseicon: Slow scaling to %ux%u (%f, %f)\n", newsize, newsize, scalex, scaley);
                for (y = 0; y < newsize; y++)
                {
                    unsigned int oldy = (unsigned int)(y * scaley) * width;
                    for (x = 0; x < newsize; x++)
                        newdata[y * newsize + x] = imagedata[oldy + (unsigned int)(x * scalex + 0.5f)];
                }
                free(imagedata);
                height = newsize;
                width = newsize;
                imagedata = newdata;
            }
        }
        makebmp("2-alpha-blend", tempd, width, height, imagedata);

        getmetrics(width, imagedata, &metrics, tempd);
        free(imagedata);

        enginesize = (width >> 3) - 2;
        for (x = 0; x < matcher->icon_counts[enginesize]; x++)
        {
            unsigned int color = 0, gray = 0, bright, dark, edge, noedge, reds, greens, blues, ccount;
            unsigned int colors, confidence, bwmatch = 0, positivematch = 64 + 4 * (2 - enginesize);
            unsigned int i, j;

            i = matcher->icons[enginesize][x].group[0];
            j = i % 64;
            i /= 64;
            if (!(set->v[0][i] & ((uint64_t)1 << j)))
                continue;
            i = matcher->icons[enginesize][x].group[1];
            j = i % 64;
            i /= 64;
            if (!(set->v[1][i] & ((uint64_t)1 << j)))
                continue;

            if (!metrics.ccount && !matcher->icons[enginesize][x].ccount)
            {
                /* BW matching */
                edge = matchbwpoint(width, metrics.edge_x, metrics.edge_y, metrics.edge_avg, metrics.color_x, metrics.color_y, metrics.color_avg, matcher->icons[enginesize][x].edge_x, matcher->icons[enginesize][x].edge_y, matcher->icons[enginesize][x].edge_avg, matcher->icons[enginesize][x].color_x, matcher->icons[enginesize][x].color_y, matcher->icons[enginesize][x].color_avg);
                noedge = matchbwpoint(width, metrics.noedge_x, metrics.noedge_y, metrics.noedge_avg, metrics.gray_x, metrics.gray_y, metrics.gray_avg, matcher->icons[enginesize][x].noedge_x, matcher->icons[enginesize][x].noedge_y, matcher->icons[enginesize][x].noedge_avg, matcher->icons[enginesize][x].gray_x, matcher->icons[enginesize][x].gray_y, matcher->icons[enginesize][x].gray_avg);
                bwmatch = 1;
            }
            else
            {
                edge = matchpoint(width, metrics.edge_x, metrics.edge_y, metrics.edge_avg, matcher->icons[enginesize][x].edge_x, matcher->icons[enginesize][x].edge_y, matcher->icons[enginesize][x].edge_avg, 255);
                noedge = matchpoint(width, metrics.noedge_x, metrics.noedge_y, metrics.noedge_avg, matcher->icons[enginesize][x].noedge_x, matcher->icons[enginesize][x].noedge_y, matcher->icons[enginesize][x].noedge_avg, 255);
                if (metrics.ccount && matcher->icons[enginesize][x].ccount)
                {
                    /* color matching */
                    color = matchpoint(width, metrics.color_x, metrics.color_y, metrics.color_avg, matcher->icons[enginesize][x].color_x, matcher->icons[enginesize][x].color_y, matcher->icons[enginesize][x].color_avg, 4072);
                    gray = matchpoint(width, metrics.gray_x, metrics.gray_y, metrics.gray_avg, matcher->icons[enginesize][x].gray_x, matcher->icons[enginesize][x].gray_y, matcher->icons[enginesize][x].gray_avg, 4072);
                }
            }

            bright = matchpoint(width, metrics.bright_x, metrics.bright_y, metrics.bright_avg, matcher->icons[enginesize][x].bright_x, matcher->icons[enginesize][x].bright_y, matcher->icons[enginesize][x].bright_avg, 255);
            dark = matchpoint(width, metrics.dark_x, metrics.dark_y, metrics.dark_avg, matcher->icons[enginesize][x].dark_x, matcher->icons[enginesize][x].dark_y, matcher->icons[enginesize][x].dark_avg, 255);

            reds = abs((int)metrics.rsum - (int)matcher->icons[enginesize][x].rsum) * 10;
            reds = (reds < 100) * (100 - reds);
            greens = abs((int)metrics.gsum - (int)matcher->icons[enginesize][x].gsum) * 10;
            greens = (greens < 100) * (100 - greens);
            blues = abs((int)metrics.bsum - (int)matcher->icons[enginesize][x].bsum) * 10;
            blues = (blues < 100) * (100 - blues);
            ccount = abs((int)metrics.ccount - (int)matcher->icons[enginesize][x].ccount) * 10;
            ccount = (ccount < 100) * (100 - ccount);
            colors = (reds + greens + blues + ccount) / 4;

            if (bwmatch)
            {
                confidence = (bright + dark + edge * 2 + noedge) / 6;
                positivematch = 70;
            }
            else
                confidence = (color + (gray + bright + noedge) * 2 / 3 + dark + edge + colors) / 6;

#ifdef LOGPARSEICONDETAILS
            cli_dbgmsg("parseicon: edge confidence: %u%%\n", edge);
            cli_dbgmsg("parseicon: noedge confidence: %u%%\n", noedge);
            if (!bwmatch)
            {
                cli_dbgmsg("parseicon: color confidence: %u%%\n", color);
                cli_dbgmsg("parseicon: gray confidence: %u%%\n", gray);
            }
            cli_dbgmsg("parseicon: bright confidence: %u%%\n", bright);
            cli_dbgmsg("parseicon: dark confidence: %u%%\n", dark);
            if (!bwmatch)
                cli_dbgmsg("parseicon: spread confidence: red %u%%, green %u%%, blue %u%% - colors %u%%\n", reds, greens, blues, ccount);
#endif

            if (confidence >= positivematch)
            {
                cli_dbgmsg("confidence: %u\n", confidence);
                return CL_VIRUS;
            }
        }

        return CL_SUCCESS;
    }

    void cli_icongroupset_add(const char *groupname, icon_groupset *set, unsigned int type, cli_ctx *ctx)
    {
        struct icon_matcher *matcher;
        unsigned int i, j;

        if (type > 1 || !ctx || !ctx->engine || !(matcher = ctx->engine->iconcheck) || !matcher->group_counts[type])
            return;

        j = matcher->group_counts[type];
        if (groupname[0] == '*' && !groupname[1])
        {
            set->v[type][0] = set->v[type][1] = set->v[type][2] = set->v[type][3] = ~0;
            return;
        }
        for (i = 0; i < j; i++)
        {
            if (!strcmp(groupname, matcher->group_names[type][i]))
                break;
        }
        if (i == j)
            cli_dbgmsg("cli_icongroupset_add: failed to locate icon group%u %s\n", type, groupname);
        else
        {
            j = i % 64;
            i /= 64;
            set->v[type][i] |= (uint64_t)1 << j;
        }
    }
