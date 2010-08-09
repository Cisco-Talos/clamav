/*
 *  Builtin ClamAV bytecodes.
 *
 *  Copyright (C) 2010 Sourcefire, Inc.
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

#ifndef BUILTIN_BYTECODES_H
#define BUILTIN_BYTECODES_H

/* bytecode run on startup with interpreter to determine if JIT/bytecode should
 * be disabled. It also runs a minimal self-check.
 * There can only be one such bytecode, if there is none this is used as
 * fallback.
 * Usually bytecode.cvd will contain this bytecode */

static const char* builtin_bc_startup = "ClamBCafheaie`fld|afefdfggifnf```aa```|biacflfafmfbfcfmb`cnbacacmbacdcicmbgfhcachcgcbchccf``bkbaap`clamcoincidencejb:1378\n"
"\n"
"Teddaaahdabahdacahdadahdaeahdafahdagahebjfebidebifebhfebgfebffebedebefebdfebcfebadcbgab`bb`bb`bb`bb`bb`bb`bbbfbbfbbfbbfbbfbbfbbfahahahahahahahahahebgeebbfaaaaaaaab`baabb`bb`baacb`bbadb`baacb`bbheb`baacb`bb`bb`baadb`bbadb`bb`baadb`bbadbadb`bdbadahdbkaahdbbcahdbibahdb`eahdbddahdbodahdbdaahdbnbah\n"
"Ebjdaibcdbke|bcaefnfgfifnfefoedfcfofnfffoelfeffgeflf``bbdbke|bkaefnfgfifnfefoeffegnfcfdgifofnfaflfifdgigoelfeffgeflf``agble|baadfefbfeggfoe`gbgifnfdgoeegifnfdg``bcable|afdgefcgdgbc``afbme|b`adfefbfeggfoe`gbgifnfdgoecgdgbg``bhdbne|b`agfefdgoeefnffgifbgofnfmfefnfdg``aaboe|afdgefcgdgac``bidb`f|bdadfifcgafbflfefoebfigdgefcfofdfefoeifff``bjdb`f|aodfifcgafbflfefoejfifdgoeifff``\n"
"G`bha`@`b`aAa`bjfBifBkeBccBdcBmeBhcBfcB`bBdfBefBdgBefBcfBdgBefBdfBlbB`bBjdBidBdeB`bBnfBefBefBdfBcgB`bB`gBefBnfBdgBifBegBmfB`bBofBbgB`bBbfBefBdgBdgBefBbg@`bidBifBccBhcBfc@`bidBifBdcBhcBfc@`bifBbeBgeBheB`bBmfBafB`gB`gBifBnfBgfB`bBdfBefBnfBifBefBdfBnb@`bhfBneBceBedBldBifBnfBegBhgB`bBifBcgB`bB`gBbgBefBfgBefBnfBdgBifBnfBgfB`bBgbBefBhgBefBcfBmfBefBmfBgbB`bBafBcfBcfBefBcgBcgBnbAjBbeBegBnfB`bB`bBgbBcgBefBdgBcgBefBbfBofBofBlfB`bBmbB`eB`bBcfBlfBafBmfBdfBoeBegBcgBefBoeBjfBifBdgB`bBofBnfBgbBnb@`bgfBneB`eBafBheB`bBifBcgB`bB`gBbgBefBfgBefBnfBdgBifBnfBgfB`bBgbBmfB`gBbgBofBdgBefBcfBdgBgbB`bBafBcfBcfBefBcgBcgBnbAjBbeBegBnfB`bBgbB`gBafBhgBcfBdgBlfB`bBmbBcfBmfB`bBlcBefBhgBefBcfBegBdgBafBbfBlfBefBncBgb@`bffBneBbeBgeBheB`bBmfBafB`gB`gBifBnfBgfB`bBdfBefBnfBifBefBdfB`bBffBofBbgB`bBegBnfBkfBnfBofBggBnfB`bBbgBefBafBcgBofBnfBnbB`eBlfBefBafBcgBefB`bBbgBefB`gBofBbgBdgB`bBdgBofB`bBhfBdgBdgB`gBjcBobBobBbfBegBgfBcgBnbBcfBlfBafBmfBafBfgBnbBnfBefBdgAj@`bed@`befBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBefBhgBefBcfBegBdgBifBofBnfB`bBifBnfB`bBafBegBdgBofB`bBmfBofBdfBef@`bdfBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBefBhgBefBcfBegBdgBifBofBnfB`bBggBifBdgBhfB`bBifBnfBdgBefBbgB`gBbgBefBdgBefBbgB`bBofBnfBlfBig@`bcfBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBdfBifBcgBafBbfBlfBefBdf@`bad@Ab`bad@Ac`bad@Ad`bad@Ae`bad@Af`bad@Ag`bad@Ah`bad@Ai`bad@Aj`bad@Ak`bad@Al`\n"
"A`b`bLbahb`bab`babgeab`b`bad`ah`aa`bad`ah`aa`bie`bad`b`b`aa`b`b`aa`b`b`b`b`bad`ah`b`b`b`b`aa`b`b`bad`ah`aa`ah`b`b`b`b`aa`b`b`b`b`aa`b`b`b`b`bad`ah`aa`bad`ah`aa`b`b`aa`b`b`b`b`aa`aa`aa`aa`aa`b`b`b`b`b`b`ah`aa`bcd`b`b`aa`bcd`b`b`bcd`b`b`aa`b`b`aa`b`b`b`b`aa`bad`ah`b`b`aa`b`b`aa`bad`ah`b`b`b`b`bad`ah`b`b`b`b`bad`ah`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`bad`ah`b`b`b`b`bcd`b`b`b`b`b`b`bad`ah`b`b`b`b`bcd`b`b`b`b`bcd`b`b`aa`b`b`bcd`b`b`aa`b`b`bcd`b`b`aa`b`b`b`b`aa`b`b`b`b`aa`b`b`b`b`Fb`kbib\n"
"Bb`bacabbbhdabClnadbadaddbbheabBdadahaegbadaaafeaahae@aTaaafb`aaa\n"
"BbadagdbbheabB`adahahgbagaaaieaahahAaaTaaaiabae\n"
"BbieajdbbheabAidbadakdbbieaj@db`balkbakAn`Addaaameab`bal@db`b`bbAadaaTaaamadac\n"
"Bb`bankbakAo`Addaaaoeab`ban@db`baa`aaob`b`bbaaaaTbaad\n"
"Bb`bb`abbaab`ab`bbaaabcbjdAm`@db`aTbaae\n"
"BbadbbadbbheabBeadahbcagbbbab`bbda`abcab`bbeak`bdaAadaabfaeab`bbea@dTaabfaafal\n"
"Bb`bbgaabcbjdB`a`@dAadbadbhadbbheabBaadahbiagbbhaaabjaeaahbiaAjaTaabjaagb`a\n"
"Bahbkagbbbab`bbla`abkab`bbmak`blaAbdaabnaeab`bbma@dTaabnaaiah\n"
"Bb`bboaabcbjdBaa`@dAadTbab`a\n"
"Bb`bb`bk`blaAhdaababeab`bb`b@dTaababakaj\n"
"Bb`bbbbabcbjdBba`@dAadTbab`a\n"
"Bb`bbcbabcbjdBca`@dAadTbab`a\n"
"BbadbdbdbbheabBaadahbebgbbdbaabfbeaahbebAjaTaabfbanam\n"
"BbadbgbdbbheabBbadahbhbgbbgbaabibeaahbhbAfaTaabibanb`a\n"
"Bb`bbjbk`bdaB`adaabkbeab`bbjb@dTaabkbb`aao\n"
"Bb`bblbabcbjdBba`@dAadTbab`a\n"
"Bb`bbmbabcbidBda`@d@daabnbnab`bbmbAadTaabnbbdabaa\n"
"Baabobnab`bbmbAbdTaabobbcabba\n"
"Baab`ceab`bbmbAbdTaab`cbgabha\n"
"Baabaceab`bbmbAadTaabacbfabha\n"
"Baabbceab`bbmb@dTaabbcbeabha\n"
"Bb`bbccabbafBea`@dTbabha\n"
"Bb`bbdcabbafBfa`@dTbabha\n"
"Bb`bbecabbafBga`@dTbabha\n"
"Bahbfcgbadaabgceaahbfc@aTaabgcbjabia\n"
"BbcdbhcdbbheabAddb`bbicgbbhcaabjceab`bbic@db`b`bbEamjnmd`Taabjcbhbbja\n"
"BbcdbkcdbbheabAfdb`bblcgbbkcbcdbmcdbbheabAedb`bbncgbbmcaabociab`bblcbncb`b`bbEbmjnmd`Taabocbhbbka\n"
"Bb`bb`dab`bbdaabadeab`bbncb`db`b`bbEcmjnmd`Taabadblabhb\n"
"Bb`bbbdgbbkcb`bbcdab`bcdaabddeab`bbbdbcdb`b`bbEdmjnmd`Taabddbmabhb\n"
"BbadbeddbbheabAndahbfdgbbedb`bbgd`abfdaabhdlbb`bbid`abhdaabjdeab`bbgdbidb`b`bbEemjnmd`Taabjdbnabhb\n"
"BbadbkddbbheabBaadahbldgbbkdb`bbmd`abldb`bbndh`bmdBhadbadboddbbheabB`adahb`egbbodb`bbae`ab`eb`bbbeh`baeBdadbadbcedbbheabBcadahbdegbbceb`bbee`abdeb`bbfeh`beeB`adb`bbgegbbmcb`bbheh`bgeAhdb`bbiegbbkcb`bbjel`bbebndb`bbkel`bjebheb`bblel`bkebieb`bbmel`blebfeb`bbneh`bgdBladbadboedbbheabAodahb`fgbboeb`bbaf`ab`fb`bbbfh`bafBhadbcdbcfdbbheabAddb`bbdfgbbcfb`bbefl`bdfbneb`bbffl`befbbfbadbgfdbbheabBeadahbhfgbbgfb`bbif`abhfb`bbjfh`bifBhadbcdbkfdbbheabAcdb`bblfgbbkfb`bbmfl`bjfblfbcdbnfdbbheab@db`bbofgbbnfaab`geab`bbmebofTaab`gb`bboa\n"
"Bb`bbagabaagbmeTcab`bEfmjnmd\n"
"BbcdbbgdbbheabAadb`bbcggbbbgaabdgeab`bbffbcgTaabdgbbbbab\n"
"Bb`bbegabaagbffTcab`bEgmjnmd\n"
"BbcdbfgdbbheabAbdb`bbgggbbfgaabhgeab`bbmfbggTaabhgbdbbcb\n"
"Bb`bbigabaagbmfTcab`bEhmjnmd\n"
"Bb`bbjgabbaaHonnkm``odHm``oonnkdaabkgeab`bbjgHhgfedcbadTaabkgbfbbeb\n"
"Bb`bblgabaagbjgTcab`bEimjnmd\n"
"Bb`bbmgababcaDm``odaabngeab`bbmgDo``mdb`b`bbHnejkjgjmd`Taabngbhbbgb\n"
"Bb`bbogabaagbmgTcab`bF`amjnmd\n"
"Bb`bb`hbb`b`hTcab`bb`hE\n"
;
/* source-code for builtin_bc_startup: */
#if 0
const uint16_t __clambc_kind = BC_STARTUP;
int entrypoint()
{
  // Whole platform specific bugs can be disabled with check_platform,
  // see clamscan --debug for meaning of bits.
  // For example:
  //disable_jit_if("Pax mprotect on, with RWX", 0,
  //              check_platform(0x0affffff, 0xffffffff, 0x19));

  struct cli_environment env;
  get_environment(&env, sizeof(env));
  if (env.has_jit_compiled) {
    /* CPU checks */
    switch (env.arch) {
    case arch_i386:
      disable_jit_if("i[34]86 detected, JIT needs pentium or better",0,
                     !memcmp(env.cpu,"i386",4) ||
                     !memcmp(env.cpu,"i486",4));
      break;
    default:
      break;
    }

    /* RWX checks */
    if (!(env.os_features & (1 << feature_map_rwx))) {
      disable_jit_if("RWX mapping denied.", 0, 1);
      if (env.os_category == os_linux) {
        if (env.os_features & (1 << feature_selinux))
          /* all SELinux versions deny RWX mapping when policy says so */
          disable_jit_if("^SELinux is preventing 'execmem' access.\n"
                         "Run  'setsebool -P clamd_use_jit on'.", 0, 1);
        else if (env.os_features & (1 << feature_pax))
          /* recent versions of PaX deny RWX mapping */
          disable_jit_if("^PaX is preventing 'mprotect' access.\n"
                         "Run 'paxctl -cm <executable>'", 0, 1);
        else
          /* RWX mapping got denied but apparently not due to SELinux/PaX */
          disable_jit_if("^RWX mapping denied for unknown reason."
            "Please report to http://bugs.clamav.net\n", 0, 1);
      }
    } else {
      if ((env.os_category == os_linux || env.os == llvm_os_Linux) &&
          (env.os_features & (1 << feature_pax_mprotect))) {
        /* older versions of PaX allow RWX mapping but silently degrade it to RW
         * mapping and kill the program if it tries to execute. */
        disable_jit_if("^PaX is preventing 'mprotect' access.\n"
                       "Run 'paxctl -cm <executable>'", 0, 1);
      }
    }
  }
  int s = disable_bytecode_if("",0,0);
  switch (s) {
  case 0:
    debug("startup: bytecode execution in auto mode");
    break;
  case 1:
    debug("startup: bytecode execution with interpreter only");
    break;
  case 2:
    debug("startup: bytecode disabled");
    break;
  }

  /* check that the OS information is consistent */
  /* JIT == C++ code compiled */
  if (env.has_jit_compiled && !env.cpp_version) {
    return 0xdead1;
  }
  if (env.dconf_level < env.functionality_level) {
    return 0xdead2;
  }
  if (env.functionality_level != engine_functionality_level()) {
    return 0xdead3;
  }
  if (env.dconf_level != engine_dconf_level()) {
    return 0xdead4;
  }
  if (env.big_endian != __is_bigendian()) {
    return 0xdead5;
  }

  uint32_t a = (env.os_category << 24) | (env.arch << 20) |
    (env.compiler <<  16) | (env.functionality_level << 8) |
    (env.dconf_level);
  uint32_t b = (env.big_endian << 28) | (env.sizeof_ptr << 24) |
    env.cpp_version;
  uint32_t c = (env.os_features << 24) | env.c_version;
  if (a != env.platform_id_a) {
    debug_print_uint(a);
    return 0xdead6;
  }
  if (b != env.platform_id_b) {
    debug_print_uint(b);
    return 0xdead7;
  }
  if (c != env.platform_id_c) {
    debug_print_uint(c);
    return 0xdead8;
  }
  c = test1(0xf00dbeef, 0xbeeff00d);
  if (c != 0x12345678) {
    debug_print_uint(c);
    return 0xdead9;
  }
  c = test2(0xf00d);
  if (c != 0xd00f) {
    debug_print_uint(c);
    return 0xdead10;
  }

  /* magic number to tell libclamav that selftest succeeded */
  return 0xda7aba5e;
}


#endif
#endif
