/*
 *  Builtin ClamAV bytecodes.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
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

static const char* builtin_bc_startup = "ClamBCafhhbfkjmld|afefdfggifnf```aa```|biacflfafmfbfcfmb`cnbacacmbachcccmbgfbfcc`ccchcbfdf``bgcaap`clamcoincidencejb:4096\n"
"\n"
"Teddaaahdabahdacahdadahdaeahdafahdagahebfgebidebegebdgebgdebkdebcgebbgebageb`gebofebnfebmfebedeblfebkfebjfebadcbgab`bb`bb`bb`bb`bb`bb`bbifbifbifbifbifbifbifahahahahahahahahahebneebifaaaaaaaab`baabb`bb`baacb`bbadb`baacb`bboeb`baacb`bb`bb`baadb`bbadb`bb`baadb`bbadbadb`bdbadahdbkaahdbbcahdbibahdb`eahdbddahdbodahdbdaahdaiahdakahdamahdahahdbncahdbnbah\n"
"Ebjdaibcdbbf|bcaefnfgfifnfefoedfcfofnfffoelfeffgeflf``bbdbbf|bkaefnfgfifnfefoeffegnfcfdgifofnfaflfifdgigoelfeffgeflf``agbcf|baadfefbfeggfoe`gbgifnfdgoeegifnfdg``bcabcf|afdgefcgdgbc``afbdf|b`adfefbfeggfoe`gbgifnfdgoecgdgbg``bhdbef|b`agfefdgoeefnffgifbgofnfmfefnfdg``aabff|afdgefcgdgac``bidbgf|bdadfifcgafbflfefoebfigdgefcfofdfefoeifff``bjdbgf|aodfifcgafbflfefoejfifdgoeifff``\n"
"G`b`c`@`b`aAa`bfgBifBkeBccBdcBmeBhcBfcB`bBdfBefBdgBefBcfBdgBefBdfBlbB`bBjdBidBdeB`bBnfBefBefBdfBcgB`bB`gBefBnfBdgBifBegBmfB`bBofBbgB`bBbfBefBdgBdgBefBbg@`bidBifBccBhcBfc@`bidBifBdcBhcBfc@`begBcdB`eBeeB`bBdfBofBefBcgBnfBgbBdgB`bBcgBegB`gB`gBofBbgBdgB`bBcdBmdBodBfeBlbB`bBggBofBegBlfBdfB`bBnfBefBefBdfB`bB`cBnbBicBgcB`bBhbBldBldBfeBmdB`bBbcBnbBhcBibB`bBdgBofB`bBggBofBbgBkfBab@`bidBifBecBhcBfc@`bdgB`gBefBnfBdgBifBegBmf@`bidBifBfcBhcBfc@`bgdBkfBfc@`bidBkfBfcBmbBbc@`bidBkfBfcBmbBcc@`bkdBafBdgBhfBlfBofBnf@`bcgBafBdgBhfBlfBofBnfBmbBdgBbfBifBbgBdf@`bbgBggBifBnfBcfBhfBifB`gBmbBcfBfc@`bagBggBifBnfBcfBhfBifB`gBbc@`bgdBcfBcc@`b`gBbeBgeBheB`bBmfBafB`gB`gBifBnfBgfB`bBdfBefBnfBifBefBdfBnb@`bofBneBceBedBldBifBnfBegBhgB`bBifBcgB`bB`gBbgBefBfgBefBnfBdgBifBnfBgfB`bBgbBefBhgBefBcfBmfBefBmfBgbB`bBafBcfBcfBefBcgBcgBnbAjBbeBegBnfB`bB`bBgbBcgBefBdgBcgBefBbfBofBofBlfB`bBmbB`eB`bBcfBlfBafBmfBdfBoeBegBcgBefBoeBjfBifBdgB`bBofBnfBgbBnb@`bnfBneB`eBafBheB`bBifBcgB`bB`gBbgBefBfgBefBnfBdgBifBnfBgfB`bBgbBmfB`gBbgBofBdgBefBcfBdgBgbB`bBafBcfBcfBefBcgBcgBnbAjBbeBegBnfB`bBgbB`gBafBhgBcfBdgBlfB`bBmbBcfBmfB`bBlcBefBhgBefBcfBegBdgBafBbfBlfBefBncBgb@`bmfBneBbeBgeBheB`bBmfBafB`gB`gBifBnfBgfB`bBdfBefBnfBifBefBdfB`bBffBofBbgB`bBegBnfBkfBnfBofBggBnfB`bBbgBefBafBcgBofBnfBnbB`eBlfBefBafBcgBefB`bBbgBefB`gBofBbgBdgB`bBdgBofB`bBhfBdgBdgB`gBjcBobBobBbfBegBgfBcgBnbBcfBlfBafBmfBafBfgBnbBnfBefBdgAj@`bed@`blfBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBefBhgBefBcfBegBdgBifBofBnfB`bBifBnfB`bBafBegBdgBofB`bBmfBofBdfBef@`bkfBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBefBhgBefBcfBegBdgBifBofBnfB`bBggBifBdgBhfB`bBifBnfBdgBefBbgB`gBbgBefBdgBefBbgB`bBofBnfBlfBig@`bjfBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBdfBifBcgBafBbfBlfBefBdf@`bad@Ab`bad@Ac`bad@Ad`bad@Ae`bad@Af`bad@Ag`bad@Ah`bad@Ai`bad@Aj`bad@Ak`bad@Al`bad@Am`bad@An`bad@Ao`bad@B`a`bad@Baa`bad@Bba`bad@Bca`bad@Bda`bad@Bea`bad@Bfa`bad@Bga`bad@Bha`\n"
"A`b`bLblib`bab`b`b`b`bneab`b`bad`ah`aa`bad`ah`aa`b`f`bad`b`b`aa`b`b`aa`b`b`b`b`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`b`b`bad`ah`b`b`b`b`aa`b`b`bad`ah`aa`ah`b`b`b`b`aa`b`b`b`b`aa`b`b`b`b`bad`ah`aa`bad`ah`aa`b`b`aa`b`b`b`b`aa`aa`aa`aa`aa`b`b`b`b`b`b`ah`aa`bcd`b`b`aa`bcd`b`b`bcd`b`b`aa`b`b`aa`b`b`b`b`aa`bad`ah`b`b`aa`b`b`aa`bad`ah`b`b`b`b`bad`ah`b`b`b`b`bad`ah`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`bad`ah`b`b`b`b`bcd`b`b`b`b`b`b`bad`ah`b`b`b`b`bcd`b`b`b`b`bcd`b`b`aa`b`b`bcd`b`b`aa`b`b`bcd`b`b`aa`b`b`b`b`aa`b`b`b`b`aa`b`b`b`b`Fbbnbec\n"
"Bb`badabbbhdacClnadbadaedbboeacBdadahafgbaeaaageaahaf@aTaaagblaaa\n"
"BbadahdbboeacB`adahaigbahaaajeaahaiAaaTaaajabbaa\n"
"Bb`fakdbboeacAidbadaldbb`fak@db`bamkbalBja`Aedaaaneab`bam@db`b`bbAadabTaaanadac\n"
"Bb`baokbalBka`Aedaab`aeab`bao@db`bab`ab`ab`b`bbababTbaad\n"
"Bb`bbaabbabbaab`bbbaabcbjdBia`@dbaab`bbcaab`bbdaabdaiab`bbcaBicdTaabdaaebaa\n"
"Bb`bbeakbalBma`Aedaabfaeab`bbea@db`b`bbAadaaTaabfab`aaf\n"
"Bb`bbgakbalBna`Ahdaabhaeab`bbga@db`b`bbAadaaTaabhab`aag\n"
"Bb`bbiakbalBoa`Aedaabjaeab`bbia@db`b`bbAadaaTaabjab`aah\n"
"Bb`bbkakbalB`b`Acdaablaeab`bbka@db`b`bbAadaaTaablab`aai\n"
"Bb`bbmakbalBab`Aedaabnaeab`bbma@db`b`bbAadaaTaabnab`aaj\n"
"Bb`bboakbalBbb`Aedaab`beab`bboa@db`b`bbAadaaTaab`bb`aak\n"
"Bb`bbabkbalBcb`Agdaabbbeab`bbab@db`b`bbAadaaTaabbbb`aal\n"
"Bb`bbcbkbalBdb`Amdaabdbeab`bbcb@db`b`bbAadaaTaabdbb`aam\n"
"Bb`bbebkbalBeb`Akdaabfbeab`bbeb@db`b`bbAadaaTaabfbb`aan\n"
"Bb`bbgbkbalBfb`Aidaabhbeab`bbgb@db`b`bbAadaaTaabhbb`aao\n"
"Bb`bbibkbalBgb`Acdaabjbeab`bbib@db`baa`abjbb`b`bbaaaaTbab`a\n"
"Bb`bbkbbbaabkbb`bblbabcbjdBla`@dbkbTbabaa\n"
"BbadbmbdbboeacBeadahbnbgbbmbb`bbob`abnbb`bb`ck`bobAadaabaceab`bb`c@dTaabacbbabha\n"
"Bb`bbbcabcbjdBhb`@dAadbadbccdbboeacBaadahbdcgbbccaabeceaahbdcAjaTaabecbcabla\n"
"Bahbfcgbbmbb`bbgc`abfcb`bbhck`bgcAbdaabiceab`bbhc@dTaabicbeabda\n"
"Bb`bbjcabcbjdBib`@dAadTbabla\n"
"Bb`bbkck`bgcAhdaablceab`bbkc@dTaablcbgabfa\n"
"Bb`bbmcabcbjdBjb`@dAadTbabla\n"
"Bb`bbncabcbjdBkb`@dAadTbabla\n"
"BbadbocdbboeacBaadahb`dgbbocaabadeaahb`dAjaTaabadbjabia\n"
"BbadbbddbboeacBbadahbcdgbbbdaabddeaahbcdAfaTaabddbjabla\n"
"Bb`bbedk`bobB`adaabfdeab`bbed@dTaabfdblabka\n"
"Bb`bbgdabcbjdBjb`@dAadTbabla\n"
"Bb`bbhdabcbidBlb`@d@daabidnab`bbhdAadTaabidb`bbma\n"
"Baabjdnab`bbhdAbdTaabjdboabna\n"
"Baabkdeab`bbhdAbdTaabkdbcbbdb\n"
"Baabldeab`bbhdAadTaabldbbbbdb\n"
"Baabmdeab`bbhd@dTaabmdbabbdb\n"
"Bb`bbndabbafBmb`@dTbabdb\n"
"Bb`bbodabbafBnb`@dTbabdb\n"
"Bb`bb`eabbafBob`@dTbabdb\n"
"Bahbaegbaeaabbeeaahbae@aTaabbebfbbeb\n"
"BbcdbcedbboeacAddb`bbdegbbceaabeeeab`bbde@db`b`bbEamjnmd`Taabeebdcbfb\n"
"BbcdbfedbboeacAfdb`bbgegbbfebcdbhedbboeacAedb`bbiegbbheaabjeiab`bbgebieb`b`bbEbmjnmd`Taabjebdcbgb\n"
"Bb`bbkeab`bbdaableeab`bbiebkeb`b`bbEcmjnmd`Taablebhbbdc\n"
"Bb`bbmegbbfeb`bbneab`bcdaaboeeab`bbmebneb`b`bbEdmjnmd`Taaboebibbdc\n"
"Bbadb`fdbboeacAndahbafgbb`fb`bbbf`abafaabcflbb`bbdf`abcfaabefeab`bbbfbdfb`b`bbEemjnmd`Taabefbjbbdc\n"
"BbadbffdbboeacBaadahbgfgbbffb`bbhf`abgfb`bbifh`bhfBhadbadbjfdbboeacB`adahbkfgbbjfb`bblf`abkfb`bbmfh`blfBdadbadbnfdbboeacBcadahbofgbbnfb`bb`g`abofb`bbagh`b`gB`adb`bbbggbbheb`bbcgh`bbgAhdb`bbdggbbfeb`bbegl`bmfbifb`bbfgl`begbcgb`bbggl`bfgbdgb`bbhgl`bggbagb`bbigh`bbfBladbadbjgdbboeacAodahbkggbbjgb`bblg`abkgb`bbmgh`blgBhadbcdbngdbboeacAddb`bboggbbngb`bb`hl`bogbigb`bbahl`b`hbmgbadbbhdbboeacBeadahbchgbbbhb`bbdh`abchb`bbehh`bdhBhadbcdbfhdbboeacAcdb`bbghgbbfhb`bbhhl`behbghbcdbihdbboeac@db`bbjhgbbihaabkheab`bbhgbjhTaabkhblbbkb\n"
"Bb`bblhabaagbhgTcab`bEfmjnmd\n"
"BbcdbmhdbboeacAadb`bbnhgbbmhaaboheab`bbahbnhTaabohbnbbmb\n"
"Bb`bb`iabaagbahTcab`bEgmjnmd\n"
"BbcdbaidbboeacAbdb`bbbigbbaiaabcieab`bbhhbbiTaabcib`cbob\n"
"Bb`bbdiabaagbhhTcab`bEhmjnmd\n"
"Bb`bbeiabbaaHonnkm``odHm``oonnkdaabfieab`bbeiHhgfedcbadTaabfibbcbac\n"
"Bb`bbgiabaagbeiTcab`bEimjnmd\n"
"Bb`bbhiababcaDm``odaabiieab`bbhiDo``mdb`b`bbHnejkjgjmd`Taabiibdcbcc\n"
"Bb`bbjiabaagbhiTcab`bF`amjnmd\n"
"Bb`bbkibb`bkiTcab`bbkiE\n"
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
                     !memcmp(env.cpu,"i386",5) ||
                     !memcmp(env.cpu,"i486",5));
      if (engine_functionality_level() < FUNC_LEVEL_097) {
	  /* LLVM 2.7 bug, fixed in 2.8, but only 0.97 has 2.8 */
	  /* bug is using CMOV instr, when CPU doesn't support it, 2.8 correctly
	   * handles this, 2.7 doesn't */
	  disable_jit_if("CPU doesn't support CMOV, would need 0.97 (LLVM 2.8) to work!",0,
			 !memcmp(env.cpu,"i586",5) ||
			 !memcmp(env.cpu,"pentium",8) ||
			 !memcmp(env.cpu,"i686",5) ||
			 !memcmp(env.cpu,"k6",3) ||
			 !memcmp(env.cpu,"k6-2",5) ||
			 !memcmp(env.cpu,"k6-3",5) ||
			 !memcmp(env.cpu,"athlon",7) ||
			 !memcmp(env.cpu,"athlon-tbird",13) ||
			 !memcmp(env.cpu,"winchip-c6",11) ||
			 !memcmp(env.cpu,"winchip2",9) ||
			 !memcmp(env.cpu,"c3",3));
      }
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
            "Please report to https://bugzilla.clamav.net\n", 0, 1);
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
