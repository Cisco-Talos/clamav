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

static const char* builtin_bc_startup = "ClamBCafhmknalkld|afefdfggifnf```aa```|biacflfafmfbfcfmb`cnbacacmbacgcgcmbgfbffcbficbfbfac``bgcaap`clamcoincidencejb:4096\n"
"\n"
"Teddaaahdabahdacahdadahdaeahdafahdagahebfgebidebegebdgebgdebkdebcgebbgebageb`gebofebnfebmfebedeblfebkfebjfebadcbgab`bb`bb`bb`bb`bb`bb`bbifbifbifbifbifbifbifahahahahahahahahahebneebifaaaaaaaab`baabb`bb`baacb`bbadb`baacb`bboeb`baacb`bb`bb`baadb`bbadb`bb`baadb`bbadbadb`bdbadahdbkaahdbbcahdbibahdb`eahdbddahdbodahdbdaahdaiahdakahdamahdahahdbgcahdbnbah\n"
"Ebjdaibcdbbf|bcaefnfgfifnfefoedfcfofnfffoelfeffgeflf``bbdbbf|bkaefnfgfifnfefoeffegnfcfdgifofnfaflfifdgigoelfeffgeflf``agbcf|baadfefbfeggfoe`gbgifnfdgoeegifnfdg``bcabcf|afdgefcgdgbc``afbdf|b`adfefbfeggfoe`gbgifnfdgoecgdgbg``bhdbef|b`agfefdgoeefnffgifbgofnfmfefnfdg``aabff|afdgefcgdgac``bidbgf|bdadfifcgafbflfefoebfigdgefcfofdfefoeifff``bjdbgf|aodfifcgafbflfefoejfifdgoeifff``\n"
"G`b`c`@`b`aAa`bfgBifBkeBccBdcBmeBhcBfcB`bBdfBefBdgBefBcfBdgBefBdfBlbB`bBjdBidBdeB`bBnfBefBefBdfBcgB`bB`gBefBnfBdgBifBegBmfB`bBofBbgB`bBbfBefBdgBdgBefBbg@`bidBifBccBhcBfc@`bidBifBdcBhcBfc@`begBcdB`eBeeB`bBdfBofBefBcgBnfBgbBdgB`bBcgBegB`gB`gBofBbgBdgB`bBcdBmdBodBfeBlbB`bBggBofBegBlfBdfB`bBnfBefBefBdfB`bBldBldBfeBmdB`bBbcBnbBhcB`bBdgBofB`bBggBofBbgBkfBab@`bidBifBecBhcBfc@`bdgB`gBefBnfBdgBifBegBmf@`bidBifBfcBhcBfc@`bgdBkfBfc@`bidBkfBfcBmbBbc@`bidBkfBfcBmbBcc@`bkdBafBdgBhfBlfBofBnf@`bcgBafBdgBhfBlfBofBnfBmbBdgBbfBifBbgBdf@`bbgBggBifBnfBcfBhfBifB`gBmbBcfBfc@`bagBggBifBnfBcfBhfBifB`gBbc@`bgdBcfBcc@`b`gBbeBgeBheB`bBmfBafB`gB`gBifBnfBgfB`bBdfBefBnfBifBefBdfBnb@`bofBneBceBedBldBifBnfBegBhgB`bBifBcgB`bB`gBbgBefBfgBefBnfBdgBifBnfBgfB`bBgbBefBhgBefBcfBmfBefBmfBgbB`bBafBcfBcfBefBcgBcgBnbAjBbeBegBnfB`bB`bBgbBcgBefBdgBcgBefBbfBofBofBlfB`bBmbB`eB`bBcfBlfBafBmfBdfBoeBegBcgBefBoeBjfBifBdgB`bBofBnfBgbBnb@`bnfBneB`eBafBheB`bBifBcgB`bB`gBbgBefBfgBefBnfBdgBifBnfBgfB`bBgbBmfB`gBbgBofBdgBefBcfBdgBgbB`bBafBcfBcfBefBcgBcgBnbAjBbeBegBnfB`bBgbB`gBafBhgBcfBdgBlfB`bBmbBcfBmfB`bBlcBefBhgBefBcfBegBdgBafBbfBlfBefBncBgb@`bmfBneBbeBgeBheB`bBmfBafB`gB`gBifBnfBgfB`bBdfBefBnfBifBefBdfB`bBffBofBbgB`bBegBnfBkfBnfBofBggBnfB`bBbgBefBafBcgBofBnfBnbB`eBlfBefBafBcgBefB`bBbgBefB`gBofBbgBdgB`bBdgBofB`bBhfBdgBdgB`gBjcBobBobBbfBegBgfBcgBnbBcfBlfBafBmfBafBfgBnbBnfBefBdgAj@`bed@`blfBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBefBhgBefBcfBegBdgBifBofBnfB`bBifBnfB`bBafBegBdgBofB`bBmfBofBdfBef@`bkfBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBefBhgBefBcfBegBdgBifBofBnfB`bBggBifBdgBhfB`bBifBnfBdgBefBbgB`gBbgBefBdgBefBbgB`bBofBnfBlfBig@`bjfBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBdfBifBcgBafBbfBlfBefBdf@`bad@Ab`bad@Ac`bad@Ad`bad@Ae`bad@Af`bad@Ag`bad@Ah`bad@Ai`bad@Aj`bad@Ak`bad@Al`bad@Am`bad@An`bad@Ao`bad@B`a`bad@Baa`bad@Bba`bad@Bca`bad@Bda`bad@Bea`bad@Bfa`bad@Bga`bad@Bha`\n"
"A`b`bLbjib`bab`bab`babneab`b`bad`ah`aa`bad`ah`aa`b`f`bad`b`b`aa`b`b`aa`b`b`b`b`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`aa`b`b`b`b`bad`ah`b`b`b`b`aa`b`b`bad`ah`aa`ah`b`b`b`b`aa`b`b`b`b`aa`b`b`b`b`bad`ah`aa`bad`ah`aa`b`b`aa`b`b`b`b`aa`aa`aa`aa`aa`b`b`b`b`b`b`ah`aa`bcd`b`b`aa`bcd`b`b`bcd`b`b`aa`b`b`aa`b`b`b`b`aa`bad`ah`b`b`aa`b`b`aa`bad`ah`b`b`b`b`bad`ah`b`b`b`b`bad`ah`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`b`bad`ah`b`b`b`b`bcd`b`b`b`b`b`b`bad`ah`b`b`b`b`bcd`b`b`b`b`bcd`b`b`aa`b`b`bcd`b`b`aa`b`b`bcd`b`b`aa`b`b`b`b`aa`b`b`b`b`aa`b`b`b`b`Fbombdc\n"
"Bb`badabbbhdacClnadbadaedbboeacBdadahafgbaeaaageaahaf@aTaaagbkaaa\n"
"BbadahdbboeacB`adahaigbahaaajeaahaiAaaTaaajabb`a\n"
"Bb`fakdbboeacAidbadaldbb`fak@db`bamkbalBja`Addaaaneab`bam@db`b`bbAadabTaaanadac\n"
"Bb`baokbalBka`Addaab`aeab`bao@db`bab`ab`ab`b`bbababTbaad\n"
"Bb`bbaabbabbaab`bbbaabcbjdBia`@dbaab`bbcakbalBma`Addaabdaeab`bbca@db`b`bbAadaaTaabdaaoae\n"
"Bb`bbeakbalBna`Agdaabfaeab`bbea@db`b`bbAadaaTaabfaaoaf\n"
"Bb`bbgakbalBoa`Addaabhaeab`bbga@db`b`bbAadaaTaabhaaoag\n"
"Bb`bbiakbalB`b`Abdaabjaeab`bbia@db`b`bbAadaaTaabjaaoah\n"
"Bb`bbkakbalBab`Addaablaeab`bbka@db`b`bbAadaaTaablaaoai\n"
"Bb`bbmakbalBbb`Addaabnaeab`bbma@db`b`bbAadaaTaabnaaoaj\n"
"Bb`bboakbalBcb`Afdaab`beab`bboa@db`b`bbAadaaTaab`baoak\n"
"Bb`bbabkbalBdb`Aldaabbbeab`bbab@db`b`bbAadaaTaabbbaoal\n"
"Bb`bbcbkbalBeb`Ajdaabdbeab`bbcb@db`b`bbAadaaTaabdbaoam\n"
"Bb`bbebkbalBfb`Ahdaabfbeab`bbeb@db`b`bbAadaaTaabfbaoan\n"
"Bb`bbgbkbalBgb`Abdaabhbeab`bbgb@db`baa`abhbb`b`bbaaaaTbaao\n"
"Bb`bbibbbaabibb`bbjbabcbjdBla`@dbibTbab`a\n"
"BbadbkbdbboeacBeadahblbgbbkbb`bbmb`ablbb`bbnbk`bmbAadaabobeab`bbnb@dTaabobbaabga\n"
"Bb`bb`cabcbjdBhb`@dAadbadbacdbboeacBaadahbbcgbbacaabcceaahbbcAjaTaabccbbabka\n"
"Bahbdcgbbkbb`bbec`abdcb`bbfck`becAbdaabgceab`bbfc@dTaabgcbdabca\n"
"Bb`bbhcabcbjdBib`@dAadTbabka\n"
"Bb`bbick`becAhdaabjceab`bbic@dTaabjcbfabea\n"
"Bb`bbkcabcbjdBjb`@dAadTbabka\n"
"Bb`bblcabcbjdBkb`@dAadTbabka\n"
"BbadbmcdbboeacBaadahbncgbbmcaaboceaahbncAjaTaabocbiabha\n"
"Bbadb`ddbboeacBbadahbadgbb`daabbdeaahbadAfaTaabbdbiabka\n"
"Bb`bbcdk`bmbB`adaabddeab`bbcd@dTaabddbkabja\n"
"Bb`bbedabcbjdBjb`@dAadTbabka\n"
"Bb`bbfdabcbidBlb`@d@daabgdnab`bbfdAadTaabgdboabla\n"
"Baabhdnab`bbfdAbdTaabhdbnabma\n"
"Baabideab`bbfdAbdTaabidbbbbcb\n"
"Baabjdeab`bbfdAadTaabjdbabbcb\n"
"Baabkdeab`bbfd@dTaabkdb`bbcb\n"
"Bb`bbldabbafBmb`@dTbabcb\n"
"Bb`bbmdabbafBnb`@dTbabcb\n"
"Bb`bbndabbafBob`@dTbabcb\n"
"Bahbodgbaeaab`eeaahbod@aTaab`ebebbdb\n"
"BbcdbaedbboeacAddb`bbbegbbaeaabceeab`bbbe@db`b`bbEamjnmd`Taabcebccbeb\n"
"BbcdbdedbboeacAfdb`bbeegbbdebcdbfedbboeacAedb`bbgegbbfeaabheiab`bbeebgeb`b`bbEbmjnmd`Taabhebccbfb\n"
"Bb`bbieab`bbdaabjeeab`bbgebieb`b`bbEcmjnmd`Taabjebgbbcc\n"
"Bb`bbkegbbdeb`bbleab`bcdaabmeeab`bbkebleb`b`bbEdmjnmd`Taabmebhbbcc\n"
"BbadbnedbboeacAndahboegbbneb`bb`f`aboeaabaflbb`bbbf`abafaabcfeab`bb`fbbfb`b`bbEemjnmd`Taabcfbibbcc\n"
"BbadbdfdbboeacBaadahbefgbbdfb`bbff`abefb`bbgfh`bffBhadbadbhfdbboeacB`adahbifgbbhfb`bbjf`abifb`bbkfh`bjfBdadbadblfdbboeacBcadahbmfgbblfb`bbnf`abmfb`bbofh`bnfB`adb`bb`ggbbfeb`bbagh`b`gAhdb`bbbggbbdeb`bbcgl`bkfbgfb`bbdgl`bcgbagb`bbegl`bdgbbgb`bbfgl`begbofb`bbggh`b`fBladbadbhgdbboeacAodahbiggbbhgb`bbjg`abigb`bbkgh`bjgBhadbcdblgdbboeacAddb`bbmggbblgb`bbngl`bmgbggb`bbogl`bngbkgbadb`hdbboeacBeadahbahgbb`hb`bbbh`abahb`bbchh`bbhBhadbcdbdhdbboeacAcdb`bbehgbbdhb`bbfhl`bchbehbcdbghdbboeac@db`bbhhgbbghaabiheab`bbfgbhhTaabihbkbbjb\n"
"Bb`bbjhabaagbfgTcab`bEfmjnmd\n"
"BbcdbkhdbboeacAadb`bblhgbbkhaabmheab`bbogblhTaabmhbmbblb\n"
"Bb`bbnhabaagbogTcab`bEgmjnmd\n"
"BbcdbohdbboeacAbdb`bb`igbbohaabaieab`bbfhb`iTaabaibobbnb\n"
"Bb`bbbiabaagbfhTcab`bEhmjnmd\n"
"Bb`bbciabbaaHonnkm``odHm``oonnkdaabdieab`bbciHhgfedcbadTaabdibacb`c\n"
"Bb`bbeiabaagbciTcab`bEimjnmd\n"
"Bb`bbfiababcaDm``odaabgieab`bbfiDo``mdb`b`bbHnejkjgjmd`Taabgibccbbc\n"
"Bb`bbhiabaagbfiTcab`bF`amjnmd\n"
"Bb`bbiibb`biiTcab`bbiiE\n"
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
      /* FIXME: update embedded LLVM to 2.8 which correctly skips CMOV if CPU
       * doesn't support it.
       * For now disable JIT on CPUs without cmov */
      disable_jit_if("CPU doesn't support CMOV, would need LLVM 2.8 to work!",0,
		     !memcmp(env.cpu,"i586",4) ||
		     !memcmp(env.cpu,"pentium",7) ||
		     !memcmp(env.cpu,"i686",4) ||
		     !memcmp(env.cpu,"k6",2) ||
		     !memcmp(env.cpu,"k6-2",4) ||
		     !memcmp(env.cpu,"k6-3",4) ||
		     !memcmp(env.cpu,"athlon",6) ||
		     !memcmp(env.cpu,"athlon-tbird",12) ||
		     !memcmp(env.cpu,"winchip-c6",10) ||
		     !memcmp(env.cpu,"winchip2",8) ||
		     !memcmp(env.cpu,"c3",2));
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
