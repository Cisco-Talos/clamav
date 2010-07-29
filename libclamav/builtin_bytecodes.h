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
 * be disabled.
 * There can only be one such bytecode, if there is none this is used as
 * fallback.
 * Usually bytecode.cvd will contain this bytecode */

static const char* builtin_bc_startup = "ClamBCafhgjmdaeld|afefdfggifnf```aa```|biacflfafmfbfcfmb`cnbacacmbacdcdcmbgfcchc`cdf`cafgc``bgbaap`clamcoincidencejb:1378\n"
"\n"
"Teddaaahdabahdacahdadahdaeahdafahdagahebffebidebefebdfebcfebbfebedebafeb`feboeebadcbgab`bb`bb`bb`bb`bb`bb`bbnebnebnebnebnebnebneahahahahahahahahahebgeebneaacb`bbadb`baacb`bbheb`baadb`bbadb`bb`baadb`bbadbadb`bdbadahdbkaahdbbcahdbibahdb`eahdbddahdbodahdbdaahdbnbah\n"
"Ebjdadafbje|b`adfefbfeggfoe`gbgifnfdgoecgdgbg``bhdbke|b`agfefdgoeefnffgifbgofnfmfefnfdg``bidble|bdadfifcgafbflfefoebfigdgefcfofdfefoeifff``bjdble|aodfifcgafbflfefoejfifdgoeifff``\n"
"G`bha`@`b`aAa`bffBifBkeBccBdcBmeBhcBfcB`bBdfBefBdgBefBcfBdgBefBdfBlbB`bBjdBidBdeB`bBnfBefBefBdfBcgB`bB`gBefBnfBdgBifBegBmfB`bBofBbgB`bBbfBefBdgBdgBefBbg@`bidBifBccBhcBfc@`bidBifBdcBhcBfc@`befBbeBgeBheB`bBmfBafB`gB`gBifBnfBgfB`bBdfBefBnfBifBefBdfBnb@`bdfBneBceBedBldBifBnfBegBhgB`bBifBcgB`bB`gBbgBefBfgBefBnfBdgBifBnfBgfB`bBgbBefBhgBefBcfBmfBefBmfBgbB`bBafBcfBcfBefBcgBcgBnbAjBbeBegBnfB`bB`bBgbBcgBefBdgBcgBefBbfBofBofBlfB`bBmbB`eB`bBcfBlfBafBmfBdfBoeBegBcgBefBoeBjfBifBdgB`bBofBnfBgbBnb@`bcfBneB`eBafBheB`bBifBcgB`bB`gBbgBefBfgBefBnfBdgBifBnfBgfB`bBgbBmfB`gBbgBofBdgBefBcfBdgBgbB`bBafBcfBcfBefBcgBcgBnbAjBbeBegBnfB`bBgbB`gBafBhgBcfBdgBlfB`bBmbBcfBmfB`bBlcBefBhgBefBcfBegBdgBafBbfBlfBefBncBgb@`bbfBneBbeBgeBheB`bBmfBafB`gB`gBifBnfBgfB`bBdfBefBnfBifBefBdfB`bBffBofBbgB`bBegBnfBkfBnfBofBggBnfB`bBbgBefBafBcgBofBnfBnbB`eBlfBefBafBcgBefB`bBbgBefB`gBofBbgBdgB`bBdgBofB`bBhfBdgBdgB`gBjcBobBobBbfBegBgfBcgBnbBcfBlfBafBmfBafBfgBnbBnfBefBdgAj@`bed@`bafBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBefBhgBefBcfBegBdgBifBofBnfB`bBifBnfB`bBafBegBdgBofB`bBmfBofBdfBef@`b`fBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBefBhgBefBcfBegBdgBifBofBnfB`bBggBifBdgBhfB`bBifBnfBdgBefBbgB`gBbgBefBdgBefBbgB`bBofBnfBlfBig@`boeBcgBdgBafBbgBdgBegB`gBjcB`bBbfBigBdgBefBcfBofBdfBefB`bBdfBifBcgBafBbfBlfBefBdf@`bad@Ab`bad@Ac`bad@Ad`bad@Ae`bad@Af`bad@Ag`bad@Ah`bad@Ai`bad@Aj`bad@Ak`bad@Al`\n"
"A`b`bLbecb`b`bgeab`b`bad`ah`aa`bad`ah`aa`bie`bad`b`b`aa`b`b`aa`b`b`b`b`bad`ah`b`b`b`b`aa`b`b`bad`ah`aa`ah`b`b`b`b`aa`b`b`b`b`aa`b`b`b`b`bad`ah`aa`bad`ah`aa`b`b`aa`b`b`b`b`aa`aa`aa`aa`aa`b`b`b`b`b`b`Fbodbia\n"
"Bb`bababbbhdaaClnadbadacdbbheaaBdadahadgbacaaaeeaahad@aTaaaeb`aaa\n"
"BbadafdbbheaaB`adahaggbafaaaheaahagAaaTaaahabae\n"
"BbieaidbbheaaAidbadajdbbieai@db`bakkbajAn`Addaaaleab`bak@db`b`bbAad`Taaaladac\n"
"Bb`bamkbajAo`Addaaaneab`bam@db`b``aanb`b`bb``Tbaad\n"
"Bb`baobb`aob`bb`aabcbjdAm`@daoTbaae\n"
"BbadbaadbbheaaBeadahbbagbbaab`bbca`abbab`bbdak`bcaAadaabeaeab`bbda@dTaabeaafal\n"
"Bb`bbfaabcbjdB`a`@dAadbadbgadbbheaaBbadahbhagbbgaaabiaeaahbhaAjaTaabiaagb`a\n"
"Bahbjagbbaab`bbka`abjab`bblak`bkaAbdaabmaeab`bbla@dTaabmaaiah\n"
"Bb`bbnaabcbjdBaa`@dAadTbab`a\n"
"Bb`bboak`bkaAhdaab`beab`bboa@dTaab`bakaj\n"
"Bb`bbababcbjdBba`@dAadTbab`a\n"
"Bb`bbbbabcbjdBca`@dAadTbab`a\n"
"BbadbcbdbbheaaBbadahbdbgbbcbaabebeaahbdbAjaTaabebanam\n"
"BbadbfbdbbheaaBaadahbgbgbbfbaabhbeaahbgbAfaTaabhbanb`a\n"
"Bb`bbibk`bcaB`adaabjbeab`bbib@dTaabjbb`aao\n"
"Bb`bbkbabcbjdBba`@dAadTbab`a\n"
"Bb`bblbabcbidBda`@d@daabmbnab`bblbAadTaabmbbdabaa\n"
"Baabnbnab`bblbAbdTaabnbbcabba\n"
"Baabobeab`bblbAbdTaabobbgabha\n"
"Baab`ceab`bblbAadTaab`cbfabha\n"
"Baabaceab`bblb@dTaabacbeabha\n"
"Bb`bbbcabbafBea`@dTcab`b@d\n"
"Bb`bbccabbafBfa`@dTcab`b@d\n"
"Bb`bbdcabbafBga`@dTcab`b@d\n"
"BTcab`b@dE\n"
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
      if (env.os == os_linux) {
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
      if ((env.os == os_linux || env.os_category == llvm_os_Linux) &&
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
  return 0;
}


#endif
#endif
