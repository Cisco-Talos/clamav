//===- TableGen'erated file -------------------------------------*- C++ -*-===//
//
// Machine Code Emitter
//
// Automatically generated file, do not edit!
//
//===----------------------------------------------------------------------===//

unsigned PPCCodeEmitter::getBinaryCodeForInstr(const MachineInstr &MI) {
  static const unsigned InstBits[] = {
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    2080375316U,	// ADD4
    2080375316U,	// ADD8
    2080374804U,	// ADDC
    2080374804U,	// ADDC8
    2080375060U,	// ADDE
    2080375060U,	// ADDE8
    939524096U,	// ADDI
    939524096U,	// ADDI8
    805306368U,	// ADDIC
    805306368U,	// ADDIC8
    872415232U,	// ADDICo
    1006632960U,	// ADDIS
    1006632960U,	// ADDIS8
    2080375252U,	// ADDME
    2080375252U,	// ADDME8
    2080375188U,	// ADDZE
    2080375188U,	// ADDZE8
    0U,	// ADJCALLSTACKDOWN
    0U,	// ADJCALLSTACKUP
    2080374840U,	// AND
    2080374840U,	// AND8
    2080374904U,	// ANDC
    2080374904U,	// ANDC8
    1946157056U,	// ANDISo
    1946157056U,	// ANDISo8
    1879048192U,	// ANDIo
    1879048192U,	// ANDIo8
    0U,	// ATOMIC_CMP_SWAP_I16
    0U,	// ATOMIC_CMP_SWAP_I32
    0U,	// ATOMIC_CMP_SWAP_I64
    0U,	// ATOMIC_CMP_SWAP_I8
    0U,	// ATOMIC_LOAD_ADD_I16
    0U,	// ATOMIC_LOAD_ADD_I32
    0U,	// ATOMIC_LOAD_ADD_I64
    0U,	// ATOMIC_LOAD_ADD_I8
    0U,	// ATOMIC_LOAD_AND_I16
    0U,	// ATOMIC_LOAD_AND_I32
    0U,	// ATOMIC_LOAD_AND_I64
    0U,	// ATOMIC_LOAD_AND_I8
    0U,	// ATOMIC_LOAD_NAND_I16
    0U,	// ATOMIC_LOAD_NAND_I32
    0U,	// ATOMIC_LOAD_NAND_I64
    0U,	// ATOMIC_LOAD_NAND_I8
    0U,	// ATOMIC_LOAD_OR_I16
    0U,	// ATOMIC_LOAD_OR_I32
    0U,	// ATOMIC_LOAD_OR_I64
    0U,	// ATOMIC_LOAD_OR_I8
    0U,	// ATOMIC_LOAD_SUB_I16
    0U,	// ATOMIC_LOAD_SUB_I32
    0U,	// ATOMIC_LOAD_SUB_I64
    0U,	// ATOMIC_LOAD_SUB_I8
    0U,	// ATOMIC_LOAD_XOR_I16
    0U,	// ATOMIC_LOAD_XOR_I32
    0U,	// ATOMIC_LOAD_XOR_I64
    0U,	// ATOMIC_LOAD_XOR_I8
    0U,	// ATOMIC_SWAP_I16
    0U,	// ATOMIC_SWAP_I32
    0U,	// ATOMIC_SWAP_I64
    0U,	// ATOMIC_SWAP_I8
    1207959552U,	// B
    1073741824U,	// BCC
    1317012512U,	// BCTR
    1317012513U,	// BCTRL8_Darwin
    1317012513U,	// BCTRL8_ELF
    1317012513U,	// BCTRL_Darwin
    1317012513U,	// BCTRL_SVR4
    1207959553U,	// BL8_Darwin
    1207959553U,	// BL8_ELF
    1207959555U,	// BLA8_Darwin
    1207959555U,	// BLA8_ELF
    1207959555U,	// BLA_Darwin
    1207959555U,	// BLA_SVR4
    1275068448U,	// BLR
    1207959553U,	// BL_Darwin
    1207959553U,	// BL_SVR4
    2082471936U,	// CMPD
    740294656U,	// CMPDI
    2082472000U,	// CMPLD
    673185792U,	// CMPLDI
    2080374848U,	// CMPLW
    671088640U,	// CMPLWI
    2080374784U,	// CMPW
    738197504U,	// CMPWI
    2080374900U,	// CNTLZD
    2080374836U,	// CNTLZW
    1275068994U,	// CREQV
    1275069314U,	// CROR
    1275068994U,	// CRSET
    2080376300U,	// DCBA
    2080374956U,	// DCBF
    2080375724U,	// DCBI
    2080374892U,	// DCBST
    2080375340U,	// DCBT
    2080375276U,	// DCBTST
    2080376812U,	// DCBZ
    2082473964U,	// DCBZL
    2080375762U,	// DIVD
    2080375698U,	// DIVDU
    2080375766U,	// DIVW
    2080375702U,	// DIVWU
    2080376428U,	// DSS
    2080376428U,	// DSSALL
    2080375468U,	// DST
    2080375468U,	// DST64
    2080375532U,	// DSTST
    2080375532U,	// DSTST64
    2080375532U,	// DSTSTT
    2080375532U,	// DSTSTT64
    2080375468U,	// DSTT
    2080375468U,	// DSTT64
    0U,	// DYNALLOC
    0U,	// DYNALLOC8
    2080375352U,	// EQV
    2080375352U,	// EQV8
    2080376692U,	// EXTSB
    2080376692U,	// EXTSB8
    2080376628U,	// EXTSH
    2080376628U,	// EXTSH8
    2080376756U,	// EXTSW
    2080376756U,	// EXTSW_32
    2080376756U,	// EXTSW_32_64
    4227858960U,	// FABSD
    4227858960U,	// FABSS
    4227858474U,	// FADD
    3959423018U,	// FADDS
    4227858474U,	// FADDrtz
    4227860124U,	// FCFID
    4227858432U,	// FCMPUD
    4227858432U,	// FCMPUS
    4227860062U,	// FCTIDZ
    4227858462U,	// FCTIWZ
    4227858468U,	// FDIV
    3959423012U,	// FDIVS
    4227858490U,	// FMADD
    3959423034U,	// FMADDS
    4227858576U,	// FMR
    4227858488U,	// FMSUB
    3959423032U,	// FMSUBS
    4227858482U,	// FMUL
    3959423026U,	// FMULS
    4227858704U,	// FNABSD
    4227858704U,	// FNABSS
    4227858512U,	// FNEGD
    4227858512U,	// FNEGS
    4227858494U,	// FNMADD
    3959423038U,	// FNMADDS
    4227858492U,	// FNMSUB
    3959423036U,	// FNMSUBS
    4227858456U,	// FRSP
    4227858478U,	// FSELD
    4227858478U,	// FSELS
    4227858476U,	// FSQRT
    3959423020U,	// FSQRTS
    4227858472U,	// FSUB
    3959423016U,	// FSUBS
    939524096U,	// LA
    2281701376U,	// LBZ
    2281701376U,	// LBZ8
    2348810240U,	// LBZU
    2348810240U,	// LBZU8
    2080374958U,	// LBZX
    2080374958U,	// LBZX8
    3892314112U,	// LD
    2080374952U,	// LDARX
    3892314113U,	// LDU
    2080374826U,	// LDX
    3896508448U,	// LDinto_toc
    3892314112U,	// LDtoc
    3896574112U,	// LDtoc_restore
    3355443200U,	// LFD
    3422552064U,	// LFDU
    2080375982U,	// LFDX
    3221225472U,	// LFS
    3288334336U,	// LFSU
    2080375854U,	// LFSX
    2818572288U,	// LHA
    2818572288U,	// LHA8
    2885681152U,	// LHAU
    2885681152U,	// LHAU8
    2080375470U,	// LHAX
    2080375470U,	// LHAX8
    2080376364U,	// LHBRX
    2684354560U,	// LHZ
    2684354560U,	// LHZ8
    2751463424U,	// LHZU
    2751463424U,	// LHZU8
    2080375342U,	// LHZX
    2080375342U,	// LHZX8
    939524096U,	// LI
    939524096U,	// LI8
    1006632960U,	// LIS
    1006632960U,	// LIS8
    2080374798U,	// LVEBX
    2080374862U,	// LVEHX
    2080374926U,	// LVEWX
    2080374796U,	// LVSL
    2080374860U,	// LVSR
    2080374990U,	// LVX
    2080375502U,	// LVXL
    3892314114U,	// LWA
    2080374824U,	// LWARX
    2080375466U,	// LWAX
    2080375852U,	// LWBRX
    2147483648U,	// LWZ
    2147483648U,	// LWZ8
    2214592512U,	// LWZU
    2214592512U,	// LWZU8
    2080374830U,	// LWZX
    2080374830U,	// LWZX8
    1275068416U,	// MCRF
    2080374822U,	// MFCRpseud
    2080965286U,	// MFCTR
    2080965286U,	// MFCTR8
    4227859598U,	// MFFS
    2080899750U,	// MFLR
    2080899750U,	// MFLR8
    2081423398U,	// MFOCRF
    2080391846U,	// MFVRSAVE
    268436996U,	// MFVSCR
    2080375072U,	// MTCRF
    2080965542U,	// MTCTR
    2080965542U,	// MTCTR8
    4227858572U,	// MTFSB0
    4227858508U,	// MTFSB1
    4227859854U,	// MTFSF
    2080900006U,	// MTLR
    2080900006U,	// MTLR8
    2080392102U,	// MTVRSAVE
    268437060U,	// MTVSCR
    2080374930U,	// MULHD
    2080374802U,	// MULHDU
    2080374934U,	// MULHW
    2080374806U,	// MULHWU
    2080375250U,	// MULLD
    469762048U,	// MULLI
    2080375254U,	// MULLW
    0U,	// MovePCtoLR
    0U,	// MovePCtoLR8
    2080375736U,	// NAND
    2080375736U,	// NAND8
    2080374992U,	// NEG
    2080374992U,	// NEG8
    1610612736U,	// NOP
    2080375032U,	// NOR
    2080375032U,	// NOR8
    2080375672U,	// OR
    2080375672U,	// OR4To8
    2080375672U,	// OR8
    2080375672U,	// OR8To4
    2080375608U,	// ORC
    2080375608U,	// ORC8
    1610612736U,	// ORI
    1610612736U,	// ORI8
    1677721600U,	// ORIS
    1677721600U,	// ORIS8
    2013265920U,	// RLDCL
    2013265920U,	// RLDICL
    2013265924U,	// RLDICR
    2013265932U,	// RLDIMI
    1342177280U,	// RLWIMI
    1409286144U,	// RLWINM
    1409286145U,	// RLWINMo
    1543503872U,	// RLWNM
    0U,	// SELECT_CC_F4
    0U,	// SELECT_CC_F8
    0U,	// SELECT_CC_I4
    0U,	// SELECT_CC_I8
    0U,	// SELECT_CC_VRRC
    2080374838U,	// SLD
    2080374832U,	// SLW
    0U,	// SPILL_CR
    2080376372U,	// SRAD
    2080376436U,	// SRADI
    2080376368U,	// SRAW
    2080376432U,	// SRAWI
    2080375862U,	// SRD
    2080375856U,	// SRW
    2550136832U,	// STB
    2550136832U,	// STB8
    2617245696U,	// STBU
    2550136832U,	// STBU8
    2080375214U,	// STBX
    2080375214U,	// STBX8
    4160749568U,	// STD
    2080375213U,	// STDCX
    4160749569U,	// STDU
    2080375146U,	// STDUX
    2080375082U,	// STDX
    2080375082U,	// STDX_32
    4160749568U,	// STD_32
    3623878656U,	// STFD
    2483027968U,	// STFDU
    2080376238U,	// STFDX
    2080376750U,	// STFIWX
    3489660928U,	// STFS
    2483027968U,	// STFSU
    2080376110U,	// STFSX
    2952790016U,	// STH
    2952790016U,	// STH8
    2080376620U,	// STHBRX
    3019898880U,	// STHU
    3019898880U,	// STHU8
    2080375598U,	// STHX
    2080375598U,	// STHX8
    2080375054U,	// STVEBX
    2080375118U,	// STVEHX
    2080375182U,	// STVEWX
    2080375246U,	// STVX
    2080375758U,	// STVXL
    2415919104U,	// STW
    2415919104U,	// STW8
    2080376108U,	// STWBRX
    2080375085U,	// STWCX
    2483027968U,	// STWU
    2080375150U,	// STWUX
    2080375086U,	// STWX
    2080375086U,	// STWX8
    2080374864U,	// SUBF
    2080374864U,	// SUBF8
    2080374800U,	// SUBFC
    2080374800U,	// SUBFC8
    2080375056U,	// SUBFE
    2080375056U,	// SUBFE8
    536870912U,	// SUBFIC
    536870912U,	// SUBFIC8
    2080375248U,	// SUBFME
    2080375248U,	// SUBFME8
    2080375184U,	// SUBFZE
    2080375184U,	// SUBFZE8
    2080375980U,	// SYNC
    1207959552U,	// TAILB
    1207959552U,	// TAILB8
    1207959552U,	// TAILBA
    1207959552U,	// TAILBA8
    1317012512U,	// TAILBCTR
    1317012512U,	// TAILBCTR8
    0U,	// TCRETURNai
    0U,	// TCRETURNai8
    0U,	// TCRETURNdi
    0U,	// TCRETURNdi8
    0U,	// TCRETURNri
    0U,	// TCRETURNri8
    2145386504U,	// TRAP
    0U,	// UPDATE_VRSAVE
    268435840U,	// VADDCUW
    268435466U,	// VADDFP
    268436224U,	// VADDSBS
    268436288U,	// VADDSHS
    268436352U,	// VADDSWS
    268435456U,	// VADDUBM
    268435968U,	// VADDUBS
    268435520U,	// VADDUHM
    268436032U,	// VADDUHS
    268435584U,	// VADDUWM
    268436096U,	// VADDUWS
    268436484U,	// VAND
    268436548U,	// VANDC
    268436738U,	// VAVGSB
    268436802U,	// VAVGSH
    268436866U,	// VAVGSW
    268436482U,	// VAVGUB
    268436546U,	// VAVGUH
    268436610U,	// VAVGUW
    268436298U,	// VCFSX
    268436234U,	// VCFUX
    268436422U,	// VCMPBFP
    268437446U,	// VCMPBFPo
    268435654U,	// VCMPEQFP
    268436678U,	// VCMPEQFPo
    268435462U,	// VCMPEQUB
    268436486U,	// VCMPEQUBo
    268435526U,	// VCMPEQUH
    268436550U,	// VCMPEQUHo
    268435590U,	// VCMPEQUW
    268436614U,	// VCMPEQUWo
    268435910U,	// VCMPGEFP
    268436934U,	// VCMPGEFPo
    268436166U,	// VCMPGTFP
    268437190U,	// VCMPGTFPo
    268436230U,	// VCMPGTSB
    268437254U,	// VCMPGTSBo
    268436294U,	// VCMPGTSH
    268437318U,	// VCMPGTSHo
    268436358U,	// VCMPGTSW
    268437382U,	// VCMPGTSWo
    268435974U,	// VCMPGTUB
    268436998U,	// VCMPGTUBo
    268436038U,	// VCMPGTUH
    268437062U,	// VCMPGTUHo
    268436102U,	// VCMPGTUW
    268437126U,	// VCMPGTUWo
    268436426U,	// VCTSXS
    268436362U,	// VCTUXS
    268435850U,	// VEXPTEFP
    268435914U,	// VLOGEFP
    268435502U,	// VMADDFP
    268436490U,	// VMAXFP
    268435714U,	// VMAXSB
    268435778U,	// VMAXSH
    268435842U,	// VMAXSW
    268435458U,	// VMAXUB
    268435522U,	// VMAXUH
    268435586U,	// VMAXUW
    268435488U,	// VMHADDSHS
    268435489U,	// VMHRADDSHS
    268436554U,	// VMINFP
    268436226U,	// VMINSB
    268436290U,	// VMINSH
    268436354U,	// VMINSW
    268435970U,	// VMINUB
    268436034U,	// VMINUH
    268436098U,	// VMINUW
    268435490U,	// VMLADDUHM
    268435468U,	// VMRGHB
    268435532U,	// VMRGHH
    268435596U,	// VMRGHW
    268435724U,	// VMRGLB
    268435788U,	// VMRGLH
    268435852U,	// VMRGLW
    268435493U,	// VMSUMMBM
    268435496U,	// VMSUMSHM
    268435497U,	// VMSUMSHS
    268435492U,	// VMSUMUBM
    268435494U,	// VMSUMUHM
    268435495U,	// VMSUMUHS
    268436232U,	// VMULESB
    268436296U,	// VMULESH
    268435976U,	// VMULEUB
    268436040U,	// VMULEUH
    268435720U,	// VMULOSB
    268435784U,	// VMULOSH
    268435464U,	// VMULOUB
    268435528U,	// VMULOUH
    268435503U,	// VNMSUBFP
    268436740U,	// VNOR
    268436612U,	// VOR
    268435499U,	// VPERM
    268436238U,	// VPKPX
    268435854U,	// VPKSHSS
    268435726U,	// VPKSHUS
    268435918U,	// VPKSWSS
    268435790U,	// VPKSWUS
    268435470U,	// VPKUHUM
    268435598U,	// VPKUHUS
    268435534U,	// VPKUWUM
    268435662U,	// VPKUWUS
    268435722U,	// VREFP
    268436170U,	// VRFIM
    268435978U,	// VRFIN
    268436106U,	// VRFIP
    268436042U,	// VRFIZ
    268435460U,	// VRLB
    268435524U,	// VRLH
    268435588U,	// VRLW
    268435786U,	// VRSQRTEFP
    268435498U,	// VSEL
    268435908U,	// VSL
    268435716U,	// VSLB
    268435500U,	// VSLDOI
    268435780U,	// VSLH
    268436492U,	// VSLO
    268435844U,	// VSLW
    268435980U,	// VSPLTB
    268436044U,	// VSPLTH
    268436236U,	// VSPLTISB
    268436300U,	// VSPLTISH
    268436364U,	// VSPLTISW
    268436108U,	// VSPLTW
    268436164U,	// VSR
    268436228U,	// VSRAB
    268436292U,	// VSRAH
    268436356U,	// VSRAW
    268435972U,	// VSRB
    268436036U,	// VSRH
    268436556U,	// VSRO
    268436100U,	// VSRW
    268435530U,	// VSUBCUW
    268435530U,	// VSUBFP
    268437248U,	// VSUBSBS
    268437312U,	// VSUBSHS
    268437376U,	// VSUBSWS
    268436480U,	// VSUBUBM
    268436992U,	// VSUBUBS
    268436544U,	// VSUBUHM
    268437056U,	// VSUBUHS
    268436608U,	// VSUBUWM
    268437120U,	// VSUBUWS
    268437128U,	// VSUM2SWS
    268437128U,	// VSUM4SBS
    268437064U,	// VSUM4SHS
    268437000U,	// VSUM4UBS
    268437384U,	// VSUMSWS
    268436302U,	// VUPKHPX
    268435982U,	// VUPKHSB
    268436046U,	// VUPKHSH
    268436430U,	// VUPKLPX
    268436110U,	// VUPKLSB
    268436174U,	// VUPKLSH
    268436676U,	// VXOR
    268436676U,	// V_SET0
    2080375416U,	// XOR
    2080375416U,	// XOR8
    1744830464U,	// XORI
    1744830464U,	// XORI8
    1811939328U,	// XORIS
    1811939328U,	// XORIS8
    0U
  };
  const unsigned opcode = MI.getOpcode();
  unsigned Value = InstBits[opcode];
  unsigned op = 0;
  op = op;  // suppress warning
  switch (opcode) {
    case PPC::ADJCALLSTACKDOWN:
    case PPC::ADJCALLSTACKUP:
    case PPC::ATOMIC_CMP_SWAP_I16:
    case PPC::ATOMIC_CMP_SWAP_I32:
    case PPC::ATOMIC_CMP_SWAP_I64:
    case PPC::ATOMIC_CMP_SWAP_I8:
    case PPC::ATOMIC_LOAD_ADD_I16:
    case PPC::ATOMIC_LOAD_ADD_I32:
    case PPC::ATOMIC_LOAD_ADD_I64:
    case PPC::ATOMIC_LOAD_ADD_I8:
    case PPC::ATOMIC_LOAD_AND_I16:
    case PPC::ATOMIC_LOAD_AND_I32:
    case PPC::ATOMIC_LOAD_AND_I64:
    case PPC::ATOMIC_LOAD_AND_I8:
    case PPC::ATOMIC_LOAD_NAND_I16:
    case PPC::ATOMIC_LOAD_NAND_I32:
    case PPC::ATOMIC_LOAD_NAND_I64:
    case PPC::ATOMIC_LOAD_NAND_I8:
    case PPC::ATOMIC_LOAD_OR_I16:
    case PPC::ATOMIC_LOAD_OR_I32:
    case PPC::ATOMIC_LOAD_OR_I64:
    case PPC::ATOMIC_LOAD_OR_I8:
    case PPC::ATOMIC_LOAD_SUB_I16:
    case PPC::ATOMIC_LOAD_SUB_I32:
    case PPC::ATOMIC_LOAD_SUB_I64:
    case PPC::ATOMIC_LOAD_SUB_I8:
    case PPC::ATOMIC_LOAD_XOR_I16:
    case PPC::ATOMIC_LOAD_XOR_I32:
    case PPC::ATOMIC_LOAD_XOR_I64:
    case PPC::ATOMIC_LOAD_XOR_I8:
    case PPC::ATOMIC_SWAP_I16:
    case PPC::ATOMIC_SWAP_I32:
    case PPC::ATOMIC_SWAP_I64:
    case PPC::ATOMIC_SWAP_I8:
    case PPC::BCTR:
    case PPC::BCTRL8_Darwin:
    case PPC::BCTRL8_ELF:
    case PPC::BCTRL_Darwin:
    case PPC::BCTRL_SVR4:
    case PPC::DYNALLOC:
    case PPC::DYNALLOC8:
    case PPC::LDtoc_restore:
    case PPC::MovePCtoLR:
    case PPC::MovePCtoLR8:
    case PPC::NOP:
    case PPC::SELECT_CC_F4:
    case PPC::SELECT_CC_F8:
    case PPC::SELECT_CC_I4:
    case PPC::SELECT_CC_I8:
    case PPC::SELECT_CC_VRRC:
    case PPC::SPILL_CR:
    case PPC::SYNC:
    case PPC::TAILBCTR:
    case PPC::TAILBCTR8:
    case PPC::TCRETURNai:
    case PPC::TCRETURNai8:
    case PPC::TCRETURNdi:
    case PPC::TCRETURNdi8:
    case PPC::TCRETURNri:
    case PPC::TCRETURNri8:
    case PPC::TRAP:
    case PPC::UPDATE_VRSAVE: {
      break;
    }
    case PPC::DCBA:
    case PPC::DCBF:
    case PPC::DCBI:
    case PPC::DCBST:
    case PPC::DCBT:
    case PPC::DCBTST:
    case PPC::DCBZ:
    case PPC::DCBZL: {
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::SRADI: {
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      // op: RS
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 21;
      // op: SH
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      Value |= (op & 32U) >> 4;
      break;
    }
    case PPC::CNTLZD:
    case PPC::CNTLZW:
    case PPC::EXTSB:
    case PPC::EXTSB8:
    case PPC::EXTSH:
    case PPC::EXTSH8:
    case PPC::EXTSW:
    case PPC::EXTSW_32:
    case PPC::EXTSW_32_64: {
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      // op: RST
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 21;
      break;
    }
    case PPC::AND:
    case PPC::AND8:
    case PPC::ANDC:
    case PPC::ANDC8:
    case PPC::EQV:
    case PPC::EQV8:
    case PPC::NAND:
    case PPC::NAND8:
    case PPC::NOR:
    case PPC::NOR8:
    case PPC::OR:
    case PPC::OR4To8:
    case PPC::OR8:
    case PPC::OR8To4:
    case PPC::ORC:
    case PPC::ORC8:
    case PPC::SLD:
    case PPC::SLW:
    case PPC::SRAD:
    case PPC::SRAW:
    case PPC::SRAWI:
    case PPC::SRD:
    case PPC::SRW:
    case PPC::XOR:
    case PPC::XOR8: {
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      // op: RST
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 21;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::ADDI:
    case PPC::ADDI8:
    case PPC::ADDIC:
    case PPC::ADDIC8:
    case PPC::ADDICo:
    case PPC::ADDIS:
    case PPC::ADDIS8:
    case PPC::LA:
    case PPC::MULLI:
    case PPC::SUBFIC:
    case PPC::SUBFIC8: {
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: C
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= op & 65535U;
      break;
    }
    case PPC::LI:
    case PPC::LI8:
    case PPC::LIS:
    case PPC::LIS8: {
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= op & 65535U;
      break;
    }
    case PPC::LBZ:
    case PPC::LBZ8:
    case PPC::LFD:
    case PPC::LFS:
    case PPC::LHA:
    case PPC::LHA8:
    case PPC::LHZ:
    case PPC::LHZ8:
    case PPC::LWZ:
    case PPC::LWZ8:
    case PPC::STB:
    case PPC::STB8:
    case PPC::STFD:
    case PPC::STFS:
    case PPC::STH:
    case PPC::STH8:
    case PPC::STW:
    case PPC::STW8: {
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: C
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= op & 65535U;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 16;
      break;
    }
    case PPC::LBZU:
    case PPC::LBZU8:
    case PPC::LFDU:
    case PPC::LFSU:
    case PPC::LHAU:
    case PPC::LHAU8:
    case PPC::LHZU:
    case PPC::LHZU8:
    case PPC::LWZU:
    case PPC::LWZU8: {
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: C
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= op & 65535U;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 16;
      break;
    }
    case PPC::STBU:
    case PPC::STBU8:
    case PPC::STFDU:
    case PPC::STFSU:
    case PPC::STHU:
    case PPC::STHU8:
    case PPC::STWU: {
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 21;
      // op: C
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= op & 65535U;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 16;
      break;
    }
    case PPC::ANDISo:
    case PPC::ANDISo8:
    case PPC::ANDIo:
    case PPC::ANDIo8:
    case PPC::ORI:
    case PPC::ORI8:
    case PPC::ORIS:
    case PPC::ORIS8:
    case PPC::XORI:
    case PPC::XORI8:
    case PPC::XORIS:
    case PPC::XORIS8: {
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 21;
      // op: C
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= op & 65535U;
      break;
    }
    case PPC::MCRF: {
      // op: BF
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 7U) << 23;
      // op: BFA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 7U) << 18;
      break;
    }
    case PPC::FCMPUD:
    case PPC::FCMPUS: {
      // op: BF
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 7U) << 23;
      // op: FRA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: FRB
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::CMPDI:
    case PPC::CMPLDI:
    case PPC::CMPLWI:
    case PPC::CMPWI: {
      // op: BF
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 7U) << 23;
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: I
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= op & 65535U;
      break;
    }
    case PPC::CMPD:
    case PPC::CMPLD:
    case PPC::CMPLW:
    case PPC::CMPW: {
      // op: BF
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 7U) << 23;
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: RB
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::BCC: {
      // op: BIBO
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      Value |= (op & 96U) << 11;
      // op: CR
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 7U) << 18;
      // op: BD
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 16383U) << 2;
      break;
    }
    case PPC::BLR: {
      // op: BIBO
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 4U) << 23;
      Value |= (op & 8U) << 21;
      Value |= (op & 16U) << 19;
      Value |= (op & 32U) << 17;
      Value |= (op & 64U) << 15;
      Value |= (op & 3U) << 16;
      // op: CR
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 1U) << 20;
      Value |= (op & 2U) << 18;
      Value |= (op & 4U) << 16;
      break;
    }
    case PPC::CREQV:
    case PPC::CROR: {
      // op: CRD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: CRA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: CRB
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::CRSET: {
      // op: CRD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      Value |= (op & 31U) << 16;
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::MTFSF: {
      // op: FM
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 255U) << 17;
      // op: RT
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::MTFSB0:
    case PPC::MTFSB1: {
      // op: FM
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      break;
    }
    case PPC::FADD:
    case PPC::FADDS:
    case PPC::FADDrtz:
    case PPC::FDIV:
    case PPC::FDIVS:
    case PPC::FSUB:
    case PPC::FSUBS: {
      // op: FRT
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: FRA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: FRB
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::FMUL:
    case PPC::FMULS: {
      // op: FRT
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: FRA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: FRC
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 6;
      break;
    }
    case PPC::FMADD:
    case PPC::FMADDS:
    case PPC::FMSUB:
    case PPC::FMSUBS:
    case PPC::FNMADD:
    case PPC::FNMADDS:
    case PPC::FNMSUB:
    case PPC::FNMSUBS:
    case PPC::FSELD:
    case PPC::FSELS: {
      // op: FRT
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: FRA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: FRC
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 6;
      // op: FRB
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::MTCRF: {
      // op: FXM
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 255U) << 12;
      // op: ST
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 21;
      break;
    }
    case PPC::B:
    case PPC::BL8_Darwin:
    case PPC::BL8_ELF:
    case PPC::BLA8_Darwin:
    case PPC::BLA8_ELF:
    case PPC::BLA_Darwin:
    case PPC::BLA_SVR4:
    case PPC::BL_Darwin:
    case PPC::BL_SVR4:
    case PPC::TAILB:
    case PPC::TAILB8:
    case PPC::TAILBA:
    case PPC::TAILBA8: {
      // op: LI
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 16777215U) << 2;
      break;
    }
    case PPC::LDinto_toc: {
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      break;
    }
    case PPC::RLWINM:
    case PPC::RLWINMo:
    case PPC::RLWNM: {
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      // op: RS
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 21;
      // op: RB
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      // op: MB
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 6;
      // op: ME
      op = getMachineOpValue(MI, MI.getOperand(4));
      Value |= (op & 31U) << 1;
      break;
    }
    case PPC::RLDCL:
    case PPC::RLDICL:
    case PPC::RLDICR: {
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      // op: RS
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 21;
      // op: SH
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      Value |= (op & 32U) >> 4;
      // op: MBE
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 6;
      Value |= op & 32U;
      break;
    }
    case PPC::RLWIMI: {
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      // op: RS
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 21;
      // op: RB
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 11;
      // op: MB
      op = getMachineOpValue(MI, MI.getOperand(4));
      Value |= (op & 31U) << 6;
      // op: ME
      op = getMachineOpValue(MI, MI.getOperand(5));
      Value |= (op & 31U) << 1;
      break;
    }
    case PPC::RLDIMI: {
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 16;
      // op: RS
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 21;
      // op: SH
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 11;
      Value |= (op & 32U) >> 4;
      // op: MBE
      op = getMachineOpValue(MI, MI.getOperand(4));
      Value |= (op & 31U) << 6;
      Value |= op & 32U;
      break;
    }
    case PPC::MFFS: {
      // op: RST
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      break;
    }
    case PPC::LBZX:
    case PPC::LBZX8:
    case PPC::LDARX:
    case PPC::LDX:
    case PPC::LFDX:
    case PPC::LFSX:
    case PPC::LHAX:
    case PPC::LHAX8:
    case PPC::LHBRX:
    case PPC::LHZX:
    case PPC::LHZX8:
    case PPC::LVEBX:
    case PPC::LVEHX:
    case PPC::LVEWX:
    case PPC::LVSL:
    case PPC::LVSR:
    case PPC::LVX:
    case PPC::LVXL:
    case PPC::LWARX:
    case PPC::LWAX:
    case PPC::LWBRX:
    case PPC::LWZX:
    case PPC::LWZX8:
    case PPC::STBX:
    case PPC::STBX8:
    case PPC::STDCX:
    case PPC::STDUX:
    case PPC::STDX:
    case PPC::STDX_32:
    case PPC::STFDX:
    case PPC::STFIWX:
    case PPC::STFSX:
    case PPC::STHBRX:
    case PPC::STHX:
    case PPC::STHX8:
    case PPC::STVEBX:
    case PPC::STVEHX:
    case PPC::STVEWX:
    case PPC::STVX:
    case PPC::STVXL:
    case PPC::STWBRX:
    case PPC::STWCX:
    case PPC::STWUX:
    case PPC::STWX:
    case PPC::STWX8: {
      // op: RST
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::FABSD:
    case PPC::FABSS:
    case PPC::FCFID:
    case PPC::FCTIDZ:
    case PPC::FCTIWZ:
    case PPC::FMR:
    case PPC::FNABSD:
    case PPC::FNABSS:
    case PPC::FNEGD:
    case PPC::FNEGS:
    case PPC::FRSP:
    case PPC::FSQRT:
    case PPC::FSQRTS: {
      // op: RST
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::LD:
    case PPC::LDtoc:
    case PPC::LWA:
    case PPC::STD:
    case PPC::STD_32: {
      // op: RST
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: DS
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 16383U) << 2;
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 16;
      break;
    }
    case PPC::LDU: {
      // op: RST
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: DS
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 16383U) << 2;
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 16;
      break;
    }
    case PPC::STDU: {
      // op: RST
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 21;
      // op: DS
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 16383U) << 2;
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 16;
      break;
    }
    case PPC::MFCRpseud:
    case PPC::MFCTR:
    case PPC::MFCTR8:
    case PPC::MFLR:
    case PPC::MFLR8:
    case PPC::MFVRSAVE:
    case PPC::MTCTR:
    case PPC::MTCTR8:
    case PPC::MTLR:
    case PPC::MTLR8:
    case PPC::MTVRSAVE: {
      // op: RT
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      break;
    }
    case PPC::ADDME:
    case PPC::ADDME8:
    case PPC::ADDZE:
    case PPC::ADDZE8:
    case PPC::NEG:
    case PPC::NEG8:
    case PPC::SUBFME:
    case PPC::SUBFME8:
    case PPC::SUBFZE:
    case PPC::SUBFZE8: {
      // op: RT
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      break;
    }
    case PPC::ADD4:
    case PPC::ADD8:
    case PPC::ADDC:
    case PPC::ADDC8:
    case PPC::ADDE:
    case PPC::ADDE8:
    case PPC::DIVD:
    case PPC::DIVDU:
    case PPC::DIVW:
    case PPC::DIVWU:
    case PPC::MULHD:
    case PPC::MULHDU:
    case PPC::MULHW:
    case PPC::MULHWU:
    case PPC::MULLD:
    case PPC::MULLW:
    case PPC::SUBF:
    case PPC::SUBF8:
    case PPC::SUBFC:
    case PPC::SUBFC8:
    case PPC::SUBFE:
    case PPC::SUBFE8: {
      // op: RT
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: RA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: RB
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::MFOCRF: {
      // op: ST
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: FXM
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 255U) << 12;
      break;
    }
    case PPC::DSS:
    case PPC::DSSALL:
    case PPC::DST:
    case PPC::DST64:
    case PPC::DSTST:
    case PPC::DSTST64:
    case PPC::DSTSTT:
    case PPC::DSTSTT64:
    case PPC::DSTT:
    case PPC::DSTT64: {
      // op: T
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 1U) << 25;
      // op: STRM
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 3U) << 21;
      // op: A
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 16;
      // op: B
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::MTVSCR: {
      // op: VB
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::MFVSCR: {
      // op: VD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      break;
    }
    case PPC::VSPLTISB:
    case PPC::VSPLTISH:
    case PPC::VSPLTISW: {
      // op: VD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: IMM
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      break;
    }
    case PPC::VADDCUW:
    case PPC::VADDFP:
    case PPC::VADDSBS:
    case PPC::VADDSHS:
    case PPC::VADDSWS:
    case PPC::VADDUBM:
    case PPC::VADDUBS:
    case PPC::VADDUHM:
    case PPC::VADDUHS:
    case PPC::VADDUWM:
    case PPC::VADDUWS:
    case PPC::VAND:
    case PPC::VANDC:
    case PPC::VAVGSB:
    case PPC::VAVGSH:
    case PPC::VAVGSW:
    case PPC::VAVGUB:
    case PPC::VAVGUH:
    case PPC::VAVGUW:
    case PPC::VCFSX:
    case PPC::VCFUX:
    case PPC::VCMPBFP:
    case PPC::VCMPBFPo:
    case PPC::VCMPEQFP:
    case PPC::VCMPEQFPo:
    case PPC::VCMPEQUB:
    case PPC::VCMPEQUBo:
    case PPC::VCMPEQUH:
    case PPC::VCMPEQUHo:
    case PPC::VCMPEQUW:
    case PPC::VCMPEQUWo:
    case PPC::VCMPGEFP:
    case PPC::VCMPGEFPo:
    case PPC::VCMPGTFP:
    case PPC::VCMPGTFPo:
    case PPC::VCMPGTSB:
    case PPC::VCMPGTSBo:
    case PPC::VCMPGTSH:
    case PPC::VCMPGTSHo:
    case PPC::VCMPGTSW:
    case PPC::VCMPGTSWo:
    case PPC::VCMPGTUB:
    case PPC::VCMPGTUBo:
    case PPC::VCMPGTUH:
    case PPC::VCMPGTUHo:
    case PPC::VCMPGTUW:
    case PPC::VCMPGTUWo:
    case PPC::VCTSXS:
    case PPC::VCTUXS:
    case PPC::VMAXFP:
    case PPC::VMAXSB:
    case PPC::VMAXSH:
    case PPC::VMAXSW:
    case PPC::VMAXUB:
    case PPC::VMAXUH:
    case PPC::VMAXUW:
    case PPC::VMINFP:
    case PPC::VMINSB:
    case PPC::VMINSH:
    case PPC::VMINSW:
    case PPC::VMINUB:
    case PPC::VMINUH:
    case PPC::VMINUW:
    case PPC::VMRGHB:
    case PPC::VMRGHH:
    case PPC::VMRGHW:
    case PPC::VMRGLB:
    case PPC::VMRGLH:
    case PPC::VMRGLW:
    case PPC::VMULESB:
    case PPC::VMULESH:
    case PPC::VMULEUB:
    case PPC::VMULEUH:
    case PPC::VMULOSB:
    case PPC::VMULOSH:
    case PPC::VMULOUB:
    case PPC::VMULOUH:
    case PPC::VNOR:
    case PPC::VOR:
    case PPC::VPKPX:
    case PPC::VPKSHSS:
    case PPC::VPKSHUS:
    case PPC::VPKSWSS:
    case PPC::VPKSWUS:
    case PPC::VPKUHUM:
    case PPC::VPKUHUS:
    case PPC::VPKUWUM:
    case PPC::VPKUWUS:
    case PPC::VRLB:
    case PPC::VRLH:
    case PPC::VRLW:
    case PPC::VSL:
    case PPC::VSLB:
    case PPC::VSLH:
    case PPC::VSLO:
    case PPC::VSLW:
    case PPC::VSPLTB:
    case PPC::VSPLTH:
    case PPC::VSPLTW:
    case PPC::VSR:
    case PPC::VSRAB:
    case PPC::VSRAH:
    case PPC::VSRAW:
    case PPC::VSRB:
    case PPC::VSRH:
    case PPC::VSRO:
    case PPC::VSRW:
    case PPC::VSUBCUW:
    case PPC::VSUBFP:
    case PPC::VSUBSBS:
    case PPC::VSUBSHS:
    case PPC::VSUBSWS:
    case PPC::VSUBUBM:
    case PPC::VSUBUBS:
    case PPC::VSUBUHM:
    case PPC::VSUBUHS:
    case PPC::VSUBUWM:
    case PPC::VSUBUWS:
    case PPC::VSUM2SWS:
    case PPC::VSUM4SBS:
    case PPC::VSUM4SHS:
    case PPC::VSUM4UBS:
    case PPC::VSUMSWS:
    case PPC::VXOR: {
      // op: VD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: VA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: VB
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::VSLDOI: {
      // op: VD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: VA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: VB
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      // op: SH
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 15U) << 6;
      break;
    }
    case PPC::VMHADDSHS:
    case PPC::VMHRADDSHS:
    case PPC::VMLADDUHM:
    case PPC::VMSUMMBM:
    case PPC::VMSUMSHM:
    case PPC::VMSUMSHS:
    case PPC::VMSUMUBM:
    case PPC::VMSUMUHM:
    case PPC::VMSUMUHS:
    case PPC::VPERM:
    case PPC::VSEL: {
      // op: VD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: VA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: VB
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 11;
      // op: VC
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 6;
      break;
    }
    case PPC::VMADDFP:
    case PPC::VNMSUBFP: {
      // op: VD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: VA
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 16;
      // op: VC
      op = getMachineOpValue(MI, MI.getOperand(2));
      Value |= (op & 31U) << 6;
      // op: VB
      op = getMachineOpValue(MI, MI.getOperand(3));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::VEXPTEFP:
    case PPC::VLOGEFP:
    case PPC::VREFP:
    case PPC::VRFIM:
    case PPC::VRFIN:
    case PPC::VRFIP:
    case PPC::VRFIZ:
    case PPC::VRSQRTEFP:
    case PPC::VUPKHPX:
    case PPC::VUPKHSB:
    case PPC::VUPKHSH:
    case PPC::VUPKLPX:
    case PPC::VUPKLSB:
    case PPC::VUPKLSH: {
      // op: VD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      // op: VB
      op = getMachineOpValue(MI, MI.getOperand(1));
      Value |= (op & 31U) << 11;
      break;
    }
    case PPC::V_SET0: {
      // op: VD
      op = getMachineOpValue(MI, MI.getOperand(0));
      Value |= (op & 31U) << 21;
      Value |= (op & 31U) << 16;
      Value |= (op & 31U) << 11;
      break;
    }
  default:
    std::string msg;
    raw_string_ostream Msg(msg);
    Msg << "Not supported instr: " << MI;
    report_fatal_error(Msg.str());
  }
  return Value;
}

