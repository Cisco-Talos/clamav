#*****************************************************************************
#                                                                            *
# Make file for VMS                                                          *
# Author : J.Jansen (joukj@hrem.nano.tudelft.nl)                             *
# Date : 20 April 2010                                                       *
#                                                                            *
#*****************************************************************************

.first
	define wx [----.include.wx]

.suffixes : .cpp

.ifdef __WXMOTIF__
CXX_DEFINE = /define=(__WX__=1,__WXMOTIF__=1)/name=(as_is,short)\
	   /assume=(nostdnew,noglobal_array_new)/include=([],[-.src],[-.include])
CC_DEFINE = /define=(__WX__=1,__WXMOTIF__=1)/name=(as_is,short)\
	/include=([],[-.src],[-.include])
.else
.ifdef __WXGTK__
CXX_DEFINE = /define=(__WX__=1,__WXGTK__=1)/float=ieee/name=(as_is,short)/ieee=denorm\
	   /assume=(nostdnew,noglobal_array_new)/include=([],[-.src],[-.include])
CC_DEFINE = /define=(__WX__=1,__WXGTK__=1)/float=ieee/name=(as_is,short)/ieee=denorm\
	/include=([],[-.src],[-.include])
.else
.ifdef __WXGTK2__
CXX_DEFINE = /define=(__WX__=1,__WXGTK__=1,VMS_GTK2=1)/float=ieee/name=(as_is,short)/ieee=denorm\
	   /assume=(nostdnew,noglobal_array_new)/include=([],[-.src],[-.include])
CC_DEFINE = /define=(__WX__=1,__WXGTK__=1,VMS_GTK2=1)/float=ieee/name=(as_is,short)\
	/ieee=denorm/include=([],[-.src],[-.include])
.else
.ifdef __WXX11__
CXX_DEFINE = /define=(__WX__=1,__WXX11__=1,__WXUNIVERSAL__==1)/float=ieee\
	/name=(as_is,short)/assume=(nostdnew,noglobal_array_new)\
	/include=([],[-.src],[-.include])
CC_DEFINE = /define=(__WX__=1,__WXX11__=1,__WXUNIVERSAL__==1)/float=ieee\
	/name=(as_is,short)/include=([],[-.src],[-.include])
.else
CXX_DEFINE =
CC_DEFINE =
.endif
.endif
.endif
.endif

.cxx.obj :
	cxx $(CXXFLAGS)$(CXX_DEFINE) $(MMS$TARGET_NAME).cxx
.cpp.obj :
	cxx $(CXXFLAGS)$(CXX_DEFINE) $(MMS$TARGET_NAME).cpp
.c.obj :
	cc $(CFLAGS)$(CC_DEFINE) $(MMS$TARGET_NAME).c

OBJECTS=AutoComplete.obj,CallTip.obj,CellBuffer.obj,CharClassify.obj,\
	ContractionState.obj,Decoration.obj,Document.obj,DocumentAccessor.obj,\
	Editor.obj,ExternalLexer.obj,Indicator.obj,KeyMap.obj,KeyWords.obj,\
	LexAbaqus.obj,LexAda.obj,LexAPDL.obj,LexAsm.obj,LexAsn1.obj,\
	LexASY.obj,LexAU3.obj,LexAVE.obj,LexBaan.obj,LexBash.obj,LexBasic.obj,\
	LexBullant.obj,LexCaml.obj,LexCLW.obj,LexCmake.obj,LexConf.obj,\
	LexCPP.obj,LexCrontab.obj,LexCsound.obj,LexCSS.obj,LexD.obj,\
	LexEiffel.obj,LexErlang.obj,LexEScript.obj,LexFlagship.obj,\
	LexForth.obj,LexFortran.obj,LexGAP.obj,LexGui4Cli.obj,LexHaskell.obj

OBJECTS1=LexHTML.obj,LexInno.obj,LexKix.obj,LexLisp.obj,LexLout.obj,LexLua.obj,\
        LexMatlab.obj,LexMetapost.obj,LexMMIXAL.obj,LexMPT.obj,LexMSSQL.obj,\
	LexNsis.obj,LexOpal.obj,LexOthers.obj,LexPascal.obj,LexPB.obj,\
	LexPerl.obj,LexPLM.obj,LexPOV.obj,LexProgress.obj,LexPS.obj,\
	LexPython.obj,LexR.obj,LexRebol.obj,LexRuby.obj,LexScriptol.obj,\
	LexSmalltalk.obj,LexSpecman.obj,LexSpice.obj,LexSQL.obj,LexTADS3.obj,\
	LexTCL.obj,LexTeX.obj,LexVB.obj,LexVerilog.obj,LexVHDL.obj,\
	LexYAML.obj,LineMarker.obj,PositionCache.obj,PropSet.obj,RESearch.obj,\
	RunStyles.obj,ScintillaBase.obj,Style.obj,StyleContext.obj,\
	UniConversion.obj,ViewStyle.obj,WindowAccessor.obj,XPM.obj,\
	PerLine.obj,Selection.obj,LexPowerPro.obj,LexCOBOL.obj,\
	LexMagik.obj,LexMarkdown.obj,LexMySQL.obj,LexNimrod.obj,\
	LexPowerShell.obj,LexSML.obj,LexSorcus.obj,LexTACL.obj,LexTAL.obj

SOURCES=AutoComplete.cxx,CallTip.cxx,CellBuffer.cxx,CharClassify.cxx,\
	ContractionState.cxx,Decoration.cxx,Document.cxx,DocumentAccessor.cxx,\
	Editor.cxx,ExternalLexer.cxx,Indicator.cxx,KeyMap.cxx,KeyWords.cxx,\
	LexAbaqus.cxx,LexAda.cxx,LexAPDL.cxx,LexAsm.cxx,LexAsn1.cxx,\
	LexASY.cxx,LexAU3.cxx,LexAVE.cxx,LexBaan.cxx,LexBash.cxx,LexBasic.cxx,\
	LexBullant.cxx,LexCaml.cxx,LexCLW.cxx,LexCmake.cxx,LexConf.cxx,\
	LexCPP.cxx,LexCrontab.cxx,LexCsound.cxx,LexCSS.cxx,LexD.cxx,\
	LexEiffel.cxx,LexErlang.cxx,LexEScript.cxx,LexFlagship.cxx,\
	LexForth.cxx,LexFortran.cxx,LexGAP.cxx,LexGui4Cli.cxx,LexHaskell.cxx,\
	LexHTML.cxx,LexInno.cxx,LexKix.cxx,LexLisp.cxx,LexLout.cxx,LexLua.cxx,\
        LexMatlab.cxx,LexMetapost.cxx,LexMMIXAL.cxx,LexMPT.cxx,LexMSSQL.cxx,\
	LexNsis.cxx,LexOpal.cxx,LexOthers.cxx,LexPascal.cxx,LexPB.cxx,\
	LexPerl.cxx,LexPLM.cxx,LexPOV.cxx,LexProgress.cxx,LexPS.cxx,\
	LexPython.cxx,LexR.cxx,LexRebol.cxx,LexRuby.cxx,LexScriptol.cxx,\
	LexSmalltalk.cxx,LexSpecman.cxx,LexSpice.cxx,LexSQL.cxx,LexTADS3.cxx,\
	LexTCL.cxx,LexTeX.cxx,LexVB.cxx,LexVerilog.cxx,LexVHDL.cxx,\
	LexYAML.cxx,LineMarker.cxx,PositionCache.cxx,PropSet.cxx,RESearch.cxx,\
	RunStyles.cxx,ScintillaBase.cxx,Style.cxx,StyleContext.cxx,\
	UniConversion.cxx,ViewStyle.cxx,WindowAccessor.cxx,XPM.cxx,\
	PerLine.cxx,Selection.cxx,LexPowerPro.cxx,LexCOBOL.cxx,\
	LexMagik.cxx,LexMarkdown.cxx,LexMySQL.cxx,LexNimrod.cxx,\
	LexPowerShell.cxx,LexSML.cxx,LexSorcus.cxx,LexTACL.cxx,LexTAL.cxx

all : $(SOURCES)
	$(MMS)$(MMSQUALIFIERS) $(OBJECTS)
	$(MMS)$(MMSQUALIFIERS) $(OBJECTS1)
.ifdef __WXMOTIF__
	library [----.lib]libwx_motif.olb $(OBJECTS)
	library [----.lib]libwx_motif.olb $(OBJECTS1)
	library [----.lib]libwx_motif.olb [.CXX_REPOSITORY]*.obj
.else
.ifdef __WXGTK__
	library [----.lib]libwx_gtk.olb $(OBJECTS)
	library [----.lib]libwx_gtk.olb $(OBJECTS1)
	library [----.lib]libwx_gtk.olb [.CXX_REPOSITORY]*.obj
.else
.ifdef __WXGTK2__
	library [----.lib]libwx_gtk2.olb $(OBJECTS)
	library [----.lib]libwx_gtk2.olb $(OBJECTS1)
	library [----.lib]libwx_gtk2.olb [.CXX_REPOSITORY]*.obj
.else
.ifdef __WXX11__
	library [----.lib]libwx_x11_univ.olb $(OBJECTS)
	library [----.lib]libwx_x11_univ.olb $(OBJECTS1)
	library [----.lib]libwx_x11_univ.olb [.CXX_REPOSITORY]*.obj
.endif
.endif
.endif
.endif

AutoComplete.obj : AutoComplete.cxx
CallTip.obj : CallTip.cxx
CellBuffer.obj : CellBuffer.cxx
CharClassify.obj : CharClassify.cxx
ContractionState.obj : ContractionState.cxx
Decoration.obj : Decoration.cxx
Document.obj : Document.cxx
DocumentAccessor.obj : DocumentAccessor.cxx
Editor.obj : Editor.cxx
	cxx $(CXXFLAGS)$(CXX_DEFINE)/nowarn Editor.cxx
ExternalLexer.obj : ExternalLexer.cxx
Indicator.obj : Indicator.cxx
KeyMap.obj : KeyMap.cxx
KeyWords.obj : KeyWords.cxx
LexAbaqus.obj : LexAbaqus.cxx
LexAda.obj : LexAda.cxx
LexAPDL.obj : LexAPDL.cxx
LexAsm.obj : LexAsm.cxx
LexAsn1.obj : LexAsn1.cxx
LexASY.obj : LexASY.cxx
LexAU3.obj : LexAU3.cxx
LexAVE.obj : LexAVE.cxx
LexBaan.obj : LexBaan.cxx
LexBash.obj : LexBash.cxx
LexBasic.obj : LexBasic.cxx
LexBullant.obj : LexBullant.cxx
LexCaml.obj : LexCaml.cxx
LexCLW.obj : LexCLW.cxx
LexCmake.obj : LexCmake.cxx
LexConf.obj : LexConf.cxx
LexCPP.obj : LexCPP.cxx
LexCrontab.obj : LexCrontab.cxx
LexCsound.obj : LexCsound.cxx
LexCSS.obj : LexCSS.cxx
LexD.obj : LexD.cxx
	cxx $(CXXFLAGS)$(CXX_DEFINE)/nowarn LexD.cxx
LexEiffel.obj : LexEiffel.cxx
LexErlang.obj : LexErlang.cxx
LexEScript.obj : LexEScript.cxx
LexFlagship.obj : LexFlagship.cxx
LexForth.obj : LexForth.cxx
LexFortran.obj : LexFortran.cxx
LexGAP.obj : LexGAP.cxx
LexGui4Cli.obj : LexGui4Cli.cxx
LexHaskell.obj : LexHaskell.cxx
LexHTML.obj : LexHTML.cxx
LexInno.obj : LexInno.cxx
LexKix.obj : LexKix.cxx
LexLisp.obj : LexLisp.cxx
LexLout.obj : LexLout.cxx
LexLua.obj : LexLua.cxx
LexMatlab.obj : LexMatlab.cxx
LexMetapost.obj : LexMetapost.cxx
LexMMIXAL.obj : LexMMIXAL.cxx
LexMPT.obj : LexMPT.cxx
LexMSSQL.obj : LexMSSQL.cxx
LexNsis.obj : LexNsis.cxx
LexOpal.obj : LexOpal.cxx
LexOthers.obj : LexOthers.cxx
LexPascal.obj : LexPascal.cxx
LexPB.obj : LexPB.cxx
LexPerl.obj : LexPerl.cxx
LexPLM.obj : LexPLM.cxx
LexPOV.obj : LexPOV.cxx
LexProgress.obj : LexProgress.cxx
LexPS.obj : LexPS.cxx
LexPython.obj : LexPython.cxx
LexR.obj : LexR.cxx
LexRebol.obj : LexRebol.cxx
LexRuby.obj : LexRuby.cxx
LexScriptol.obj : LexScriptol.cxx
LexSmalltalk.obj : LexSmalltalk.cxx
LexSpecman.obj : LexSpecman.cxx
LexSpice.obj : LexSpice.cxx
LexSQL.obj : LexSQL.cxx
LexTADS3.obj : LexTADS3.cxx
LexTCL.obj : LexTCL.cxx
LexTeX.obj : LexTeX.cxx
LexVB.obj : LexVB.cxx
LexVerilog.obj : LexVerilog.cxx
LexVHDL.obj : LexVHDL.cxx
LexYAML.obj : LexYAML.cxx
LineMarker.obj : LineMarker.cxx
PositionCache.obj : PositionCache.cxx
PropSet.obj : PropSet.cxx
RESearch.obj : RESearch.cxx
RunStyles.obj : RunStyles.cxx
ScintillaBase.obj : ScintillaBase.cxx
Style.obj : Style.cxx
StyleContext.obj : StyleContext.cxx
UniConversion.obj : UniConversion.cxx
ViewStyle.obj : ViewStyle.cxx
WindowAccessor.obj : WindowAccessor.cxx
XPM.obj : XPM.cxx
PerLine.obj : PerLine.cxx
Selection.obj : Selection.cxx
LexPowerPro.obj : LexPowerPro.cxx
LexCOBOL.obj : LexCOBOL.cxx
LexMagik.obj : LexMagik.cxx
LexMarkdown.obj : LexMarkdown.cxx
LexMySQL.obj : LexMySQL.cxx
LexNimrod.obj : LexNimrod.cxx
LexPowerShell.obj : LexPowerShell.cxx
LexSML.obj : LexSML.cxx
LexSorcus.obj : LexSorcus.cxx
LexTACL.obj : LexTACL.cxx
LexTAL.obj : LexTAL.cxx
