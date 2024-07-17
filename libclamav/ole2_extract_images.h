#ifndef OLE2_EXTRACT_IMAGES_H_
#define OLE2_EXTRACT_IMAGES_H_

typedef struct __attribute__((packed)) {
    uint32_t fcStshfOrig;
    uint32_t lcbStshfOrig;
    uint32_t fcStshf;
    uint32_t lcbStshf;
    uint32_t fcPlcffndRef;
    uint32_t lcbPlcffndRef;
    uint32_t fcPlcffndTxt;
    uint32_t lcbPlcffndTxt;
    uint32_t fcPlcfandRef;
    uint32_t lcbPlcfandRef;
    uint32_t fcPlcfandTxt;
    uint32_t lcbPlcfandTxt;
    uint32_t fcPlcfSed;
    uint32_t lcbPlcfSed;
    uint32_t fcPlcPad;
    uint32_t lcbPlcPad;
    uint32_t fcPlcfPhe;
    uint32_t lcbPlcfPhe;
    uint32_t fcSttbfGlsy;
    uint32_t lcbSttbfGlsy;
    uint32_t fcPlcfGlsy;
    uint32_t lcbPlcfGlsy;
    uint32_t fcPlcfHdd;
    uint32_t lcbPlcfHdd;
    uint32_t fcPlcfBteChpx;
    uint32_t lcbPlcfBteChpx;
    uint32_t fcPlcfBtePapx;
    uint32_t lcbPlcfBtePapx;
    uint32_t fcPlcfSea;
    uint32_t lcbPlcfSea;
    uint32_t fcSttbfFfn;
    uint32_t lcbSttbfFfn;
    uint32_t fcPlcfFldMom;
    uint32_t lcbPlcfFldMom;
    uint32_t fcPlcfFldHdr;
    uint32_t lcbPlcfFldHdr;
    uint32_t fcPlcfFldFtn;
    uint32_t lcbPlcfFldFtn;
    uint32_t fcPlcfFldAtn;
    uint32_t lcbPlcfFldAtn;
    uint32_t fcPlcfFldMcr;
    uint32_t lcbPlcfFldMcr;
    uint32_t fcSttbfBkmk;
    uint32_t lcbSttbfBkmk;
    uint32_t fcPlcfBkf;
    uint32_t lcbPlcfBkf;
    uint32_t fcPlcfBkl;
    uint32_t lcbPlcfBkl;
    uint32_t fcCmds;
    uint32_t lcbCmds;
    uint32_t fcUnused1;
    uint32_t lcbUnused1;
    uint32_t fcSttbfMcr;
    uint32_t lcbSttbfMcr;
    uint32_t fcPrDrvr;
    uint32_t lcbPrDrvr;
    uint32_t fcPrEnvPort;
    uint32_t lcbPrEnvPort;
    uint32_t fcPrEnvLand;
    uint32_t lcbPrEnvLand;
    uint32_t fcWss;
    uint32_t lcbWss;
    uint32_t fcDop;
    uint32_t lcbDop;
    uint32_t fcSttbfAssoc;
    uint32_t lcbSttbfAssoc;
    uint32_t fcClx;
    uint32_t lcbClx;
    uint32_t fcPlcfPgdFtn;
    uint32_t lcbPlcfPgdFtn;
    uint32_t fcAutosaveSource;
    uint32_t lcbAutosaveSource;
    uint32_t fcGrpXstAtnOwners;
    uint32_t lcbGrpXstAtnOwners;
    uint32_t fcSttbfAtnBkmk;
    uint32_t lcbSttbfAtnBkmk;
    uint32_t fcUnused2;
    uint32_t lcbUnused2;
    uint32_t fcUnused3;
    uint32_t lcbUnused3;
    uint32_t fcPlcSpaMom;
    uint32_t lcbPlcSpaMom;
    uint32_t fcPlcSpaHdr;
    uint32_t lcbPlcSpaHdr;
    uint32_t fcPlcfAtnBkf;
    uint32_t lcbPlcfAtnBkf;
    uint32_t fcPlcfAtnBkl;
    uint32_t lcbPlcfAtnBkl;
    uint32_t fcPms;
    uint32_t lcbPms;
    uint32_t fcFormFldSttbs;
    uint32_t lcbFormFldSttbs;
    uint32_t fcPlcfendRef;
    uint32_t lcbPlcfendRef;
    uint32_t fcPlcfendTxt;
    uint32_t lcbPlcfendTxt;
    uint32_t fcPlcfFldEdn;
    uint32_t lcbPlcfFldEdn;
    uint32_t fcUnused4;
    uint32_t lcbUnused4;
    uint32_t fcDggInfo;
    uint32_t lcbDggInfo;
    uint32_t fcSttbfRMark;
    uint32_t lcbSttbfRMark;
    uint32_t fcSttbfCaption;
    uint32_t lcbSttbfCaption;
    uint32_t fcSttbfAutoCaption;
    uint32_t lcbSttbfAutoCaption;
    uint32_t fcPlcfWkb;
    uint32_t lcbPlcfWkb;
    uint32_t fcPlcfSpl;
    uint32_t lcbPlcfSpl;
    uint32_t fcPlcftxbxTxt;
    uint32_t lcbPlcftxbxTxt;
    uint32_t fcPlcfFldTxbx;
    uint32_t lcbPlcfFldTxbx;
    uint32_t fcPlcfHdrtxbxTxt;
    uint32_t lcbPlcfHdrtxbxTxt;
    uint32_t fcPlcffldHdrTxbx;
    uint32_t lcbPlcffldHdrTxbx;
    uint32_t fcStwUser;
    uint32_t lcbStwUser;
    uint32_t fcSttbTtmbd;
    uint32_t lcbSttbTtmbd;
    uint32_t fcCookieData;
    uint32_t lcbCookieData;
    uint32_t fcPgdMotherOldOld;
    uint32_t lcbPgdMotherOldOld;
    uint32_t fcBkdMotherOldOld;
    uint32_t lcbBkdMotherOldOld;
    uint32_t fcPgdFtnOldOld;
    uint32_t lcbPgdFtnOldOld;
    uint32_t fcBkdFtnOldOld;
    uint32_t lcbBkdFtnOldOld;
    uint32_t fcPgdEdnOldOld;
    uint32_t lcbPgdEdnOldOld;
    uint32_t fcBkdEdnOldOld;
    uint32_t lcbBkdEdnOldOld;
    uint32_t fcSttbfIntlFld;
    uint32_t lcbSttbfIntlFld;
    uint32_t fcRouteSlip;
    uint32_t lcbRouteSlip;
    uint32_t fcSttbSavedBy;
    uint32_t lcbSttbSavedBy;
    uint32_t fcSttbFnm;
    uint32_t lcbSttbFnm;
    uint32_t fcPlfLst;
    uint32_t lcbPlfLst;
    uint32_t fcPlfLfo;
    uint32_t lcbPlfLfo;
    uint32_t fcPlcfTxbxBkd;
    uint32_t lcbPlcfTxbxBkd;
    uint32_t fcPlcfTxbxHdrBkd;
    uint32_t lcbPlcfTxbxHdrBkd;
    uint32_t fcDocUndoWord9;
    uint32_t lcbDocUndoWord9;
    uint32_t fcRgbUse;
    uint32_t lcbRgbUse;
    uint32_t fcUsp;
    uint32_t lcbUsp;
    uint32_t fcUskf;
    uint32_t lcbUskf;
    uint32_t fcPlcupcRgbUse;
    uint32_t lcbPlcupcRgbUse;
    uint32_t fcPlcupcUsp;
    uint32_t lcbPlcupcUsp;
    uint32_t fcSttbGlsyStyle;
    uint32_t lcbSttbGlsyStyle;
    uint32_t fcPlgosl;
    uint32_t lcbPlgosl;
    uint32_t fcPlcocx;
    uint32_t lcbPlcocx;
    uint32_t fcPlcfBteLvc;
    uint32_t lcbPlcfBteLvc;
    uint32_t dwLowDateTime;
    uint32_t dwHighDateTime;
    uint32_t fcPlcfLvcPre10;
    uint32_t lcbPlcfLvcPre10;
    uint32_t fcPlcfAsumy;
    uint32_t lcbPlcfAsumy;
    uint32_t fcPlcfGram;
    uint32_t lcbPlcfGram;
    uint32_t fcSttbListNames;
    uint32_t lcbSttbListNames;
    uint32_t fcSttbfUssr;
    uint32_t lcbSttbfUssr;
} FibRgFcLcb97;

static void copy_FibRgFcLcb97(FibRgFcLcb97 * pHeader, const uint8_t *const ptr) {

    memcpy(pHeader, ptr, sizeof(*pHeader));

pHeader->fcStshfOrig = ole2_endian_convert_32(pHeader->fcStshfOrig);
pHeader->lcbStshfOrig = ole2_endian_convert_32(pHeader->lcbStshfOrig);
pHeader->fcStshf = ole2_endian_convert_32(pHeader->fcStshf);
pHeader->lcbStshf = ole2_endian_convert_32(pHeader->lcbStshf);
pHeader->fcPlcffndRef = ole2_endian_convert_32(pHeader->fcPlcffndRef);
pHeader->lcbPlcffndRef = ole2_endian_convert_32(pHeader->lcbPlcffndRef);
pHeader->fcPlcffndTxt = ole2_endian_convert_32(pHeader->fcPlcffndTxt);
pHeader->lcbPlcffndTxt = ole2_endian_convert_32(pHeader->lcbPlcffndTxt);
pHeader->fcPlcfandRef = ole2_endian_convert_32(pHeader->fcPlcfandRef);
pHeader->lcbPlcfandRef = ole2_endian_convert_32(pHeader->lcbPlcfandRef);
pHeader->fcPlcfandTxt = ole2_endian_convert_32(pHeader->fcPlcfandTxt);
pHeader->lcbPlcfandTxt = ole2_endian_convert_32(pHeader->lcbPlcfandTxt);
pHeader->fcPlcfSed = ole2_endian_convert_32(pHeader->fcPlcfSed);
pHeader->lcbPlcfSed = ole2_endian_convert_32(pHeader->lcbPlcfSed);
pHeader->fcPlcPad = ole2_endian_convert_32(pHeader->fcPlcPad);
pHeader->lcbPlcPad = ole2_endian_convert_32(pHeader->lcbPlcPad);
pHeader->fcPlcfPhe = ole2_endian_convert_32(pHeader->fcPlcfPhe);
pHeader->lcbPlcfPhe = ole2_endian_convert_32(pHeader->lcbPlcfPhe);
pHeader->fcSttbfGlsy = ole2_endian_convert_32(pHeader->fcSttbfGlsy);
pHeader->lcbSttbfGlsy = ole2_endian_convert_32(pHeader->lcbSttbfGlsy);
pHeader->fcPlcfGlsy = ole2_endian_convert_32(pHeader->fcPlcfGlsy);
pHeader->lcbPlcfGlsy = ole2_endian_convert_32(pHeader->lcbPlcfGlsy);
pHeader->fcPlcfHdd = ole2_endian_convert_32(pHeader->fcPlcfHdd);
pHeader->lcbPlcfHdd = ole2_endian_convert_32(pHeader->lcbPlcfHdd);
pHeader->fcPlcfBteChpx = ole2_endian_convert_32(pHeader->fcPlcfBteChpx);
pHeader->lcbPlcfBteChpx = ole2_endian_convert_32(pHeader->lcbPlcfBteChpx);
pHeader->fcPlcfBtePapx = ole2_endian_convert_32(pHeader->fcPlcfBtePapx);
pHeader->lcbPlcfBtePapx = ole2_endian_convert_32(pHeader->lcbPlcfBtePapx);
pHeader->fcPlcfSea = ole2_endian_convert_32(pHeader->fcPlcfSea);
pHeader->lcbPlcfSea = ole2_endian_convert_32(pHeader->lcbPlcfSea);
pHeader->fcSttbfFfn = ole2_endian_convert_32(pHeader->fcSttbfFfn);
pHeader->lcbSttbfFfn = ole2_endian_convert_32(pHeader->lcbSttbfFfn);
pHeader->fcPlcfFldMom = ole2_endian_convert_32(pHeader->fcPlcfFldMom);
pHeader->lcbPlcfFldMom = ole2_endian_convert_32(pHeader->lcbPlcfFldMom);
pHeader->fcPlcfFldHdr = ole2_endian_convert_32(pHeader->fcPlcfFldHdr);
pHeader->lcbPlcfFldHdr = ole2_endian_convert_32(pHeader->lcbPlcfFldHdr);
pHeader->fcPlcfFldFtn = ole2_endian_convert_32(pHeader->fcPlcfFldFtn);
pHeader->lcbPlcfFldFtn = ole2_endian_convert_32(pHeader->lcbPlcfFldFtn);
pHeader->fcPlcfFldAtn = ole2_endian_convert_32(pHeader->fcPlcfFldAtn);
pHeader->lcbPlcfFldAtn = ole2_endian_convert_32(pHeader->lcbPlcfFldAtn);
pHeader->fcPlcfFldMcr = ole2_endian_convert_32(pHeader->fcPlcfFldMcr);
pHeader->lcbPlcfFldMcr = ole2_endian_convert_32(pHeader->lcbPlcfFldMcr);
pHeader->fcSttbfBkmk = ole2_endian_convert_32(pHeader->fcSttbfBkmk);
pHeader->lcbSttbfBkmk = ole2_endian_convert_32(pHeader->lcbSttbfBkmk);
pHeader->fcPlcfBkf = ole2_endian_convert_32(pHeader->fcPlcfBkf);
pHeader->lcbPlcfBkf = ole2_endian_convert_32(pHeader->lcbPlcfBkf);
pHeader->fcPlcfBkl = ole2_endian_convert_32(pHeader->fcPlcfBkl);
pHeader->lcbPlcfBkl = ole2_endian_convert_32(pHeader->lcbPlcfBkl);
pHeader->fcCmds = ole2_endian_convert_32(pHeader->fcCmds);
pHeader->lcbCmds = ole2_endian_convert_32(pHeader->lcbCmds);
pHeader->fcUnused1 = ole2_endian_convert_32(pHeader->fcUnused1);
pHeader->lcbUnused1 = ole2_endian_convert_32(pHeader->lcbUnused1);
pHeader->fcSttbfMcr = ole2_endian_convert_32(pHeader->fcSttbfMcr);
pHeader->lcbSttbfMcr = ole2_endian_convert_32(pHeader->lcbSttbfMcr);
pHeader->fcPrDrvr = ole2_endian_convert_32(pHeader->fcPrDrvr);
pHeader->lcbPrDrvr = ole2_endian_convert_32(pHeader->lcbPrDrvr);
pHeader->fcPrEnvPort = ole2_endian_convert_32(pHeader->fcPrEnvPort);
pHeader->lcbPrEnvPort = ole2_endian_convert_32(pHeader->lcbPrEnvPort);
pHeader->fcPrEnvLand = ole2_endian_convert_32(pHeader->fcPrEnvLand);
pHeader->lcbPrEnvLand = ole2_endian_convert_32(pHeader->lcbPrEnvLand);
pHeader->fcWss = ole2_endian_convert_32(pHeader->fcWss);
pHeader->lcbWss = ole2_endian_convert_32(pHeader->lcbWss);
pHeader->fcDop = ole2_endian_convert_32(pHeader->fcDop);
pHeader->lcbDop = ole2_endian_convert_32(pHeader->lcbDop);
pHeader->fcSttbfAssoc = ole2_endian_convert_32(pHeader->fcSttbfAssoc);
pHeader->lcbSttbfAssoc = ole2_endian_convert_32(pHeader->lcbSttbfAssoc);
pHeader->fcClx = ole2_endian_convert_32(pHeader->fcClx);
pHeader->lcbClx = ole2_endian_convert_32(pHeader->lcbClx);
pHeader->fcPlcfPgdFtn = ole2_endian_convert_32(pHeader->fcPlcfPgdFtn);
pHeader->lcbPlcfPgdFtn = ole2_endian_convert_32(pHeader->lcbPlcfPgdFtn);
pHeader->fcAutosaveSource = ole2_endian_convert_32(pHeader->fcAutosaveSource);
pHeader->lcbAutosaveSource = ole2_endian_convert_32(pHeader->lcbAutosaveSource);
pHeader->fcGrpXstAtnOwners = ole2_endian_convert_32(pHeader->fcGrpXstAtnOwners);
pHeader->lcbGrpXstAtnOwners = ole2_endian_convert_32(pHeader->lcbGrpXstAtnOwners);
pHeader->fcSttbfAtnBkmk = ole2_endian_convert_32(pHeader->fcSttbfAtnBkmk);
pHeader->lcbSttbfAtnBkmk = ole2_endian_convert_32(pHeader->lcbSttbfAtnBkmk);
pHeader->fcUnused2 = ole2_endian_convert_32(pHeader->fcUnused2);
pHeader->lcbUnused2 = ole2_endian_convert_32(pHeader->lcbUnused2);
pHeader->fcUnused3 = ole2_endian_convert_32(pHeader->fcUnused3);
pHeader->lcbUnused3 = ole2_endian_convert_32(pHeader->lcbUnused3);
pHeader->fcPlcSpaMom = ole2_endian_convert_32(pHeader->fcPlcSpaMom);
pHeader->lcbPlcSpaMom = ole2_endian_convert_32(pHeader->lcbPlcSpaMom);
pHeader->fcPlcSpaHdr = ole2_endian_convert_32(pHeader->fcPlcSpaHdr);
pHeader->lcbPlcSpaHdr = ole2_endian_convert_32(pHeader->lcbPlcSpaHdr);
pHeader->fcPlcfAtnBkf = ole2_endian_convert_32(pHeader->fcPlcfAtnBkf);
pHeader->lcbPlcfAtnBkf = ole2_endian_convert_32(pHeader->lcbPlcfAtnBkf);
pHeader->fcPlcfAtnBkl = ole2_endian_convert_32(pHeader->fcPlcfAtnBkl);
pHeader->lcbPlcfAtnBkl = ole2_endian_convert_32(pHeader->lcbPlcfAtnBkl);
pHeader->fcPms = ole2_endian_convert_32(pHeader->fcPms);
pHeader->lcbPms = ole2_endian_convert_32(pHeader->lcbPms);
pHeader->fcFormFldSttbs = ole2_endian_convert_32(pHeader->fcFormFldSttbs);
pHeader->lcbFormFldSttbs = ole2_endian_convert_32(pHeader->lcbFormFldSttbs);
pHeader->fcPlcfendRef = ole2_endian_convert_32(pHeader->fcPlcfendRef);
pHeader->lcbPlcfendRef = ole2_endian_convert_32(pHeader->lcbPlcfendRef);
pHeader->fcPlcfendTxt = ole2_endian_convert_32(pHeader->fcPlcfendTxt);
pHeader->lcbPlcfendTxt = ole2_endian_convert_32(pHeader->lcbPlcfendTxt);
pHeader->fcPlcfFldEdn = ole2_endian_convert_32(pHeader->fcPlcfFldEdn);
pHeader->lcbPlcfFldEdn = ole2_endian_convert_32(pHeader->lcbPlcfFldEdn);
pHeader->fcUnused4 = ole2_endian_convert_32(pHeader->fcUnused4);
pHeader->lcbUnused4 = ole2_endian_convert_32(pHeader->lcbUnused4);
pHeader->fcDggInfo = ole2_endian_convert_32(pHeader->fcDggInfo);
pHeader->lcbDggInfo = ole2_endian_convert_32(pHeader->lcbDggInfo);
pHeader->fcSttbfRMark = ole2_endian_convert_32(pHeader->fcSttbfRMark);
pHeader->lcbSttbfRMark = ole2_endian_convert_32(pHeader->lcbSttbfRMark);
pHeader->fcSttbfCaption = ole2_endian_convert_32(pHeader->fcSttbfCaption);
pHeader->lcbSttbfCaption = ole2_endian_convert_32(pHeader->lcbSttbfCaption);
pHeader->fcSttbfAutoCaption = ole2_endian_convert_32(pHeader->fcSttbfAutoCaption);
pHeader->lcbSttbfAutoCaption = ole2_endian_convert_32(pHeader->lcbSttbfAutoCaption);
pHeader->fcPlcfWkb = ole2_endian_convert_32(pHeader->fcPlcfWkb);
pHeader->lcbPlcfWkb = ole2_endian_convert_32(pHeader->lcbPlcfWkb);
pHeader->fcPlcfSpl = ole2_endian_convert_32(pHeader->fcPlcfSpl);
pHeader->lcbPlcfSpl = ole2_endian_convert_32(pHeader->lcbPlcfSpl);
pHeader->fcPlcftxbxTxt = ole2_endian_convert_32(pHeader->fcPlcftxbxTxt);
pHeader->lcbPlcftxbxTxt = ole2_endian_convert_32(pHeader->lcbPlcftxbxTxt);
pHeader->fcPlcfFldTxbx = ole2_endian_convert_32(pHeader->fcPlcfFldTxbx);
pHeader->lcbPlcfFldTxbx = ole2_endian_convert_32(pHeader->lcbPlcfFldTxbx);
pHeader->fcPlcfHdrtxbxTxt = ole2_endian_convert_32(pHeader->fcPlcfHdrtxbxTxt);
pHeader->lcbPlcfHdrtxbxTxt = ole2_endian_convert_32(pHeader->lcbPlcfHdrtxbxTxt);
pHeader->fcPlcffldHdrTxbx = ole2_endian_convert_32(pHeader->fcPlcffldHdrTxbx);
pHeader->lcbPlcffldHdrTxbx = ole2_endian_convert_32(pHeader->lcbPlcffldHdrTxbx);
pHeader->fcStwUser = ole2_endian_convert_32(pHeader->fcStwUser);
pHeader->lcbStwUser = ole2_endian_convert_32(pHeader->lcbStwUser);
pHeader->fcSttbTtmbd = ole2_endian_convert_32(pHeader->fcSttbTtmbd);
pHeader->lcbSttbTtmbd = ole2_endian_convert_32(pHeader->lcbSttbTtmbd);
pHeader->fcCookieData = ole2_endian_convert_32(pHeader->fcCookieData);
pHeader->lcbCookieData = ole2_endian_convert_32(pHeader->lcbCookieData);
pHeader->fcPgdMotherOldOld = ole2_endian_convert_32(pHeader->fcPgdMotherOldOld);
pHeader->lcbPgdMotherOldOld = ole2_endian_convert_32(pHeader->lcbPgdMotherOldOld);
pHeader->fcBkdMotherOldOld = ole2_endian_convert_32(pHeader->fcBkdMotherOldOld);
pHeader->lcbBkdMotherOldOld = ole2_endian_convert_32(pHeader->lcbBkdMotherOldOld);
pHeader->fcPgdFtnOldOld = ole2_endian_convert_32(pHeader->fcPgdFtnOldOld);
pHeader->lcbPgdFtnOldOld = ole2_endian_convert_32(pHeader->lcbPgdFtnOldOld);
pHeader->fcBkdFtnOldOld = ole2_endian_convert_32(pHeader->fcBkdFtnOldOld);
pHeader->lcbBkdFtnOldOld = ole2_endian_convert_32(pHeader->lcbBkdFtnOldOld);
pHeader->fcPgdEdnOldOld = ole2_endian_convert_32(pHeader->fcPgdEdnOldOld);
pHeader->lcbPgdEdnOldOld = ole2_endian_convert_32(pHeader->lcbPgdEdnOldOld);
pHeader->fcBkdEdnOldOld = ole2_endian_convert_32(pHeader->fcBkdEdnOldOld);
pHeader->lcbBkdEdnOldOld = ole2_endian_convert_32(pHeader->lcbBkdEdnOldOld);
pHeader->fcSttbfIntlFld = ole2_endian_convert_32(pHeader->fcSttbfIntlFld);
pHeader->lcbSttbfIntlFld = ole2_endian_convert_32(pHeader->lcbSttbfIntlFld);
pHeader->fcRouteSlip = ole2_endian_convert_32(pHeader->fcRouteSlip);
pHeader->lcbRouteSlip = ole2_endian_convert_32(pHeader->lcbRouteSlip);
pHeader->fcSttbSavedBy = ole2_endian_convert_32(pHeader->fcSttbSavedBy);
pHeader->lcbSttbSavedBy = ole2_endian_convert_32(pHeader->lcbSttbSavedBy);
pHeader->fcSttbFnm = ole2_endian_convert_32(pHeader->fcSttbFnm);
pHeader->lcbSttbFnm = ole2_endian_convert_32(pHeader->lcbSttbFnm);
pHeader->fcPlfLst = ole2_endian_convert_32(pHeader->fcPlfLst);
pHeader->lcbPlfLst = ole2_endian_convert_32(pHeader->lcbPlfLst);
pHeader->fcPlfLfo = ole2_endian_convert_32(pHeader->fcPlfLfo);
pHeader->lcbPlfLfo = ole2_endian_convert_32(pHeader->lcbPlfLfo);
pHeader->fcPlcfTxbxBkd = ole2_endian_convert_32(pHeader->fcPlcfTxbxBkd);
pHeader->lcbPlcfTxbxBkd = ole2_endian_convert_32(pHeader->lcbPlcfTxbxBkd);
pHeader->fcPlcfTxbxHdrBkd = ole2_endian_convert_32(pHeader->fcPlcfTxbxHdrBkd);
pHeader->lcbPlcfTxbxHdrBkd = ole2_endian_convert_32(pHeader->lcbPlcfTxbxHdrBkd);
pHeader->fcDocUndoWord9 = ole2_endian_convert_32(pHeader->fcDocUndoWord9);
pHeader->lcbDocUndoWord9 = ole2_endian_convert_32(pHeader->lcbDocUndoWord9);
pHeader->fcRgbUse = ole2_endian_convert_32(pHeader->fcRgbUse);
pHeader->lcbRgbUse = ole2_endian_convert_32(pHeader->lcbRgbUse);
pHeader->fcUsp = ole2_endian_convert_32(pHeader->fcUsp);
pHeader->lcbUsp = ole2_endian_convert_32(pHeader->lcbUsp);
pHeader->fcUskf = ole2_endian_convert_32(pHeader->fcUskf);
pHeader->lcbUskf = ole2_endian_convert_32(pHeader->lcbUskf);
pHeader->fcPlcupcRgbUse = ole2_endian_convert_32(pHeader->fcPlcupcRgbUse);
pHeader->lcbPlcupcRgbUse = ole2_endian_convert_32(pHeader->lcbPlcupcRgbUse);
pHeader->fcPlcupcUsp = ole2_endian_convert_32(pHeader->fcPlcupcUsp);
pHeader->lcbPlcupcUsp = ole2_endian_convert_32(pHeader->lcbPlcupcUsp);
pHeader->fcSttbGlsyStyle = ole2_endian_convert_32(pHeader->fcSttbGlsyStyle);
pHeader->lcbSttbGlsyStyle = ole2_endian_convert_32(pHeader->lcbSttbGlsyStyle);
pHeader->fcPlgosl = ole2_endian_convert_32(pHeader->fcPlgosl);
pHeader->lcbPlgosl = ole2_endian_convert_32(pHeader->lcbPlgosl);
pHeader->fcPlcocx = ole2_endian_convert_32(pHeader->fcPlcocx);
pHeader->lcbPlcocx = ole2_endian_convert_32(pHeader->lcbPlcocx);
pHeader->fcPlcfBteLvc = ole2_endian_convert_32(pHeader->fcPlcfBteLvc);
pHeader->lcbPlcfBteLvc = ole2_endian_convert_32(pHeader->lcbPlcfBteLvc);
pHeader->dwLowDateTime = ole2_endian_convert_32(pHeader->dwLowDateTime);
pHeader->dwHighDateTime = ole2_endian_convert_32(pHeader->dwHighDateTime);
pHeader->fcPlcfLvcPre10 = ole2_endian_convert_32(pHeader->fcPlcfLvcPre10);
pHeader->lcbPlcfLvcPre10 = ole2_endian_convert_32(pHeader->lcbPlcfLvcPre10);
pHeader->fcPlcfAsumy = ole2_endian_convert_32(pHeader->fcPlcfAsumy);
pHeader->lcbPlcfAsumy = ole2_endian_convert_32(pHeader->lcbPlcfAsumy);
pHeader->fcPlcfGram = ole2_endian_convert_32(pHeader->fcPlcfGram);
pHeader->lcbPlcfGram = ole2_endian_convert_32(pHeader->lcbPlcfGram);
pHeader->fcSttbListNames = ole2_endian_convert_32(pHeader->fcSttbListNames);
pHeader->lcbSttbListNames = ole2_endian_convert_32(pHeader->lcbSttbListNames);
pHeader->fcSttbfUssr = ole2_endian_convert_32(pHeader->fcSttbfUssr);
pHeader->lcbSttbfUssr = ole2_endian_convert_32(pHeader->lcbSttbfUssr);


}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/5dc1b9ed-818c-436f-8a4f-905a7ebb1ba9 */
typedef struct __attribute__((packed)) {
    uint16_t recVer_recInstance;
    uint16_t recType;
    uint32_t recLen;
} OfficeArtRecordHeader;

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/5dc1b9ed-818c-436f-8a4f-905a7ebb1ba9  */
static void copy_OfficeArtRecordHeader (OfficeArtRecordHeader * header, const uint8_t * const ptr) {
    memcpy(header, ptr, sizeof(OfficeArtRecordHeader));

    header->recVer_recInstance = ole2_endian_convert_16(header->recVer_recInstance);
    header->recType = ole2_endian_convert_16(header->recType);
    header->recLen = ole2_endian_convert_32(header->recLen);

    fprintf(stderr, "%s::%d::recVer_recInstance = %x\n", __FUNCTION__, __LINE__, header->recVer_recInstance);
    fprintf(stderr, "%s::%d::recType = %x\n", __FUNCTION__, __LINE__, header->recType);
    fprintf(stderr, "%s::%d::recLen = %x\n", __FUNCTION__, __LINE__, header->recLen);

}

static uint16_t getRecInst(OfficeArtRecordHeader * header) {
    return ole2_endian_convert_16((header->recVer_recInstance & 0xfff0) >> 4);
}

static uint8_t getRecVer(OfficeArtRecordHeader * header) {
    return header->recVer_recInstance & 0xf;
}


static void parse_fibRgFcLcb97(const uint8_t * ptr){
    fprintf(stderr, "%s::%d::%p::UNIMPLEMENTED\n", __FUNCTION__, __LINE__, ptr); exit(11);
}

static void parse_fibRgFcLcb2000(const uint8_t * ptr){
    fprintf(stderr, "%s::%d::%p::UNIMPLEMENTED\n", __FUNCTION__, __LINE__, ptr); exit(11);
}


/*
 * TODO: MOVE THIS TO A STRUCTURE THAT IS PASSED IN, BUT 
 * CURRENTLY TRYING TO FIGURE OUT IF I AM FINDING ALL THE DATA CORRECTLY
 */
FibRgFcLcb97 header;




static void parse_fibRgFcLcb2002(const uint8_t * base_ptr, size_t idx, const property_t * table_stream){
    const uint8_t * ptr = &(base_ptr[idx]);

    fprintf(stderr, "%s::%d::Data is in the fcDggInfo, size is in the lcbDggInfo\n", __FUNCTION__, __LINE__);
    fprintf(stderr, "%s::%d::Structure is the FibRgFcLcb97\n", __FUNCTION__, __LINE__);
    fprintf(stderr, "%s::%d::%p\n", __FUNCTION__, __LINE__, table_stream);

    copy_FibRgFcLcb97(&header, ptr);

    /*Offset is in the TableStream.*/
    size_t offset = header.fcDggInfo;
    size_t size = header.lcbDggInfo;
    fprintf(stderr, "%s::%d::Offset = %lu (0x%lx)\n", __FUNCTION__, __LINE__, offset, offset);
    fprintf(stderr, "%s::%d::Size = %lu (0x%lx)\n", __FUNCTION__, __LINE__, size, size);

    /*Information about 
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/dd7133b6-ed10-4bcb-be29-67b0544f884f 
     * at the beginning of 
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/8699a984-3718-44be-adae-08b05827f8b3
     * */
    OfficeArtRecordHeader drawingGroupDataRecordHeader;
    copy_OfficeArtRecordHeader (&drawingGroupDataRecordHeader, &(ptr[offset]));

    fprintf(stderr, "%s::%d::Calling second time\n", __FUNCTION__, __LINE__);
    copy_OfficeArtRecordHeader (&drawingGroupDataRecordHeader, &(base_ptr[offset]));

#if 0
    if (table_stream) {
        fprintf(stderr, "%s::%d::Calling THIRD time\n", __FUNCTION__, __LINE__);
        copy_OfficeArtRecordHeader (&drawingGroupDataRecordHeader, &(((const uint8_t*)   table_stream   )[offset]));
    }
#endif


    fprintf(stderr, "%s::%d::The offset and size information is for the OfficeArtContent header information\n", __FUNCTION__, __LINE__);

    fprintf(stderr, "https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/8699a984-3718-44be-adae-08b05827f8b3\n");


    fprintf(stderr, "%s::%d::UNIMPLEMENTED\n", __FUNCTION__, __LINE__); /* exit(11); */
}

static void parse_fibRgFcLcb2003(const uint8_t * ptr){
    fprintf(stderr, "%s::%d::%p::UNIMPLEMENTED\n", __FUNCTION__, __LINE__, ptr); exit(11);
}

static void parse_fibRgFcLcb2007(const uint8_t * ptr){
    fprintf(stderr, "%s::%d::%p::UNIMPLEMENTED\n", __FUNCTION__, __LINE__, ptr); exit(11);
}

ole2_header_t * pGLOBAL_HEADER;
static void test_for_pictures( const property_t *word_block, const property_t * table_stream, ole2_header_t *hdr) {
    pGLOBAL_HEADER = hdr;

    const uint8_t *ptr = NULL;
    fib_base_t fib     = {0};
    //size_t i;
    size_t to_read = 0x1000;

    fprintf(stderr,"%s::%d::Entering\n", __FUNCTION__, __LINE__);

    uint32_t fib_offset = get_stream_data_offset(hdr, word_block, word_block->start_block);
//    fprintf(stderr,"%s::%d::fib_offset = %x\n", __FUNCTION__, __LINE__, fib_offset);

    if ((size_t)(hdr->m_length) < (size_t)(fib_offset + sizeof(fib_base_t))) {
        cli_dbgmsg("ERROR: Invalid offset for File Information Block %d (0x%x)\n", fib_offset, fib_offset);
        return;
    }
    fprintf(stderr,"%s::%d\n", __FUNCTION__, __LINE__);

    //ptr = fmap_need_off_once(hdr->map, fib_offset, sizeof(fib_base_t));
    fprintf(stderr, "%s::%d::TODO: Add the correct size, trying to read 4k because, why not?\n", __FUNCTION__, __LINE__);

    ptr = fmap_need_off_once(hdr->map, fib_offset, to_read);
    if (NULL == ptr) {
        cli_dbgmsg("ERROR: Invalid offset for File Information Block %d (0x%x)\n", fib_offset, fib_offset);
        return;
    }
fprintf(stderr,"%s::%d\n", __FUNCTION__, __LINE__);
    copy_fib_base(&fib, ptr);
fprintf(stderr,"%s::%d\n", __FUNCTION__, __LINE__);

#define FIB_BASE_IDENTIFIER 0xa5ec
    fprintf(stderr,"%s::%d\n", __FUNCTION__, __LINE__);

    if (FIB_BASE_IDENTIFIER != fib.wIdent) {
        cli_dbgmsg("ERROR: Invalid identifier for File Information Block %d (0x%x)\n", fib.wIdent, fib.wIdent);
        return;
    }
    fprintf(stderr,"%s::%d\n", __FUNCTION__, __LINE__);

    uint32_t idx = sizeof(fib);
    /* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/9aeaa2e7-4a45-468e-ab13-3f6193eb9394 */
    uint16_t csw;
    read_uint16(ptr, to_read, &idx, &csw);
    if (0x000e != csw){
        fprintf(stderr, "%s::%d::Invalid csw = 0x%x\n", __FUNCTION__, __LINE__, csw);
        return;
    }
    fprintf(stderr,"%s::%d\n", __FUNCTION__, __LINE__);

    idx += 28; /* Size of the fibRgW.  Don't think I need anything from there. */

    uint16_t cslw;
    read_uint16(ptr, to_read, &idx, &cslw);
    if (0x0016 != cslw) {
        fprintf(stderr, "%s::%d::Invalid cslw = 0x%x\n", __FUNCTION__, __LINE__, cslw);
        return;
    }
    idx += 88; /* Size of the FibRgLw97.  Don't think I need anything from there. */

    uint16_t cbRgFcLcb;
    read_uint16(ptr, to_read, &idx, &cbRgFcLcb);
#if 0
    if (!= cbRgFcLcb){
        fprintf(stderr, "%s::%d::Invalid cbRgFcLcb of 0x%x\n", __FUNCTION__, __LINE__, cbRgFcLcb);
        return;
    }
#else
    fprintf(stderr, "nFib = 0x%x::cbRgFcLcb = 0x%x\n", fib.nFib, cbRgFcLcb );
    switch (fib.nFib){
        default:
            fprintf(stderr, "%s::%d::Invalid fib.nFib\n", __FUNCTION__, __LINE__);
            return;
        case 0x00c1:
            if (0x005d != cbRgFcLcb){
                fprintf(stderr, "%s::%d::Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", __FUNCTION__, __LINE__, fib.nFib, cbRgFcLcb);
                return;
            }
            parse_fibRgFcLcb97(ptr);
            break;
        case 0x00d9:
            if (0x006c != cbRgFcLcb){
                fprintf(stderr, "%s::%d::Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", __FUNCTION__, __LINE__, fib.nFib, cbRgFcLcb);
                return;
            }
            parse_fibRgFcLcb2000(ptr);
            break;
        case 0x0101:
            if (0x0088 != cbRgFcLcb){
                fprintf(stderr, "%s::%d::Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", __FUNCTION__, __LINE__, fib.nFib, cbRgFcLcb);
                return;
            }
            fprintf(stderr, "%s::%d::idx = %u (0x%x)\n", __FUNCTION__, __LINE__, idx, idx);
            //parse_fibRgFcLcb2002(&(ptr[idx]));
            parse_fibRgFcLcb2002(ptr, idx, table_stream);
            break;
        case 0x010c:
            if (0x00a4 != cbRgFcLcb){
                fprintf(stderr, "%s::%d::Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", __FUNCTION__, __LINE__, fib.nFib, cbRgFcLcb);
                return;
            }
            parse_fibRgFcLcb2003(ptr);
            break;
        case 0x0112:
            if (0x00b7 != cbRgFcLcb){
                fprintf(stderr, "%s::%d::Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", __FUNCTION__, __LINE__, fib.nFib, cbRgFcLcb);
                return;
            }
            parse_fibRgFcLcb2007(ptr);
            break;
    }
#endif


#if 0
    {
        int i;
    fprintf(stderr, "%s::%d::", __FUNCTION__, __LINE__);
    for (i = idx; i < to_read; i++){
        fprintf(stderr, "%02x ", ptr[i]);
    }
    fprintf(stderr, "\n");
}
#endif


    fprintf(stderr,"%s::%d::GOT TO END!!!\n", __FUNCTION__, __LINE__);

}




#if 0
static void extract_images( FibRgFcLcb97 * header, const property_t * table_stream,  ole2_header_t *hdr) {

    int i;
    const uint8_t * table_stream_data = (const uint8_t*) table_stream;
    size_t offset = header->fcDggInfo;

    fprintf(stderr, "%s::%d::%p::%lu::(0x%lx)Entering\n", __FUNCTION__, __LINE__, hdr, offset, offset);
#if 0
    const uint8_t * ptr = fmap_need_off_once(hdr->map, &(table_stream_data[offset]), header->lcbDggInfo );
#else
    const uint8_t * ptr = &(table_stream_data[offset]);
#endif
    fprintf(stderr, "%s::%d::%p\n", __FUNCTION__, __LINE__, ptr);

    OfficeArtRecordHeader officeArtDggContainer;
    copy_OfficeArtRecordHeader (&officeArtDggContainer, ptr);
    /*None of the values make sense.*/

    fprintf(stderr, "%s::%d::", __FUNCTION__, __LINE__);
    for (i = 0; i < 8; i++){
        fprintf(stderr, "%02x ", table_stream_data[offset + i]);
    }
    fprintf(stderr, "\n");

    offset += 8; //size of OfficeArtRecordHeader

    fprintf(stderr, "%s::%d::Leaving\n", __FUNCTION__, __LINE__);
}
#else

typedef struct __attribute__((packed)) {
    uint32_t spidMax;
    uint32_t cidcl;
    uint32_t cspSaved;
    uint32_t cdgSaved;
} OfficeArtFDGG;

static void copy_OfficeArtFDGG(OfficeArtFDGG * dst, const uint8_t * const ptr){
    //size_t idx = 0;
    memcpy(dst, ptr, sizeof(OfficeArtFDGG));

    dst->spidMax = ole2_endian_convert_32(dst->spidMax);
    dst->cidcl = ole2_endian_convert_32(dst->cidcl);
    dst->cspSaved = ole2_endian_convert_32(dst->cspSaved );
    dst->cdgSaved = ole2_endian_convert_32(dst->cdgSaved );
}


/*This does NOT include the rh (OfficeArtRecordHeader) 
 *
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2f2d7f5e-d5c4-4cb7-b230-59b3fe8f10d6
 * */
typedef struct __attribute__((packed)) {
    uint8_t btWin32;

    uint8_t btMacOS;

    uint8_t rgbUid[16];
    uint16_t tag;
    uint32_t size;
    uint32_t cRef;
    uint32_t foDelay;

    uint8_t unused1;
    uint8_t cbName;
    uint8_t unused2;
    uint8_t unused3;

    //followed by namedata
    //followed by blip
} OfficeArtFBSEKnown;

static void copy_OfficeArtFBSEKnown (OfficeArtFBSEKnown * dst, const uint8_t * const ptr) {
    memcpy(dst, ptr, sizeof(OfficeArtFBSEKnown));

    dst->tag = ole2_endian_convert_16(dst->tag);
    dst->size = ole2_endian_convert_32(dst->size);
    dst->cRef = ole2_endian_convert_32(dst->cRef);
    dst->foDelay = ole2_endian_convert_32(dst->foDelay);
}

static void saveImageFile(const uint8_t * const ptr, size_t size){
    fprintf(stderr, "%s::%d::Actually extracting the file, FINALLY %p %lu!!!\n", __FUNCTION__, __LINE__, ptr, size);
}


/*All these structures (except JPEG) are exactly the same, with the exception of the recInst values for 1 or 2 UIDs, 
 * so this function accepts them as parameters.
 * 
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2c09e2c4-0513-419f-b5f9-4feb0a71ef32
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/ee892f04-f001-4531-a34b-67aab3426dcb
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/4b6c5fc5-98cc-445a-8ec7-12b2f2c05b9f
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/7af7d17e-6ae1-4c43-a3d6-691e6b3b4a45 
 *
 */
static void processOfficeArtBlipGeneric(OfficeArtRecordHeader * rh, const uint8_t * const ptr,
        uint16_t riSingleUID, uint16_t riDoubleUID, uint32_t bytesAfterUIDs) {
    size_t offset = 16; /* Size of rh*/

    uint16_t recInst = getRecInst(rh);

    if (riDoubleUID == recInst) {
        offset += 16;
    } else if (riSingleUID != recInst) {
        fprintf(stderr, "%s::%d::Invaild recInst\n", __FUNCTION__, __LINE__);
        exit(121); //normally just return, will fix
    }
    offset += bytesAfterUIDs; /*metafile header*/

    saveImageFile(&(ptr[offset]), rh->recLen - offset);
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2c09e2c4-0513-419f-b5f9-4feb0a71ef32 */
static void processOfficeArtBlipEMF(OfficeArtRecordHeader * rh, const uint8_t * const ptr) {
    processOfficeArtBlipGeneric(rh, ptr, 0x3d4, 0x3d5, 34) ;
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/ee892f04-f001-4531-a34b-67aab3426dcb */
static void processOfficeArtBlipWMF(OfficeArtRecordHeader * rh, const uint8_t * const ptr){
    processOfficeArtBlipGeneric(rh, ptr, 0x216, 0x217, 34) ;
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/4b6c5fc5-98cc-445a-8ec7-12b2f2c05b9f */
static void processOfficeArtBlipPICT(OfficeArtRecordHeader * rh, const uint8_t * const ptr){
    processOfficeArtBlipGeneric(rh, ptr, 0x542, 0x543, 34) ;
}

/*https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/704b3ec5-3e3f-425f-b2f7-a090cc68e624*/
static void processOfficeArtBlipJPEG(OfficeArtRecordHeader * rh, const uint8_t * const ptr){
    size_t offset = 16; /* Size of rh*/
    uint16_t recInst = getRecInst(rh);

    if ((0x46b == recInst) || (0x6e3 != recInst)){
        offset += 16;
    } else if ((0x46a != recInst) && (0x6e2 != recInst)) {
        fprintf(stderr, "%s::%d::Invaild recInst\n", __FUNCTION__, __LINE__);
        exit(121); //normally just return, will fix
    }
    offset += 1; /*metafile header*/

    saveImageFile(&(ptr[offset]), rh->recLen - offset);
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/7af7d17e-6ae1-4c43-a3d6-691e6b3b4a45 */
static void processOfficeArtBlipPNG(OfficeArtRecordHeader * rh, const uint8_t * const ptr){
    processOfficeArtBlipGeneric(rh, ptr, 0x6e0, 0x6e1, 1) ;
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/1393bf5e-6fa0-4665-b3ec-68199b555656 */
static void processOfficeArtBlipDIB(OfficeArtRecordHeader * rh, const uint8_t * const ptr){
    processOfficeArtBlipGeneric(rh, ptr, 0x7a8, 0x7a9, 1) ;
}

static void processOfficeArtBlipTIFF(OfficeArtRecordHeader * rh, const uint8_t * const ptr){
    processOfficeArtBlipGeneric(rh, ptr, 0x6e4, 0x6e5, 1) ;
}

static void processOfficeArtBlip(const uint8_t * const ptr){

    size_t offset = 0;
    OfficeArtRecordHeader rh;

    copy_OfficeArtRecordHeader (&rh, ptr);
    offset += sizeof(OfficeArtRecordHeader );
    uint8_t recVer = getRecVer(&rh);
    if (0 != recVer) {
        fprintf(stderr, "%s::%d::Invalid recver\n", __FUNCTION__, __LINE__);
        exit(110);
    }

#define RECTYPE_OFFICE_ART_BLIP_EMF 0xf01a
#define RECTYPE_OFFICE_ART_BLIP_WMF 0xf01b
#define RECTYPE_OFFICE_ART_BLIP_PICT 0xf01c
#define RECTYPE_OFFICE_ART_BLIP_JPEG 0xf01d
#define RECTYPE_OFFICE_ART_BLIP_PNG 0xf01e
#define RECTYPE_OFFICE_ART_BLIP_DIB 0xf01f
#define RECTYPE_OFFICE_ART_BLIP_TIFF 0xf029
#define RECTYPE_OFFICE_ART_BLIP_JPEG2 0xf02a

    switch (rh.recType) {
        case RECTYPE_OFFICE_ART_BLIP_EMF:
            processOfficeArtBlipEMF(&rh, &(ptr[offset]));
            break;
        case RECTYPE_OFFICE_ART_BLIP_WMF :
            processOfficeArtBlipWMF(&rh, &(ptr[offset]));
            break;
        case RECTYPE_OFFICE_ART_BLIP_PICT:
            processOfficeArtBlipPICT(&rh, &(ptr[offset]));
            break;
        case RECTYPE_OFFICE_ART_BLIP_JPEG:
            /* fallthrough */
        case RECTYPE_OFFICE_ART_BLIP_JPEG2:
            processOfficeArtBlipJPEG(&rh, &(ptr[offset]));
            break;
        case RECTYPE_OFFICE_ART_BLIP_PNG:
            processOfficeArtBlipPNG(&rh, &(ptr[offset]));
            break;
        case RECTYPE_OFFICE_ART_BLIP_DIB:
            processOfficeArtBlipDIB(&rh, &(ptr[offset]));
            break;
        case RECTYPE_OFFICE_ART_BLIP_TIFF:
            processOfficeArtBlipTIFF(&rh, &(ptr[offset]));
            break;
        default:
            fprintf(stderr, "%s::%d::Invalid 0x%x::", __FUNCTION__, __LINE__, rh.recType);
            exit(11);
            break;
    }
}


/*
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2f2d7f5e-d5c4-4cb7-b230-59b3fe8f10d6
 */
static void processOfficeArtFBSE(OfficeArtRecordHeader * imageHeader, const uint8_t * const ptr) {

    size_t i;
    OfficeArtFBSEKnown fbse;

    uint32_t offset = sizeof(OfficeArtRecordHeader);
    uint16_t recInst = getRecInst(imageHeader);

    copy_OfficeArtFBSEKnown (&fbse, &(ptr[offset]));
    offset += sizeof(OfficeArtFBSEKnown );

    if ((recInst != fbse.btWin32) && (recInst != fbse.btMacOS)) {
        fprintf(stderr, "%s::%d::Invalid record, exiting (fix later)\n", __FUNCTION__, __LINE__);
        exit(1);
    }
    if (imageHeader->recType != 0xf007) {
        fprintf(stderr, "%s::%d::Invalid record, exiting (fix later)\n", __FUNCTION__, __LINE__);
        exit(1);
    }

    fprintf(stderr, "%s::%d::imageHeader->recLen = %d\n", __FUNCTION__, __LINE__, imageHeader->recLen);
    fprintf(stderr, "%s::%d::blip size = %d\n", __FUNCTION__, __LINE__, fbse.size);
    fprintf(stderr, "%s::%d::delay = %d\n", __FUNCTION__, __LINE__, fbse.foDelay);
    fprintf(stderr, "%s::%d::recInst = %d (0x%x)\n", __FUNCTION__, __LINE__, recInst, recInst);

    fprintf(stderr, "%s::%d::fbse.btWin32 = %d (0x%x)\n", __FUNCTION__, __LINE__, fbse.btWin32, fbse.btWin32);
    fprintf(stderr, "%s::%d::fbse.btMacOS = %d (0x%x)\n", __FUNCTION__, __LINE__, fbse.btMacOS, fbse.btMacOS);

    offset += fbse.cbName;

    fprintf(stderr, "%s::%d::Since the recLen is 36 (for this file), there is no name data or embedded blip record, so I need to figure out how this delay stream works???\n", __FUNCTION__, __LINE__);

    if (imageHeader->recLen == (sizeof(OfficeArtFBSEKnown) + fbse.cbName + fbse.size)) {
        /* The BLIP is embedded in this record*/ 
        processOfficeArtBlip(&(ptr[offset]));
    } else {
        fprintf(stderr, "%s::%d::Still trying to figure out where teh BLIP is!!!\n", __FUNCTION__, __LINE__);
        fprintf(stderr, "%s::%d::Found the BLIP in the 'DocumentSummaryInformation' stream (searching), but can't find structures that point towards it\n", __FUNCTION__, __LINE__);
    }



#if 0
    offset += fbse.foDelay;
    uint8_t * blah = fmap_need_off_once(pGLOBAL_HEADER->map, offset, fbse.size);
    processOfficeArtBlip(blah);
#else


#if 1
    {
        size_t andy;
        fprintf(stderr, "%s::%d::", __FUNCTION__, __LINE__);
        for (andy = 0; andy < 1024; andy++) {
            fprintf(stderr, "%02x ", ptr[offset + andy]);

        }
        fprintf(stderr, "\n");

        fprintf(stderr, "%s::%d::", __FUNCTION__, __LINE__);
        for (andy = 0; andy < 1024; andy++) {
            char c = ptr[offset + andy];
            if (c) fprintf(stderr, "%c ", c);
            else fprintf(stderr, " ");

        }
        fprintf(stderr, "\n");

        fprintf(stderr, "%s::%d::Figure out what is going on here, since none of the record types match the documentation\n", __FUNCTION__, __LINE__);
        exit(1);
    }
#endif



//    processOfficeArtBlip(&(ptr[offset]));
#endif

}

static void extract_images_2( FibRgFcLcb97 * header, const uint8_t * ptr) {
    fprintf(stderr, "%s::%d::%p::%p\n", __FUNCTION__, __LINE__, header, ptr);
    size_t offset = header->fcDggInfo;
    uint32_t i;

#if 0
    fprintf(stderr, "%s::%d::", __FUNCTION__, __LINE__);
    for (i= 0; i < 100; i++) {
        fprintf(stderr, "%02x ", ptr[i]);
    }
        fprintf(stderr, "\n");
#endif

        fprintf(stderr, "%s::%d::offset = %lx\n", __FUNCTION__, __LINE__, offset);

    /*
     * Start of OfficeArtContent
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/8699a984-3718-44be-adae-08b05827f8b3
     * First record is an OfficeArtDggContainer
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/dd7133b6-ed10-4bcb-be29-67b0544f884f
     */
    OfficeArtRecordHeader oadc_recordHeader; //OfficeArtDggContainer
    copy_OfficeArtRecordHeader (&oadc_recordHeader, &(ptr[offset]));

    /*TODO: validate recVer and recInst separately*/
    if (0xf != oadc_recordHeader.recVer_recInstance){
        fprintf(stderr, "%s::%d::Error\n", __FUNCTION__, __LINE__);
        exit(11);
    }

    offset += sizeof (OfficeArtRecordHeader );

    /*
     * Next is the OfficeArtFDGGBlock 
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/a9ff4320-4fa3-4408-8ea4-85c3cec0b501
     * We shouldn't have to care about that, since it's for drawings and not actual file images.
     * Going to just skip this record for now.
     * */
    OfficeArtRecordHeader hdr; //OfficeArtFDGGBlock
    copy_OfficeArtRecordHeader(&hdr,  &(ptr[offset]));
    //offset += hdr.recLen; not right, doesn't *always* seem to be a size.

    offset += sizeof(OfficeArtRecordHeader);

    OfficeArtFDGG fdgg;
    copy_OfficeArtFDGG(&fdgg, &(ptr[offset]));
    offset += sizeof(OfficeArtFDGG);

    fprintf(stderr, "%s::%d::fdgg.cidcl = %d\n", __FUNCTION__, __LINE__, fdgg.cidcl);
/* OfficeArtIDCL is not used in parsing images, only drawings.  If details are needed, they are
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2335d2f8-109b-4cd6-ac8d-40b1237283f3
 * */
#define OFFICE_ART_IDCL_LEN 8 
    offset += (OFFICE_ART_IDCL_LEN  * (fdgg.cidcl-1));

    fprintf(stderr, "\n%s::%d::Before last one\n", __FUNCTION__, __LINE__);

    /*
     * OfficeArtBStoreContainer
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/561cb6d4-d38b-4666-b2b4-10abc1dce44c
     *
     */
    OfficeArtRecordHeader blipStoreRecordHeader;
    copy_OfficeArtRecordHeader(&blipStoreRecordHeader,  &(ptr[offset]));

    fprintf(stderr, "%s::%d::RecVer = %x\n", __FUNCTION__, __LINE__, getRecVer(&blipStoreRecordHeader));
    if (0xf != getRecVer(&blipStoreRecordHeader)) {
        fprintf(stderr, "%s::%d::Not a correct value, exiting (during debugging, normally just return)\n", __FUNCTION__, __LINE__);
        exit(11);
    }

    if (0xf001 != blipStoreRecordHeader.recType){
        fprintf(stderr, "%s::%d::Not a correct value, exiting (during debugging, normally just return)\n", __FUNCTION__, __LINE__);
        exit(11);
    }

    uint32_t imageCnt = getRecInst (&blipStoreRecordHeader);
    fprintf(stderr, "%s::%d::imageCnt = %d\n", __FUNCTION__, __LINE__, imageCnt);

    offset += sizeof(OfficeArtRecordHeader);

#if 0
    /*I *hate* doing this, but I have been unable to figuer out why I need to increment by 2 bytes here.  There is
     * nothing in the documentation that I have found to account for these bytes, so I am going to increment them
     * here, and hope it makes sense at some point???
     *
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/561cb6d4-d38b-4666-b2b4-10abc1dce44c
     *
     * */
    offset += 2;
#endif











    /*Rec types taken from 
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/a7d7d967-6bff-489c-a267-3ec30448344a
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2f2d7f5e-d5c4-4cb7-b230-59b3fe8f10d6
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/c67b883b-8136-4e91-a1a3-2981d16e934f
     *
     * */
#define OFFICE_ART_FBSE_REC_TYPE 0x2
    for (i = 0; i < imageCnt; i++) {
        OfficeArtRecordHeader imageHeader;
        copy_OfficeArtRecordHeader(&imageHeader,  &(ptr[offset]));
        uint8_t recVer = getRecVer(&imageHeader);
        fprintf(stderr, "%s::%d::recType = %x\n", __FUNCTION__, __LINE__, recVer);

        if (OFFICE_ART_FBSE_REC_TYPE == recVer){
            /* OfficeArtFBSE 
             * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2f2d7f5e-d5c4-4cb7-b230-59b3fe8f10d6
             */
            processOfficeArtFBSE(&imageHeader, &(ptr[offset]));
        } else {
            processOfficeArtBlip(&(ptr[offset]));
        }
    }






#if 0







//fprintf(stderr, "%s::%d::Process blip store here\n", __FUNCTION__, __LINE__);
    uint16_t numRecords = (blipStoreRecordHeader.recVer_recInstance & 0xfff0) >> 4;

    offset += sizeof(OfficeArtRecordHeader);


    /*I am thinking I need to increment offset by 2 here, but I can't find anything in the docs to say why.
     * That's just what all the files appear to be expecting.*/

    fprintf(stderr, "%s::%d::offset = %lx\n", __FUNCTION__, __LINE__, offset);
    fprintf(stderr, "%s::%d::numRecords = 0x%x\n", __FUNCTION__, __LINE__, numRecords);
#endif

    fprintf(stderr, "%s::%d::", __FUNCTION__, __LINE__);
    for (i = 0; i < blipStoreRecordHeader.recLen; i++){
        fprintf(stderr, "%02x ", ptr[offset + i]);
    }
    fprintf(stderr, "\n");


    fprintf(stderr, "%s::%d::Got to end\n", __FUNCTION__, __LINE__);

    exit(11);
}

#endif











#endif /* OLE2_EXTRACT_IMAGES_H_ */
