#ifndef OLE2_EXTRACT_IMAGES_H_
#define OLE2_EXTRACT_IMAGES_H_


/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/0c9df81f-98d0-454e-ad84-b612cd05b1a4   */
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

typedef struct {
    FibRgFcLcb97 fibRgFcLcb97Header;
    bool bFibRgFcLcb97Header_initialized;
    property_t word_block;
    property_t table_stream_0_block;
    property_t table_stream_1_block;
    bool table_stream_0_initialized;
    bool table_stream_1_initialized;
} ole2_image_directory_t;

/*
 * This structure is used to keep track of a poiner's offset, to determine if it will cross
 * a block that is used by the DIFAT
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea
 *
 * The structures that describe where images are stored don't specify that there may be
 * DIFAT blocks in the middle.
 *
 * stream_file_offset is the offset of the Stream in the file.  For example, the WordDocument, 0Table, etc.
 *
 * base_ptr is the beginning of the Stream pointer in the fmap
 *
 * ptr is the offset of where the actual data is.
 *
 * To calculate an actual location in the file, it use
 *
 * stream_file_offset + (ptr - base_ptr)
 */
typedef struct __attribute__((packed)) {

    size_t stream_file_offset;

    const uint8_t * base_ptr;

    const uint8_t * ptr;

} ole2_pointer_t;

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
}

static uint16_t getRecInst(OfficeArtRecordHeader * header) {
    return ole2_endian_convert_16((header->recVer_recInstance & 0xfff0) >> 4);
}

static uint8_t getRecVer(OfficeArtRecordHeader * header) {
    return header->recVer_recInstance & 0xf;
}

static const uint8_t* load_pointer_to_stream_from_fmap(ole2_header_t * hdr, const property_t * block, size_t delay, size_t size){
    const uint8_t * ptr = NULL;

    uint32_t offset = get_stream_data_offset(hdr, block, block->start_block);
    offset += delay;
    if ((size_t)(hdr->m_length) < (size_t)(offset + sizeof(fib_base_t))) {
        cli_dbgmsg("ERROR: Invalid offset for stream %d (0x%x)\n", offset, offset);
        goto done;
    }

    /*This is the actual offset in the file.*/
    ptr = fmap_need_off_once(hdr->map, offset, size);
    if (NULL == ptr) {
        cli_dbgmsg("ERROR: Invalid offset for File Information Block %d (0x%x)\n", offset, offset);
        goto done;
    }

done:
    return ptr;
}

static bool getFibRgFcLcb97Header( const property_t *word_block, ole2_header_t *hdr, FibRgFcLcb97 * pFibRgFcLcb97Header) {
    bool bRet = false;

    const uint8_t *ptr = NULL;
    fib_base_t fib     = {0};

#define FIBRGW97_SIZE 28
#define FIBRGLW97_SIZE 88
    /*Bytes we need.
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/9aeaa2e7-4a45-468e-ab13-3f6193eb9394
     * */
    size_t size = sizeof(fib_base_t) +
        2 +  /*csw*/
        FIBRGW97_SIZE +
        2 +  /*cslw*/
        FIBRGLW97_SIZE + 
        2 +  /*cbRgFcLcb */
        sizeof(FibRgFcLcb97)
        ;

    ptr = load_pointer_to_stream_from_fmap(hdr, word_block, 0, size);
    if (NULL == ptr) {
        goto done;
    }
    copy_fib_base(&fib, ptr);

#define FIB_BASE_IDENTIFIER 0xa5ec

    if (FIB_BASE_IDENTIFIER != fib.wIdent) {
        cli_dbgmsg("ERROR: Invalid identifier for File Information Block %d (0x%x)\n", fib.wIdent, fib.wIdent);
        goto done;
    }

    uint32_t idx = sizeof(fib);
    /* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/9aeaa2e7-4a45-468e-ab13-3f6193eb9394 */
    uint16_t csw;
    read_uint16(ptr, size, &idx, &csw);
    if (0x000e != csw){
        cli_dbgmsg("ERROR Invalid csw = 0x%x\n", csw);
        goto done;
    }

    idx += FIBRGW97_SIZE; /* Size of the fibRgW.  Don't think I need anything from there. */

    uint16_t cslw;
    read_uint16(ptr, size, &idx, &cslw);
    if (0x0016 != cslw) {
        cli_dbgmsg("ERROR Invalid cslw = 0x%x\n", cslw);
        goto done;
    }
    idx += FIBRGLW97_SIZE; /* Size of the FibRgLw97.  Don't think I need anything from there. */

    uint16_t cbRgFcLcb;
    read_uint16(ptr, size, &idx, &cbRgFcLcb);

    /*For FIB Version numbers, see
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/175d2fe1-92dd-45d2-b091-1fe8a0c0d40a
     */
#define FIB_VERSION_FIBRGFCLCB97 0x00c1
#define FIB_VERSION_FIBRGFCLCB2000 0x00d9
#define FIB_VERSION_FIBRGFCLCB2002 0x0101
#define FIB_VERSION_FIBRGFCLCB2003 0x010c
#define FIB_VERSION_FIBRGFCLCB2007 0x0112

#define FIB_64BITCNT_FIBRGFCLCB97 0x005d
#define FIB_64BITCNT_FIBRGFCLCB2000 0x006c
#define FIB_64BITCNT_FIBRGFCLCB2002 0x0088
#define FIB_64BITCNT_FIBRGFCLCB2003 0x00a4
#define FIB_64BITCNT_FIBRGFCLCB2007 0x00b7


    switch (fib.nFib){
        default:
            cli_dbgmsg("ERROR Invalid fib.nFib = 0x%x\n", fib.nFib);
            goto done;
        case FIB_VERSION_FIBRGFCLCB97:
            if (FIB_64BITCNT_FIBRGFCLCB97 != cbRgFcLcb){
                cli_dbgmsg("ERROR Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", fib.nFib, cbRgFcLcb);
                goto done;
            }
            break;
        case FIB_VERSION_FIBRGFCLCB2000:
            if (FIB_64BITCNT_FIBRGFCLCB2000 != cbRgFcLcb){
                cli_dbgmsg("ERROR Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", fib.nFib, cbRgFcLcb);
                goto done;
            }
            break;
        case FIB_VERSION_FIBRGFCLCB2002:
            if (FIB_64BITCNT_FIBRGFCLCB2002 != cbRgFcLcb){
                cli_dbgmsg("ERROR Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", fib.nFib, cbRgFcLcb);
                goto done;
            }
            break;
        case FIB_VERSION_FIBRGFCLCB2003:
            if (FIB_64BITCNT_FIBRGFCLCB2003 != cbRgFcLcb){
                cli_dbgmsg("ERROR Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", fib.nFib, cbRgFcLcb);
                goto done;
            }
            break;
        case FIB_VERSION_FIBRGFCLCB2007:
            if (FIB_64BITCNT_FIBRGFCLCB2007 != cbRgFcLcb){
                cli_dbgmsg("ERROR Invalid fib.nFib(0x%x) cbRgFcLcb(0x%x) combo\n", fib.nFib, cbRgFcLcb);
                goto done;
            }
            break;
    }

    /* Since all of the FibBlock structures have a FibRgFcLcb97 at the beginning, we just copy the struct.
     * See https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/175d2fe1-92dd-45d2-b091-1fe8a0c0d40a
     * for more details
     */
    copy_FibRgFcLcb97(pFibRgFcLcb97Header, &(ptr[idx]));
    bRet = true;

done:
    return bRet;
}


typedef struct __attribute__((packed)) {
    uint32_t spidMax;
    uint32_t cidcl;
    uint32_t cspSaved;
    uint32_t cdgSaved;
} OfficeArtFDGG;

static void copy_OfficeArtFDGG(OfficeArtFDGG * dst, const uint8_t * const ptr){
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

/*
 * The OfficeArtBlip data structures don't specify that there could be DIFAT blocks in the middle
 * of the image data, so this function skips over the DIFAT records to make sure to save
 * the correct file data.
 *
 * See the definition of ole_poiter_t for more information.
 */
static void saveImageFile( cli_ctx * ctx, ole2_header_t * ole2Hdr, ole2_pointer_t * ole2Ptr, size_t size){

    char *tempfile = NULL;
    int out_fd = -1;
    cl_error_t ret ;
    size_t bytesWritten = 0;
    FILE * fp = NULL;
    static json_object * ary = NULL;
    size_t totalIncrement = 0;

    size_t blockSize = 1 << ole2Hdr->log2_big_block_size;

    if ((ret = cli_gentempfd_with_prefix(ctx->sub_tmpdir, "ole2_images", &tempfile, &out_fd)) != CL_SUCCESS) {
        cli_dbgmsg("[ole2_process_image_directory] Failed to open output file descriptor\n");
        goto done;
    }

    size_t fileOffset = ole2Ptr->stream_file_offset /*The offset of the document stream in the ole2 file.*/
        + (ole2Ptr->ptr - ole2Ptr->base_ptr);       /*The offset of the file data from the start of the document stream */

    fp = fdopen(out_fd, "wb");

    size_t lastWritten = 0;
    size_t difatIter = 0;
    while (bytesWritten < size) {
        int difatIdx = -1;
        size_t reserveBlock = 0;
        size_t toWrite = size - bytesWritten;
        size_t increment = 0;
        for (; difatIter < NUM_DIFAT_ENTRIES; difatIter++) {
            if (-1 != ole2Hdr->bat_array[difatIter]) {
                size_t block = (ole2Hdr->bat_array[difatIter]+1) << ole2Hdr->log2_big_block_size;
                if ((block >= fileOffset) && (block <= (fileOffset + size))){
                    difatIdx = difatIter;
                    reserveBlock = block;
                    toWrite = reserveBlock - fileOffset;
                    increment = blockSize;
                    totalIncrement += increment;

                    /*Get more space from the fmap to account for the extra block*/
                    const uint8_t * ptr = fmap_need_off_once(ole2Hdr->map, ole2Ptr->stream_file_offset, (ole2Ptr->ptr - ole2Ptr->base_ptr) + increment + size);
                    if (ptr != ole2Ptr->base_ptr) {
                        ole2Ptr->ptr = &(ptr[ole2Ptr->ptr - ole2Ptr->base_ptr]);
                        ole2Ptr->base_ptr = ptr;
                    }
                }
            }
            if (-1 != difatIdx) {
                difatIter++;
                break;
            }
        }

        size_t loopWritten = 0;
        while (loopWritten < toWrite) {
            int ret = fwrite(&(ole2Ptr->ptr[lastWritten + loopWritten]), 1, toWrite - loopWritten, fp);
            if (ret > 0) {
                loopWritten += ret;
            } else {
                break;
            }
        }
        bytesWritten += toWrite;
        lastWritten += toWrite + increment;
    }

    if (bytesWritten != size) {
        cli_dbgmsg("ERROR unable to write to '%s'\n", tempfile);
    }

    if (SCAN_COLLECT_METADATA && ctx->wrkproperty != NULL){
        if (NULL == ary) {
#define OLE2_EXTRACTED_IMAGES_JSON_KEY "OLE2_IMAGES"
            ary = cli_jsonarray(ctx->wrkproperty, OLE2_EXTRACTED_IMAGES_JSON_KEY);
        }
        if (ary) {
            cli_jsonstr(ary, NULL, tempfile);
        }
    }

done:
    ole2Ptr->ptr = &(ole2Ptr->ptr[size + totalIncrement]);

    if (tempfile && !ctx->engine->keeptmp) {
        remove(tempfile);
    }
    CLI_FREE_AND_SET_NULL(tempfile);

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
static void processOfficeArtBlipGeneric(cli_ctx * ctx, ole2_header_t * ole2Hdr, OfficeArtRecordHeader * rh, ole2_pointer_t * ole2Ptr,
        uint16_t riSingleUID, uint16_t riDoubleUID, uint32_t bytesAfterUIDs) {
    size_t offset = 16; /* Size of rh*/

    uint16_t recInst = getRecInst(rh);

    if (riDoubleUID == recInst) {
        offset += 16;
    } else if (riSingleUID != recInst) {
        cli_dbgmsg("ERROR Invalid recInst 0x%x\n", recInst);
        return;
    }
    offset += bytesAfterUIDs; /*metafile header*/

    ole2Ptr->ptr = &(ole2Ptr->ptr[offset]);
    saveImageFile(ctx, ole2Hdr, ole2Ptr, rh->recLen - offset);
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2c09e2c4-0513-419f-b5f9-4feb0a71ef32 */
static void processOfficeArtBlipEMF(cli_ctx * ctx, ole2_header_t * ole2Hdr, OfficeArtRecordHeader * rh, ole2_pointer_t * ole2Ptr) {
    processOfficeArtBlipGeneric(ctx, ole2Hdr, rh, ole2Ptr, 0x3d4, 0x3d5, 34) ;
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/ee892f04-f001-4531-a34b-67aab3426dcb */
static void processOfficeArtBlipWMF(cli_ctx * ctx, ole2_header_t * ole2Hdr, OfficeArtRecordHeader * rh, ole2_pointer_t * ole2Ptr){
    processOfficeArtBlipGeneric(ctx, ole2Hdr, rh, ole2Ptr, 0x216, 0x217, 34) ;
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/4b6c5fc5-98cc-445a-8ec7-12b2f2c05b9f */
static void processOfficeArtBlipPICT(cli_ctx* ctx, ole2_header_t * ole2Hdr, OfficeArtRecordHeader * rh, ole2_pointer_t * ole2Ptr ){
    processOfficeArtBlipGeneric(ctx, ole2Hdr, rh, ole2Ptr, 0x542, 0x543, 34) ;
}

/*https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/704b3ec5-3e3f-425f-b2f7-a090cc68e624*/
static void processOfficeArtBlipJPEG(cli_ctx * ctx, ole2_header_t * ole2Hdr, OfficeArtRecordHeader * rh, ole2_pointer_t * ole2Ptr){
    size_t offset = 16; /* Size of rh*/
    uint16_t recInst = getRecInst(rh);

    if ((0x46b == recInst) || (0x6e3 == recInst)){
        offset += 16;
    } else if ((0x46a != recInst) && (0x6e2 != recInst)) {
        cli_dbgmsg("ERROR Invalid recInst 0x%x\n", recInst);
        return;
    }
    offset += 1; /*metafile header*/

    ole2Ptr->ptr = &(ole2Ptr->ptr[offset]);
    saveImageFile(ctx, ole2Hdr, ole2Ptr, rh->recLen - offset);
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/7af7d17e-6ae1-4c43-a3d6-691e6b3b4a45 */
static void processOfficeArtBlipPNG(cli_ctx * ctx, ole2_header_t * ole2Hdr, OfficeArtRecordHeader * rh, ole2_pointer_t * ole2Ptr){
    processOfficeArtBlipGeneric(ctx, ole2Hdr, rh, ole2Ptr, 0x6e0, 0x6e1, 1) ;
}

/* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/1393bf5e-6fa0-4665-b3ec-68199b555656 */
static void processOfficeArtBlipDIB(cli_ctx * ctx, ole2_header_t * ole2Hdr, OfficeArtRecordHeader * rh, ole2_pointer_t * ole2Ptr){
    processOfficeArtBlipGeneric(ctx, ole2Hdr, rh, ole2Ptr, 0x7a8, 0x7a9, 1) ;
}

static void processOfficeArtBlipTIFF(cli_ctx * ctx, ole2_header_t * ole2Hdr, OfficeArtRecordHeader * rh, ole2_pointer_t * ole2Ptr){
    processOfficeArtBlipGeneric(ctx, ole2Hdr, rh, ole2Ptr, 0x6e4, 0x6e5, 1) ;
}

static size_t processOfficeArtBlip(cli_ctx * ctx, ole2_header_t * ole2Hdr, ole2_pointer_t * ole2Ptr){

    size_t offset = 0;
    OfficeArtRecordHeader rh;

    copy_OfficeArtRecordHeader (&rh, ole2Ptr->ptr);
    offset += sizeof(OfficeArtRecordHeader );
    uint8_t recVer = getRecVer(&rh);
    if (0 != recVer) {
        cli_dbgmsg("ERROR Invalid recVer 0x%x\n", recVer);
        goto done;
    }

#define RECTYPE_OFFICE_ART_BLIP_EMF 0xf01a
#define RECTYPE_OFFICE_ART_BLIP_WMF 0xf01b
#define RECTYPE_OFFICE_ART_BLIP_PICT 0xf01c
#define RECTYPE_OFFICE_ART_BLIP_JPEG 0xf01d
#define RECTYPE_OFFICE_ART_BLIP_PNG 0xf01e
#define RECTYPE_OFFICE_ART_BLIP_DIB 0xf01f
#define RECTYPE_OFFICE_ART_BLIP_TIFF 0xf029
#define RECTYPE_OFFICE_ART_BLIP_JPEG2 0xf02a

    ole2Ptr->ptr = &(ole2Ptr->ptr[offset]);
    switch (rh.recType) {
        case RECTYPE_OFFICE_ART_BLIP_EMF:
            processOfficeArtBlipEMF(ctx, ole2Hdr, &rh, ole2Ptr);
            break;
        case RECTYPE_OFFICE_ART_BLIP_WMF :
            processOfficeArtBlipWMF(ctx, ole2Hdr, &rh, ole2Ptr);
            break;
        case RECTYPE_OFFICE_ART_BLIP_PICT:
            processOfficeArtBlipPICT(ctx, ole2Hdr, &rh, ole2Ptr);
            break;
        case RECTYPE_OFFICE_ART_BLIP_JPEG:
            /* fallthrough */
        case RECTYPE_OFFICE_ART_BLIP_JPEG2:
            processOfficeArtBlipJPEG(ctx, ole2Hdr, &rh, ole2Ptr);
            break;
        case RECTYPE_OFFICE_ART_BLIP_PNG:
            processOfficeArtBlipPNG(ctx, ole2Hdr, &rh, ole2Ptr);
            break;
        case RECTYPE_OFFICE_ART_BLIP_DIB:
            processOfficeArtBlipDIB(ctx, ole2Hdr, &rh, ole2Ptr);
            break;
        case RECTYPE_OFFICE_ART_BLIP_TIFF:
            processOfficeArtBlipTIFF(ctx, ole2Hdr, &rh, ole2Ptr);
            break;
        default:
            cli_dbgmsg("ERROR Invalid recType 0x%x\n", rh.recType);
            break;
    }

done:
    ole2Ptr->ptr = &(ole2Ptr->ptr[sizeof(rh) + rh.recLen]);
    return (sizeof(rh) + rh.recLen);
}

/*
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2f2d7f5e-d5c4-4cb7-b230-59b3fe8f10d6
 */
static size_t processOfficeArtFBSE(cli_ctx * ctx, ole2_header_t *hdr, OfficeArtRecordHeader * imageHeader, ole2_pointer_t * ole2Ptr, property_t * wordDocBlock) {
    OfficeArtFBSEKnown fbse;

    uint32_t offset = sizeof(OfficeArtRecordHeader);
    uint16_t recInst = getRecInst(imageHeader);

    copy_OfficeArtFBSEKnown (&fbse, &(ole2Ptr->ptr[offset]));
    offset += sizeof(OfficeArtFBSEKnown );

    if ((recInst != fbse.btWin32) && (recInst != fbse.btMacOS)) {
        cli_dbgmsg("ERROR Invalid recInst 0x%x\n", recInst);
        return offset;
    }
    if (imageHeader->recType != 0xf007) {
        cli_dbgmsg("ERROR Invalid recType 0x%x\n", imageHeader->recType);
        return offset;
    }

    offset += fbse.cbName;

    ole2Ptr->ptr = &(ole2Ptr->ptr[offset]);
    if (imageHeader->recLen == (sizeof(OfficeArtFBSEKnown) + fbse.cbName + fbse.size)) {
        /* The BLIP is embedded in this record*/ 
        processOfficeArtBlip(ctx, hdr, ole2Ptr);
        ole2Ptr->ptr = &(ole2Ptr->ptr[fbse.size]);
        offset += fbse.size;
    } else {
        /* The BLIP is in the 'WordDocument' stream. */
        size_t size = fbse.size;
        ole2_pointer_t wordStreamPtr = {0};
        wordStreamPtr.base_ptr = load_pointer_to_stream_from_fmap(hdr, wordDocBlock, 0, fbse.foDelay + size);
        if (NULL == wordStreamPtr.base_ptr){
            cli_dbgmsg("ERROR: Unable to get fmap for wordBlock\n");
            goto done;
        }
        wordStreamPtr.ptr = &(wordStreamPtr.base_ptr[fbse.foDelay]);
        wordStreamPtr.stream_file_offset = get_stream_data_offset(hdr, wordDocBlock, wordDocBlock->start_block);
        processOfficeArtBlip(ctx, hdr, &wordStreamPtr);
        /* I don't need to add anything to the offset here, because the actual data is not here.
         * The data is in a different stream
         */
    }

done:
    return offset;
}

size_t get_block_size(ole2_header_t * ole2Hdr) {
    return 1 << ole2Hdr->log2_big_block_size;
}

static void ole2_extract_images(cli_ctx * ctx, ole2_header_t * ole2Hdr, ole2_image_directory_t * directory, property_t * tableStream) {
    FibRgFcLcb97 * header = &(directory->fibRgFcLcb97Header);
    property_t * wordDocBlock = &(directory->word_block);
    ole2_pointer_t ole2Ptr = {0};

    /*This offset is an actual offset of the table stream in the file.*/
    size_t tableStreamOffset = get_stream_data_offset(ole2Hdr, tableStream, tableStream->start_block);

    //ptr = fmap_need_off_once(ole2Hdr->map, tableStreamOffset, 4096);
    ole2Ptr.ptr = fmap_need_off_once(ole2Hdr->map, tableStreamOffset, get_block_size(ole2Hdr));
    if (NULL == ole2Ptr.ptr) {
        cli_dbgmsg("ERROR: Invalid tableStreamOffset for File Information Block %ld (0x%lx)\n", tableStreamOffset, tableStreamOffset);
        goto done;
    }
    //ole2Ptr.start_block = tableStream->start_block;
    ole2Ptr.stream_file_offset = tableStreamOffset;
    ole2Ptr.base_ptr = ole2Ptr.ptr;

    size_t offset = header->fcDggInfo;

    /*
     * Start of OfficeArtContent
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/8699a984-3718-44be-adae-08b05827f8b3
     * First record is an OfficeArtDggContainer
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/dd7133b6-ed10-4bcb-be29-67b0544f884f
     */
    OfficeArtRecordHeader oadc_recordHeader; //OfficeArtDggContainer
    copy_OfficeArtRecordHeader (&oadc_recordHeader, &(ole2Ptr.ptr[offset]));

    if (0xf != oadc_recordHeader.recVer_recInstance){
        cli_dbgmsg("ERROR: Invalid record version (%x)\n", oadc_recordHeader.recVer_recInstance);
        return;
    }

    offset += sizeof (OfficeArtRecordHeader );

    /*
     * Next is the OfficeArtFDGGBlock 
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/a9ff4320-4fa3-4408-8ea4-85c3cec0b501
     * We shouldn't have to care about that, since it's for drawings and not actual file images.
     * Going to just skip this record for now.
     * */
    OfficeArtRecordHeader hdr;
    copy_OfficeArtRecordHeader(&hdr,  &(ole2Ptr.ptr[offset]));

    offset += sizeof(OfficeArtRecordHeader);

    OfficeArtFDGG fdgg;
    copy_OfficeArtFDGG(&fdgg, &(ole2Ptr.ptr[offset]));
    offset += sizeof(OfficeArtFDGG);

    /* OfficeArtIDCL is not used in parsing images, only drawings.  If details are needed, they are
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2335d2f8-109b-4cd6-ac8d-40b1237283f3
     * */
#define OFFICE_ART_IDCL_LEN 8 
    offset += (OFFICE_ART_IDCL_LEN  * (fdgg.cidcl-1));

    /*
     * OfficeArtBStoreContainer
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/561cb6d4-d38b-4666-b2b4-10abc1dce44c
     *
     */
    OfficeArtRecordHeader blipStoreRecordHeader;
    copy_OfficeArtRecordHeader(&blipStoreRecordHeader,  &(ole2Ptr.ptr[offset]));

    /*Allocate the full number of bytes needed for headers.*/
    size_t total_needed = 0;
    while (total_needed < (offset + blipStoreRecordHeader.recLen)) {
        total_needed += get_block_size(ole2Hdr);
    }

    ole2Ptr.ptr = fmap_need_off_once(ole2Hdr->map, tableStreamOffset, total_needed);
    if (NULL == ole2Ptr.ptr) {
        cli_dbgmsg("ERROR: Invalid offset for OfficeArtRecordHeader%ld (0x%lx)\n", total_needed, total_needed);
        goto done;
    }

    if (0xf != getRecVer(&blipStoreRecordHeader)) {
        cli_dbgmsg("ERROR Invalid recVer 0x%x\n", getRecVer(&blipStoreRecordHeader));
        return;
    }

    if (0xf001 != blipStoreRecordHeader.recType){
        cli_dbgmsg("ERROR Invalid recType 0x%x\n", getRecVer(&blipStoreRecordHeader));
        return;
    }

    offset += sizeof(OfficeArtRecordHeader);

    /*Rec types taken from 
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/a7d7d967-6bff-489c-a267-3ec30448344a
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2f2d7f5e-d5c4-4cb7-b230-59b3fe8f10d6
     * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/c67b883b-8136-4e91-a1a3-2981d16e934f
     *
     * */
#define OFFICE_ART_FBSE_REC_TYPE 0x2
    size_t bytesProcessed = 0;
    ole2Ptr.ptr = &(ole2Ptr.ptr[offset]);
    while (bytesProcessed < blipStoreRecordHeader.recLen)
    {
        OfficeArtRecordHeader imageHeader;
        copy_OfficeArtRecordHeader(&imageHeader,  ole2Ptr.ptr);
        uint8_t recVer = getRecVer(&imageHeader);

        if (OFFICE_ART_FBSE_REC_TYPE == recVer){
            /* OfficeArtFBSE 
             * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2f2d7f5e-d5c4-4cb7-b230-59b3fe8f10d6
             */
            bytesProcessed += processOfficeArtFBSE(ctx, ole2Hdr, &imageHeader, &ole2Ptr, wordDocBlock);
        } else {
            bytesProcessed += processOfficeArtBlip(ctx, ole2Hdr, &ole2Ptr);
        }
    }

done:
    return;

}





void ole2_process_image_directory( cli_ctx * ctx, ole2_header_t * hdr, ole2_image_directory_t * directory ) {
    if (directory->bFibRgFcLcb97Header_initialized && (directory->table_stream_0_initialized 
                || directory->table_stream_1_initialized)) {
        property_t * tableStream = NULL;
        /*Get the FIBBase*/
        fib_base_t fib;
        uint32_t fib_offset = get_stream_data_offset(hdr, &(directory->word_block), directory->word_block.start_block);
        const uint8_t * ptr = NULL;

        if ((size_t)(hdr->m_length) < (size_t)(fib_offset + sizeof(fib_base_t))) {
            cli_dbgmsg("ERROR: Invalid offset for File Information Block %d (0x%x)\n", fib_offset, fib_offset);
            goto done;
        }

        ptr = fmap_need_off_once(hdr->map, fib_offset, sizeof(fib_base_t));
        if (NULL == ptr) {
            cli_dbgmsg("ERROR: Invalid offset for File Information Block %d (0x%x)\n", fib_offset, fib_offset);
            goto done;
        }
        copy_fib_base(&fib, ptr);

#define FIB_BASE_fWhichTblStm_OFFSET 9
        if (fib.ABCDEFGHIJKLM & (1 << FIB_BASE_fWhichTblStm_OFFSET)) {
            tableStream = &(directory->table_stream_1_block);
            if (!directory->table_stream_1_initialized){
                cli_dbgmsg("ERROR: FIB references 1Table stream, that does not exist\n");
                goto done;
            }
        } else {
            tableStream = &(directory->table_stream_0_block);
            if (!directory->table_stream_0_initialized){
                cli_dbgmsg("ERROR: FIB references 0Table stream, that does not exist\n");
                goto done;
            }
        }

        ole2_extract_images(ctx, hdr, directory, tableStream);
    }
done:
    return ;
}









#endif /* OLE2_EXTRACT_IMAGES_H_ */
