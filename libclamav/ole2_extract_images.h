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


static void parse_fibRgFcLcb97(const uint8_t * ptr){
    fprintf(stderr, "%s::%d::UNIMPLEMENTED\n", __FUNCTION__, __LINE__); exit(11);
}

static void parse_fibRgFcLcb2000(const uint8_t * ptr){
    fprintf(stderr, "%s::%d::UNIMPLEMENTED\n", __FUNCTION__, __LINE__); exit(11);
}

static void parse_fibRgFcLcb2002(const uint8_t * ptr){
    fprintf(stderr, "%s::%d::Data is in the fcDggInfo, size is in the lcbDggInfo\n", __FUNCTION__, __LINE__);
    fprintf(stderr, "%s::%d::Structure is the FibRgFcLcb97\n", __FUNCTION__, __LINE__);
    fprintf(stderr, "%s::%d::UNIMPLEMENTED\n", __FUNCTION__, __LINE__); exit(11);
}

static void parse_fibRgFcLcb2003(const uint8_t * ptr){
    fprintf(stderr, "%s::%d::UNIMPLEMENTED\n", __FUNCTION__, __LINE__); exit(11);
}

static void parse_fibRgFcLcb2007(const uint8_t * ptr){
    fprintf(stderr, "%s::%d::UNIMPLEMENTED\n", __FUNCTION__, __LINE__); exit(11);
}

static void test_for_pictures( const property_t *word_block, ole2_header_t *hdr) {

    const uint8_t *ptr = NULL;
    fib_base_t fib     = {0};
    size_t i;
    size_t to_read = 0x1000;

    fprintf(stderr,"%s::%d\n", __FUNCTION__, __LINE__);

    uint32_t fib_offset = get_stream_data_offset(hdr, word_block, word_block->start_block);
    fprintf(stderr,"%s::%d\n", __FUNCTION__, __LINE__);

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

    uint32_t idx = sizeof(fib);
    /* https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/9aeaa2e7-4a45-468e-ab13-3f6193eb9394 */
    uint16_t csw;
    read_uint16(ptr, to_read, &idx, &csw);
    if (0x000e != csw){
        fprintf(stderr, "%s::%d::Invalid csw = 0x%x\n", __FUNCTION__, __LINE__, csw);
        return;
    }

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
            parse_fibRgFcLcb2002(ptr);
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


    fprintf(stderr, "%s::%d::", __FUNCTION__, __LINE__);
    for (i = idx; i < to_read; i++){
        fprintf(stderr, "%02x ", ptr[i]);
    }
    fprintf(stderr, "\n");


    fprintf(stderr,"%s::%d::GOT TO END!!!\n", __FUNCTION__, __LINE__);

}


#endif /* OLE2_EXTRACT_IMAGES_H_ */
