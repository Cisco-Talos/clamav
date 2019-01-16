      * Summary: Unicode character APIs
      * Description: API for the Unicode character APIs
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_UNICODE_H__)
      /define XML_UNICODE_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_UNICODE_ENABLED)

      /include "libxmlrpg/xmlTypesC"

     d xmlUCSIsAegeanNumbers...
     d                 pr                  extproc('xmlUCSIsAegeanNumbers')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsAlphabeticPresentationForms...
     d                 pr                  extproc(
     d                                     'xmlUCSIsAlphabeticPresentationForms'
     d                                     )
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsArabic  pr                  extproc('xmlUCSIsArabic')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsArabicPresentationFormsA...
     d                 pr                  extproc(
     d                                     'xmlUCSIsArabicPresentationFormsA')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsArabicPresentationFormsB...
     d                 pr                  extproc(
     d                                     'xmlUCSIsArabicPresentationFormsB')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsArmenian...
     d                 pr                  extproc('xmlUCSIsArmenian')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsArrows  pr                  extproc('xmlUCSIsArrows')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsBasicLatin...
     d                 pr                  extproc('xmlUCSIsBasicLatin')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsBengali...
     d                 pr                  extproc('xmlUCSIsBengali')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsBlockElements...
     d                 pr                  extproc('xmlUCSIsBlockElements')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsBopomofo...
     d                 pr                  extproc('xmlUCSIsBopomofo')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsBopomofoExtended...
     d                 pr                  extproc('xmlUCSIsBopomofoExtended')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsBoxDrawing...
     d                 pr                  extproc('xmlUCSIsBoxDrawing')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsBraillePatterns...
     d                 pr                  extproc('xmlUCSIsBraillePatterns')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsBuhid   pr                  extproc('xmlUCSIsBuhid')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsByzantineMusicalSymbols...
     d                 pr                  extproc(
     d                                     'xmlUCSIsByzantineMusicalSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCJKCompatibility...
     d                 pr                  extproc('xmlUCSIsCJKCompatibility')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCJKCompatibilityForms...
     d                 pr                  extproc(
     d                                     'xmlUCSIsCJKCompatibilityForms')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCJKCompatibilityIdeographs...
     d                 pr                  extproc(
     d                                     'xmlUCSIsCJKCompatibilityIdeographs')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCJKCompatibilityIdeographsSupplement...
     d                 pr                  extproc('xmlUCSIsCJKCompatibilityIde-
     d                                     ographsSupplement')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCJKRadicalsSupplement...
     d                 pr                  extproc(
     d                                     'xmlUCSIsCJKRadicalsSupplement')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCJKSymbolsandPunctuation...
     d                 pr                  extproc(
     d                                     'xmlUCSIsCJKSymbolsandPunctuation')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCJKUnifiedIdeographs...
     d                 pr                  extproc(
     d                                     'xmlUCSIsCJKUnifiedIdeographs')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCJKUnifiedIdeographsExtensionA...
     d                 pr                  extproc('xmlUCSIsCJKUnifiedIdeograph-
     d                                     sExtensionA')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCJKUnifiedIdeographsExtensionB...
     d                 pr                  extproc('xmlUCSIsCJKUnifiedIdeograph-
     d                                     sExtensionB')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCherokee...
     d                 pr                  extproc('xmlUCSIsCherokee')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCombiningDiacriticalMarks...
     d                 pr                  extproc(
     d                                     'xmlUCSIsCombiningDiacriticalMarks')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCombiningDiacriticalMarksforSymbols...
     d                 pr                  extproc('xmlUCSIsCombiningDiacritica-
     d                                     lMarksforSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCombiningHalfMarks...
     d                 pr                  extproc('xmlUCSIsCombiningHalfMarks')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCombiningMarksforSymbols...
     d                 pr                  extproc(
     d                                     'xmlUCSIsCombiningMarksforSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsControlPictures...
     d                 pr                  extproc('xmlUCSIsControlPictures')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCurrencySymbols...
     d                 pr                  extproc('xmlUCSIsCurrencySymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCypriotSyllabary...
     d                 pr                  extproc('xmlUCSIsCypriotSyllabary')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCyrillic...
     d                 pr                  extproc('xmlUCSIsCyrillic')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCyrillicSupplement...
     d                 pr                  extproc('xmlUCSIsCyrillicSupplement')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsDeseret...
     d                 pr                  extproc('xmlUCSIsDeseret')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsDevanagari...
     d                 pr                  extproc('xmlUCSIsDevanagari')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsDingbats...
     d                 pr                  extproc('xmlUCSIsDingbats')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsEnclosedAlphanumerics...
     d                 pr                  extproc(
     d                                     'xmlUCSIsEnclosedAlphanumerics')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsEnclosedCJKLettersandMonths...
     d                 pr                  extproc(
     d                                     'xmlUCSIsEnclosedCJKLettersandMonths'
     d                                     )
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsEthiopic...
     d                 pr                  extproc('xmlUCSIsEthiopic')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsGeneralPunctuation...
     d                 pr                  extproc('xmlUCSIsGeneralPunctuation')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsGeometricShapes...
     d                 pr                  extproc('xmlUCSIsGeometricShapes')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsGeorgian...
     d                 pr                  extproc('xmlUCSIsGeorgian')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsGothic  pr                  extproc('xmlUCSIsGothic')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsGreek   pr                  extproc('xmlUCSIsGreek')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsGreekExtended...
     d                 pr                  extproc('xmlUCSIsGreekExtended')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsGreekandCoptic...
     d                 pr                  extproc('xmlUCSIsGreekandCoptic')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsGujarati...
     d                 pr                  extproc('xmlUCSIsGujarati')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsGurmukhi...
     d                 pr                  extproc('xmlUCSIsGurmukhi')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsHalfwidthandFullwidthForms...
     d                 pr                  extproc(
     d                                     'xmlUCSIsHalfwidthandFullwidthForms')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsHangulCompatibilityJamo...
     d                 pr                  extproc(
     d                                     'xmlUCSIsHangulCompatibilityJamo')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsHangulJamo...
     d                 pr                  extproc('xmlUCSIsHangulJamo')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsHangulSyllables...
     d                 pr                  extproc('xmlUCSIsHangulSyllables')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsHanunoo...
     d                 pr                  extproc('xmlUCSIsHanunoo')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsHebrew  pr                  extproc('xmlUCSIsHebrew')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsHighPrivateUseSurrogates...
     d                 pr                  extproc(
     d                                     'xmlUCSIsHighPrivateUseSurrogates')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsHighSurrogates...
     d                 pr                  extproc('xmlUCSIsHighSurrogates')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsHiragana...
     d                 pr                  extproc('xmlUCSIsHiragana')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsIPAExtensions...
     d                 pr                  extproc('xmlUCSIsIPAExtensions')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsIdeographicDescriptionCharacters...
     d                 pr                  extproc('xmlUCSIsIdeographicDescript-
     d                                     ionCharacters')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsKanbun  pr                  extproc('xmlUCSIsKanbun')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsKangxiRadicals...
     d                 pr                  extproc('xmlUCSIsKangxiRadicals')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsKannada...
     d                 pr                  extproc('xmlUCSIsKannada')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsKatakana...
     d                 pr                  extproc('xmlUCSIsKatakana')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsKatakanaPhoneticExtensions...
     d                 pr                  extproc(
     d                                     'xmlUCSIsKatakanaPhoneticExtensions')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsKhmer   pr                  extproc('xmlUCSIsKhmer')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsKhmerSymbols...
     d                 pr                  extproc('xmlUCSIsKhmerSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLao     pr                  extproc('xmlUCSIsLao')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLatin1Supplement...
     d                 pr                  extproc('xmlUCSIsLatin1Supplement')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLatinExtendedA...
     d                 pr                  extproc('xmlUCSIsLatinExtendedA')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLatinExtendedB...
     d                 pr                  extproc('xmlUCSIsLatinExtendedB')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLatinExtendedAdditional...
     d                 pr                  extproc(
     d                                     'xmlUCSIsLatinExtendedAdditional')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLetterlikeSymbols...
     d                 pr                  extproc('xmlUCSIsLetterlikeSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLimbu   pr                  extproc('xmlUCSIsLimbu')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLinearBIdeograms...
     d                 pr                  extproc('xmlUCSIsLinearBIdeograms')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLinearBSyllabary...
     d                 pr                  extproc('xmlUCSIsLinearBSyllabary')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsLowSurrogates...
     d                 pr                  extproc('xmlUCSIsLowSurrogates')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMalayalam...
     d                 pr                  extproc('xmlUCSIsMalayalam')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMathematicalAlphanumericSymbols...
     d                 pr                  extproc('xmlUCSIsMathematicalAlphanu-
     d                                     mericSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMathematicalOperators...
     d                 pr                  extproc(
     d                                     'xmlUCSIsMathematicalOperators')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMiscellaneousMathematicalSymbolsA...
     d                 pr                  extproc('xmlUCSIsMiscellaneousMathem-
     d                                     aticalSymbolsA')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMiscellaneousMathematicalSymbolsB...
     d                 pr                  extproc('xmlUCSIsMiscellaneousMathem-
     d                                     aticalSymbolsB')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMiscellaneousSymbols...
     d                 pr                  extproc(
     d                                     'xmlUCSIsMiscellaneousSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMiscellaneousSymbolsandArrows...
     d                 pr                  extproc('xmlUCSIsMiscellaneousSymbol-
     d                                     sandArrows')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMiscellaneousTechnical...
     d                 pr                  extproc(
     d                                     'xmlUCSIsMiscellaneousTechnical')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMongolian...
     d                 pr                  extproc('xmlUCSIsMongolian')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMusicalSymbols...
     d                 pr                  extproc('xmlUCSIsMusicalSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsMyanmar...
     d                 pr                  extproc('xmlUCSIsMyanmar')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsNumberForms...
     d                 pr                  extproc('xmlUCSIsNumberForms')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsOgham   pr                  extproc('xmlUCSIsOgham')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsOldItalic...
     d                 pr                  extproc('xmlUCSIsOldItalic')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsOpticalCharacterRecognition...
     d                 pr                  extproc(
     d                                     'xmlUCSIsOpticalCharacterRecognition'
     d                                     )
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsOriya   pr                  extproc('xmlUCSIsOriya')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsOsmanya...
     d                 pr                  extproc('xmlUCSIsOsmanya')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsPhoneticExtensions...
     d                 pr                  extproc('xmlUCSIsPhoneticExtensions')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsPrivateUse...
     d                 pr                  extproc('xmlUCSIsPrivateUse')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsPrivateUseArea...
     d                 pr                  extproc('xmlUCSIsPrivateUseArea')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsRunic   pr                  extproc('xmlUCSIsRunic')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsShavian...
     d                 pr                  extproc('xmlUCSIsShavian')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSinhala...
     d                 pr                  extproc('xmlUCSIsSinhala')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSmallFormVariants...
     d                 pr                  extproc('xmlUCSIsSmallFormVariants')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSpacingModifierLetters...
     d                 pr                  extproc(
     d                                     'xmlUCSIsSpacingModifierLetters')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSpecials...
     d                 pr                  extproc('xmlUCSIsSpecials')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSuperscriptsandSubscripts...
     d                 pr                  extproc(
     d                                     'xmlUCSIsSuperscriptsandSubscripts')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSupplementalArrowsA...
     d                 pr                  extproc(
     d                                     'xmlUCSIsSupplementalArrowsA')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSupplementalArrowsB...
     d                 pr                  extproc(
     d                                     'xmlUCSIsSupplementalArrowsB')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSupplementalMathematicalOperators...
     d                 pr                  extproc('xmlUCSIsSupplementalMathema-
     d                                     ticalOperators')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSupplementaryPrivateUseAreaA...
     d                 pr                  extproc('xmlUCSIsSupplementaryPrivat-
     d                                     eUseAreaA')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSupplementaryPrivateUseAreaB...
     d                 pr                  extproc('xmlUCSIsSupplementaryPrivat-
     d                                     eUseAreaB')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsSyriac  pr                  extproc('xmlUCSIsSyriac')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsTagalog...
     d                 pr                  extproc('xmlUCSIsTagalog')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsTagbanwa...
     d                 pr                  extproc('xmlUCSIsTagbanwa')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsTags    pr                  extproc('xmlUCSIsTags')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsTaiLe   pr                  extproc('xmlUCSIsTaiLe')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsTaiXuanJingSymbols...
     d                 pr                  extproc('xmlUCSIsTaiXuanJingSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsTamil   pr                  extproc('xmlUCSIsTamil')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsTelugu  pr                  extproc('xmlUCSIsTelugu')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsThaana  pr                  extproc('xmlUCSIsThaana')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsThai    pr                  extproc('xmlUCSIsThai')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsTibetan...
     d                 pr                  extproc('xmlUCSIsTibetan')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsUgaritic...
     d                 pr                  extproc('xmlUCSIsUgaritic')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsUnifiedCanadianAboriginalSyllabics...
     d                 pr                  extproc('xmlUCSIsUnifiedCanadianAbor-
     d                                     iginalSyllabics')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsVariationSelectors...
     d                 pr                  extproc('xmlUCSIsVariationSelectors')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsVariationSelectorsSupplement...
     d                 pr                  extproc('xmlUCSIsVariationSelectorsS-
     d                                     upplement')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsYiRadicals...
     d                 pr                  extproc('xmlUCSIsYiRadicals')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsYiSyllables...
     d                 pr                  extproc('xmlUCSIsYiSyllables')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsYijingHexagramSymbols...
     d                 pr                  extproc(
     d                                     'xmlUCSIsYijingHexagramSymbols')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsBlock   pr                  extproc('xmlUCSIsBlock')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)
     d  block                          *   value options(*string)               const char *

     d xmlUCSIsCatC    pr                  extproc('xmlUCSIsCatC')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatCc   pr                  extproc('xmlUCSIsCatCc')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatCf   pr                  extproc('xmlUCSIsCatCf')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatCo   pr                  extproc('xmlUCSIsCatCo')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatCs   pr                  extproc('xmlUCSIsCatCs')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatL    pr                  extproc('xmlUCSIsCatL')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatLl   pr                  extproc('xmlUCSIsCatLl')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatLm   pr                  extproc('xmlUCSIsCatLm')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatLo   pr                  extproc('xmlUCSIsCatLo')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatLt   pr                  extproc('xmlUCSIsCatLt')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatLu   pr                  extproc('xmlUCSIsCatLu')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatM    pr                  extproc('xmlUCSIsCatM')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatMc   pr                  extproc('xmlUCSIsCatMc')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatMe   pr                  extproc('xmlUCSIsCatMe')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatMn   pr                  extproc('xmlUCSIsCatMn')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatN    pr                  extproc('xmlUCSIsCatN')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatNd   pr                  extproc('xmlUCSIsCatNd')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatNl   pr                  extproc('xmlUCSIsCatNl')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatNo   pr                  extproc('xmlUCSIsCatNo')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatP    pr                  extproc('xmlUCSIsCatP')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatPc   pr                  extproc('xmlUCSIsCatPc')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatPd   pr                  extproc('xmlUCSIsCatPd')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatPe   pr                  extproc('xmlUCSIsCatPe')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatPf   pr                  extproc('xmlUCSIsCatPf')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatPi   pr                  extproc('xmlUCSIsCatPi')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatPo   pr                  extproc('xmlUCSIsCatPo')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatPs   pr                  extproc('xmlUCSIsCatPs')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatS    pr                  extproc('xmlUCSIsCatS')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatSc   pr                  extproc('xmlUCSIsCatSc')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatSk   pr                  extproc('xmlUCSIsCatSk')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatSm   pr                  extproc('xmlUCSIsCatSm')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatSo   pr                  extproc('xmlUCSIsCatSo')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatZ    pr                  extproc('xmlUCSIsCatZ')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatZl   pr                  extproc('xmlUCSIsCatZl')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatZp   pr                  extproc('xmlUCSIsCatZp')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCatZs   pr                  extproc('xmlUCSIsCatZs')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)

     d xmlUCSIsCat     pr                  extproc('xmlUCSIsCat')
     d                                     like(xmlCint)
     d  code                               value like(xmlCint)
     d  cat                            *   value options(*string)               const char *

      /endif                                                                    LIBXML_UNICODE_ENBLD
      /endif                                                                    XML_UNICODE_H__
