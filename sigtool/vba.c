/*
 *  Copyright (C) 2004 Trog <trog@uncon.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>

#include "libclamav/clamav.h"
#include "libclamav/vba_extract.h"
#include "libclamav/ole2_extract.h"
#include "shared/output.h"

#include "vba.h"

typedef struct mac_token_tag
{
    unsigned char token;
    const char *str;
} mac_token_t;

typedef struct mac_token2_tag
{
    uint16_t token;
    const char *str;

} mac_token2_t;

cli_ctx *convenience_ctx(int fd) {
    cli_ctx *ctx;
    struct cl_engine *engine;

    ctx = cli_calloc(1, sizeof(cli_ctx));
    if(!ctx){
	printf("ctx allocation failed\n");
        return NULL;
    }

    ctx->engine = engine = cl_engine_new();
    if(!(ctx->engine)){	    
	printf("engine initialization failed\n");
        free(ctx);
	return NULL;
    }	

    ctx->fmap = cli_calloc(1, sizeof(struct F_MAP *));
    if(!(ctx->fmap)){
	printf("fmap initialization failed\n");
        free(engine);
        free(ctx);
	return NULL;
    }

    if(!(*ctx->fmap = fmap(fd, 0, 0))){
	printf("fmap failed\n");
	free(ctx->fmap);
	free(engine);
        free(ctx);
	return NULL;
    }
    return ctx;
}

void destroy_ctx(int desc, cli_ctx *ctx) {
    funmap(*(ctx->fmap));
    if (desc >= 0)
        close(desc);
    free(ctx->fmap);
    cl_engine_free((struct cl_engine *)ctx->engine);
    free(ctx);
}

int sigtool_vba_scandir(const char *dirname, int hex_output, struct uniq *U);

static char *get_unicode_name (char *name, int size)
{
    int i, j;
    char *newname;

    if (*name == 0 || size <= 0) {
	return NULL;
    }

    newname = (char *) malloc (size * 2);
    if (!newname) {
	return NULL;
    }
    j = 0;
    for (i = 0; i < size; i = i + 2) {
	if (isprint (name[i])) {
	    newname[j++] = name[i];
	} else {
	    if (name[i] < 10 && name[i] >= 0) {
		newname[j++] = '_';
		newname[j++] = name[i] + '0';
	    }
	    newname[j++] = '_';
	}
    }
    newname[j] = '\0';
    return newname;
}

static void output_token (unsigned char token)
{
    int i;
    mac_token_t mac_token[] = {
	{0x01, "-"},
	{0x02, "Not"},
	{0x03, "And"},
	{0x04, "Or"},
	{0x05, "("},
	{0x06, ")"},
	{0x07, "+"},
	{0x08, "-"},
	{0x09, "/"},
	{0x0a, "*"},
	{0x0b, "Mod"},
	{0x0c, "="},
	{0x0d, "<>"},
	{0x0e, "<"},
	{0x0f, ">"},
	{0x10, "<="},
	{0x11, ">="},
	{0x12, ","},
	{0x18, "Resume"},
	{0x19, ":"},
	{0x1a, "End"},
	{0x1b, "Sub"},
	{0x1c, "Function"},
	{0x1d, "If"},
	{0x1e, "Then"},
	{0x1f, "ElseIf"},
	{0x20, "Else"},
	{0x21, "While"},
	{0x22, "Wend"},
	{0x23, "For"},
	{0x24, "To"},
	{0x25, "Step"},
	{0x26, "Next"},
	{0x28, ";"},
	{0x29, "Call"},
	{0x2a, "Goto"},
	{0x2c, "On"},
	{0x2d, "Error"},
	{0x2e, "Let"},
	{0x2f, "Dim"},
	{0x30, "Shared"},
	{0x31, "Select"},
	{0x32, "Is"},
	{0x33, "Case"},
	{0x34, "As"},
	{0x35, "Redim"},
	{0x36, "Print"},
	{0x37, "Input"},
	{0x38, "Line"},
	{0x39, "Write"},
	{0x3a, "Name"},
	{0x3b, "Output"},
	{0x3c, "Append"},
	{0x3d, "Open"},
	{0x3e, "GetCurValues"},
	{0x3f, "Dialog"},
	{0x40, "Super"},
	{0x41, "Declare"},
	{0x42, "Double"},
	{0x43, "Integer"},
	{0x44, "Long"},
	{0x45, "Single"},
	{0x46, "String"},
	{0x47, "Cdecl"},
	{0x48, "Alias"},
	{0x49, "Any"},
	{0x4a, "ToolsGetSpelling"},
	{0x4b, "ToolsGetSynonyms"},
	{0x4c, "Close"},
	{0x4d, "Begin"},
	{0x4e, "Lib"},
	{0x4f, "Read"},
	{0x50, "CheckDialog"},
	{0x51, " "},		/* not sure about this one - some white space */
	{0x52, "\t"},
	{0x54, "EndIf"},
	{0x64, "\n"},
	{0x71, "#"},
	{0x72, "\\"},
	{0x00, NULL},
    };

    for (i = 0; mac_token[i].token != 0x00; i++) {
	if (token == mac_token[i].token) {
	    printf (" %s ", mac_token[i].str);
	    return;
	}
    }
    printf ("[#0x%x]", token);
    return;
}

static void output_token67 (uint16_t token)
{
    int i;
    mac_token2_t mac_token[] = {
	{0x0004, "HelpActivateWindow"},
	{0x0009, "HelpAbout"},
	{0x000c, "ShrinkFont"},
	{0x0016, "NextWindow"},
	{0x0017, "PrevWindow"},
	{0x001c, "DeleteWord"},
	{0x001e, "EditClear"},
	{0x0045, "GoBack"},
	{0x0046, "SaveTemplate"},
	{0x0048, "Cancel"},
	{0x004e, "DocumentStatistics"},
	{0x004f, "FileNew"},
	{0x0050, "FileOpen"},
	{0x0053, "FileSave"},
	{0x0054, "FileSaveAs"},
	{0x0056, "FileSummaryInfo"},
	{0x0057, "FileTemplates"},
	{0x0058, "FilePrint"},
	{0x0061, "FilePrintSetup"},
	{0x0063, "FileFind"},
	{0x006c, "EditCut"},
	{0x006d, "EditCopy"},
	{0x006e, "EditPaste"},
	{0x0070, "EditFind"},
	{0x0074, "EditFindClearFormatting"},
	{0x0075, "EditReplace"},
	{0x0079, "EditReplaceClearFormatting"},
	{0x007a, "EditGoTo"},
	{0x007b, "EditAutoText"},
	{0x0093, "ViewPage"},
	{0x0098, "ToolsCustomize"},
	{0x009b, "NormalViewHeaderArea"},
	{0x009f, "InsertBreak"},
	{0x00a2, "InsertSymbol"},
	{0x00a4, "InsertFile"},
	{0x00a8, "EditBookmark"},
	{0x00ac, "InsertObject"},
	{0x00ae, "FormatFont"},
	{0x00af, "FormatParagraph"},
	{0x00b2, "FilePageSetup"},
	{0x00bf, "ToolsSpelling"},
	{0x00ca, "ToolsOptions"},
	{0x00cc, "ToolsOptionsView"},
	{0x00cb, "ToolsOptionsGeneral"},
	{0x00d1, "ToolsOptionsSave"},
	{0x00d3, "ToolsOptionsSpelling"},
	{0x00d5, "ToolsOptionsUserInfo"},
	{0x00d7, "ToolsMacro"},
	{0x00de, "Organizer"},
	{0x00e1, "ToolsOptionsFileLocations"},
	{0x00e4, "ToolsWordCount"},
	{0x00e9, "DocRestore"},
	{0x00ed, "EditSelectAll"},
	{0x00f3, "ClosePane"},
	{0x0129, "UserDialog"},
	{0x012c, "CopyFile"},
	{0x012d, "FileNewDefault"},
	{0x012e, "FilePrintDefault"},
	{0x0143, "ViewToolbars"},
	{0x015d, "TextFormField"},
	{0x0161, "FormFieldOptions"},
	{0x0172, "InsertFootnote"},
	{0x0179, "DrawRectangle"},
	{0x017a, "ToolsAutoCorrect"},
	{0x01a4, "Connect"},
	{0x01a5, "WW2_EditFind"},
	{0x01a6, "WW2_EditReplace"},
	{0x01b0, "ToolsCustomizeKeyboard"},
	{0x01b1, "ToolsCustomizeMenus"},
	{0x01d2, "DrawBringToFront"},
	{0x01d3, "DrawSendToBack"},
	{0x01e3, "InsertFormField"},
	{0x01f7, "ToolsProtectDocument"},
	{0x0202, "ShrinkFontOnePoint"},
	{0x0209, "ToolsUnprotectDocument"},
	{0x022f, "DrawFlipHorizontal"},
	{0x0235, "FormatDrawingObject"},
	{0x0241, "ViewZoom"},
	{0x0246, "ToogleFull"},
	{0x024a, "NewToolbar"},
	{0x0265, "FileSendMail"},
	{0x0267, "ToolsCustomizeMenuBar"},
	{0x0270, "FileRoutingSlip"},
	{0x0273, "ChooseButtonImage"},
	{0x027b, "HelpTipOfTheDay"},
	{0x0280, "Int"},
	{0x0290, "MicrosoftMail"},
	{0x0299, "ScreenRefresh"},
	{0x02b0, "HelpContents"},
	{0x0780, "Str$"},
	{0x0e80, "Rnd"},
	{0x2580, "FileName$"},
	{0x2b80, "MsgBox"},
	{0x2c80, "Beep"},
	{0x5400, "FileSaveAs"},
	{0x5600, "FileSummaryInfo"},
	{0x8000, "Abs"},
	{0x8001, "Sgn"},
	{0x8002, "Int"},
	{0x8003, "Len"},
	{0x8004, "Asc"},
	{0x8005, "Chr$"},
	{0x8006, "Val"},
	{0x8007, "Str$"},
	{0x8008, "Left$"},
	{0x8009, "Right$"},
	{0x800a, "Mid$"},
	{0x800b, "String$"},
	{0x800c, "Date$"},
	{0x800d, "Time$"},
	{0x800e, "Rnd"},
	{0x800f, "InStr"},
	{0x8012, "Insert"},
	{0x8013, "InsertPara"},
	{0x8015, "Selection$"},
	{0x801b, "ExistingBookMark"},
	{0x8023, "IsDocumentDirty"},
	{0x8024, "SetDocumentDirty"},
	{0x8025, "FileName$"},
	{0x8026, "CountFiles"},
	{0x8027, "GetAutoText$"},
	{0x8028, "CountAutoTextEntries"},
	{0x802a, "SetAutoText"},
	{0x802b, "MsgBox"},
	{0x802c, "Beep"},
	{0x802d, "Shell"},
	{0x802f, "ResetPara"},
	{0x8032, "DocMove"},
	{0x8033, "DocSize"},
	{0x8034, "VLine"},
	{0x803a, "CountWindows"},
	{0x803b, "WindowName$"},
	{0x803e, "Window"},
	{0x8041, "AppMinimize"},
	{0x8042, "AppMaximize"},
	{0x8043, "AppRestore"},
	{0x8044, "DocMaximize"},
	{0x8045, "GetProfileString$"},
	{0x8046, "SetProfileString"},
	{0x8047, "CharColor"},
	{0x8048, "Bold"},
	{0x8049, "Italic"},
	{0x804e, "UnderLine"},
	{0x8053, "CenterPara"},
	{0x8054, "LeftPara"},
	{0x8055, "RightPara"},
	{0x8056, "JustifyPara"},
	{0x805c, "DDEInitiate"},
	{0x805d, "DDETerminate"},
	{0x8053, "DDETerminateAll"},
	{0x805f, "DDEExecute"},
	{0x8060, "DDEPoke"},
	{0x8061, "DDERequest$"},
	{0x8062, "Activate"},
	{0x8063, "AppActivate"},
	{0x8064, "SendKeys"},
	{0x806f, "ViewStatusBar"},
	{0x8071, "ViewRibbon"},
	{0x8073, "ViewPage"},
	{0x8075, "ViewNormal"},
	{0x8079, "Overtype"},
	{0x807a, "Font$"},
	{0x807b, "CountOfFonts"},
	{0x807c, "Font"},
	{0x807d, "FontSize"},
	{0x8081, "WW6_EditClear"},
	{0x8082, "FileList"},
	{0x8083, "File1"},
	{0x8098, "ExtendSelection"},
	{0x809e, "DisableInput"},
	{0x809f, "DocClose"},
	{0x80a0, "FileClose"},
	{0x80a1, "File$"},
	{0x80a2, "FileExit"},
	{0x80a3, "FileSaveAll"},
	{0x80a7, "Input$"},
	{0x80a8, "Seek"},
	{0x80a9, "Eof"},
	{0x80aa, "Lof"},
	{0x80ab, "Kill"},
	{0x80ac, "ChDir"},
	{0x80ad, "MkDir"},
	{0x80ae, "RmDir"},
	{0x80af, "UCase$"},
	{0x80b0, "LCase$"},
	{0x80b1, "InoutBox$"},
	{0x80b3, "OnTime"},
	{0x80b5, "AppInfo$"},
	{0x80b6, "SelInfo"},
	{0x80b7, "CountMacros"},
	{0x80b8, "MacroName"},
	{0x80b9, "CountFoundFiles"},
	{0x80ba, "FoundFileName$"},
	{0x80be, "MacroDesc$"},
	{0x80bf, "CountKeys"},
	{0x80c1, "KeyMacro$"},
	{0x80c2, "MacroCopy"},
	{0x80c3, "IsExecuteOnly"},
	{0x80c7, "OKButton"},
	{0x80c8, "CancelButton"},
	{0x80c9, "Text"},
	{0x80ca, "GroupBox"},
	{0x80cb, "OptionButton"},
	{0x80cc, "PushButton"},
	{0x80d5, "ExitWindows"},
	{0x80d6, "DisableAutoMacros"},
	{0x80d7, "EditFindFound"},
	{0x80d8, "CheckBox"},
	{0x80d9, "TextBox"},
	{0x80da, "ListBox"},
	{0x80db, "OptionGroup"},
	{0x80dc, "ComboBox"},
	{0x80de, "WindowList"},
	{0x80e8, "CountDirectories"},
	{0x80e9, "GetDirectory$"},
	{0x80ea, "LTrim$"},
	{0x80eb, "RTrim$"},
	{0x80ee, "Environ$"},
	{0x80ef, "WaitCursor"},
	{0x80f0, "DateSerial"},
	{0x80f1, "DateValue"},
	{0x80f2, "Day"},
	{0x80f4, "Hour"},
	{0x80f5, "Minute"},
	{0x80f6, "Month"},
	{0x80f7, "Now"},
	{0x80f8, "WeekdayNow"},
	{0x80f9, "Year"},
	{0x80fa, "DocWindowHeight"},
	{0x80fb, "DocWindowWidth"},
	{0x80fc, "DOSToWIN$"},
	{0x80fd, "WinToDOS$"},
	{0x80ff, "Second"},
	{0x8100, "TimeValue"},
	{0x8101, "Today"},
	{0x8103, "SetAttr"},
	{0x8105, "DocMinimize"},
	{0x8107, "AppActivate"},
	{0x8108, "AppCount"},
	{0x8109, "AppGetNames"},
	{0x810a, "AppHide"},
	{0x810b, "AppIsRunning"},
	{0x810c, "GetSystemInfo$"},
	{0x810d, "GetPrivateProfileString$"},
	{0x810e, "SetPrivateProfileString"},
	{0x810f, "GetAttr"},
	{0x8111, "ScreenUpdating"},
	{0x8116, "SelectCurWord"},
	{0x8118, "IsTemplateDirty"},
	{0x8119, "SetTemplateDirty"},
	{0x811b, "DlgEnable"},
	{0x811d, "DlgVisible"},
	{0x811f, "DlgText$"},
	{0x8121, "AppShow"},
	{0x8122, "DlgListBoxArray"},
	{0x8125, "Picture"},
	{0x8126, "DlgSetPicture"},
	{0x8131, "WW2_Files$"},
	{0x8138, "DlgFocus"},
	{0x813b, "BorderLineStyle"},
	{0x813d, "MenuItemText$"},
	{0x813e, "MenuItemMacro$"},
	{0x813f, "CountMenus"},
	{0x8140, "MenuText$"},
	{0x8141, "CountMenuItems"},
	{0x8145, "DocWindowPosTop"},
	{0x8146, "DocWindowPosLeft"},
	{0x8147, "Stop"},
	{0x8148, "DropListBox"},
	{0x8149, "RenameMenu"},
	{0x814a, "FileCloseAll"},
	{0x814b, "SortArray"},
	{0x814c, "SetDocumentVar"},
	{0x814d, "GetDocumentVar$"},
	{0x8152, "IsMacro"},
	{0x8153, "FileNameFromWindow$"},
	{0x815b, "MoveToolbar"},
	{0x816e, "MacID$"},
	{0x8170, "GetSelEndPos"},
	{0x8171, "SetSelRange"},
	{0x8172, "GetText$"},
	{0x8174, "DeleteButton"},
	{0x8175, "AddButton"},
	{0x8177, "DeleteAddIn"},
	{0x8178, "AddAddIn"},
	{0x8179, "GetAddInName$"},
	{0x817c, "ResetButtonImage"},
	{0x8180, "GetAddInId"},
	{0x8181, "CountAddIns"},
	{0x8182, "ClearAddIns"},
	{0x8183, "AddInState"},
	{0x818c, "DefaultDir$"},
	{0x818d, "FileNameInfo$"},
	{0x818e, "MacroFileName$"},
	{0x818f, "ViewHeader"},
	{0x8190, "ViewFooter"},
	{0x8192, "CopyButtonImage"},
	{0x8195, "CountToolbars"},
	{0x8196, "ToolbarName$"},
	{0x8198, "ChDefaultDir"},
	{0x8199, "EditUndo"},
	{0x81a0, "GetAutoCorrect$"},
	{0x81a2, "FileQuit"},
	{0x81a4, "FileConfirmConversions"},
	{0x81d3, "SelectionFileName$"},
	{0x81d9, "CountToolbarButtons"},
	{0x81da, "ToolbarButtonMacro$"},
	{0x81db, "WW2_Insert"},
	{0x81dc, "AtEndOfDocument"},
	{0x81fc, "GetDocumentProperty$"},
	{0x81fd, "GetDocumentProperty"},
	{0x8201, "DocumentPropertyName$"},
	{0x820e, "SpellChecked"},
	{0xb780, "CountMacros"},
	{0xb880, "MacroName$"},
	{0xc000, "CharLeft"},
	{0xc001, "CharRight"},
	{0xc002, "WordLeft"},
	{0xc003, "WordRight"},
	{0xc004, "EndOfLine"},
	{0xc007, "ParaDown"},
	{0xc008, "LineUp"},
	{0xc009, "LineDown"},
	{0xc00a, "PageUp"},
	{0xc00c, "StartOfLine"},
	{0xc00d, "EndOfLine"},
	{0xc010, "StartOfDocument"},
	{0xc011, "EndOfDocument"},
	{0xc012, "EditClear"},
	{0xc024, "BorderTop"},
	{0xc025, "BorderLeft"},
	{0xc026, "BorderBottom"},
	{0xc027, "BorderRight"},
	{0xc280, "MacroCopy"},
	{0x0000, NULL},
    };
    for (i = 0; mac_token[i].token != 0x0000; i++) {
	if (token == mac_token[i].token) {
	    printf ("%s", mac_token[i].str);
	    return;
	}
    }
    printf ("[#67(0x%x)]", token);
    return;
}

static void output_token73 (uint16_t token)
{
    int i;
    mac_token2_t mac_token[] = {
	{0x0001, ".Name"},
	{0x0002, ".KeyCode"},
	{0x0003, ".Context"},
	{0x0004, ".ResetAll"},
	{0x0007, ".Menu"},
	{0x0008, ".MenuText"},
	{0x0009, ".APPUSERNAME"},
	{0x000b, ".Delete"},
	{0x000c, ".Sort"},
	{0x0012, ".SavedBy"},
	{0x0014, ".DateCreatedFrom"},
	{0x0015, ".DateCreatedTo"},
	{0x0016, ".DateSavedFrom"},
	{0x0017, ".DateSavedTo"},
	{0x0020, ".ButtonFieldClicks"},
	{0x0021, ".Font"},
	{0x0022, ".Points"},
	{0x0023, ".Color"},
	{0x0024, ".Bold"},
	{0x0025, ".Italic"},
	{0x0027, ".Hidden"},
	{0x0028, ".Underline"},
	{0x0029, ".Outline"},
	{0x002b, ".Position"},
	{0x002d, ".Spacing"},
	{0x002f, ".Printer"},
	{0x0034, ".AutoSave"},
	{0x0035, ".Units"},
	{0x0036, ".Pagination"},
	{0x0037, ".SummaryPrompt"},
	{0x0039, ".Initials"},
	{0x003a, ".Tabs"},
	{0x003b, ".Spaces"},
	{0x003c, ".Paras"},
	{0x003d, ".Hyphens"},
	{0x003e, ".ShowAll"},
	{0x0041, ".TextBoundaries"},
	{0x0043, ".VScroll"},
	{0x0046, ".PageWidth"},
	{0x0047, ".PageHeight"},
	{0x0049, ".TopMargin"},
	{0x004a, ".BottomMargin"},
	{0x004b, ".LeftMargin"},
	{0x004c, ".RightMargin"},
	{0x0052, ".Template"},
	{0x0059, ".RecentFileCount"},
	{0x005d, ".SmallCaps"},
	{0x0060, ".Password"},
	{0x0061, ".RecentFiles"},
	{0x0062, ".Title"},
	{0x0063, ".Subject"},
	{0x0064, ".Author"},
	{0x0065, ".Keywords"},
	{0x0066, ".Comments"},
	{0x0067, ".FileName"},
	{0x0068, ".Directory"},
	{0x0069, ".CreateDate"},
	{0x006a, ".LastSavedDate"},
	{0x006b, ".LastSavedBy"},
	{0x006c, ".RevisionNumber"},
	{0x006f, ".NumPages"},
	{0x0070, ".NumWords"},
	{0x0071, ".NumChars"},
	{0x0074, ".Rename"},
	{0x0075, ".NewName"},
	{0x0078, ".SmartQuotes"},
	{0x007f, ".Source"},
	{0x0080, ".Reference"},
	{0x0085, ".Insert"},
	{0x0086, ".Destination"},
	{0x0087, ".Type"},
	{0x0089, ".HeaderDistance"},
	{0x008a, ".FooterDistance"},
	{0x008b, ".FirstPage"},
	{0x008c, ".OddAndEvenPages"},
	{0x0091, ".Entry"},
	{0x0092, ".Range"},
	{0x0095, ".Link"},
	{0x0098, ".Add"},
	{0x009b, ".NewTemplate"},
	{0x009f, ".ReadOnly"},
	{0x00a1, ".LeftIndent"},
	{0x00a2, ".RightIndent"},
	{0x00a3, ".FirstIndent"},
	{0x00a5, ".After"},
	{0x00b9, ".NumCopies"},
	{0x00ba, ".From"},
	{0x00bb, ".To"},
	{0x00cb, ".Format"},
	{0x00cd, ".Replace"},
	{0x00ce, ".WholeWord"},
	{0x00cf, ".MatchCase"},
	{0x00d7, ".CreateBackup"},
	{0x00d8, ".LockAnnot"},
	{0x00d9, ".Direction"},
	{0x00ff, ".SuggestFromMainDictOnly"},
	{0x012b, ".UpdateLinks"},
	{0x012e, ".Update"},
	{0x0131, ".Text"},
	{0x0136, ".Description"},
	{0x0139, ".Setting"},
	{0x013b, ".AllCaps"},
	{0x0148, ".Category"},
	{0x0149, ".ConfirmConversions"},
	{0x014c, ".StatusBar"},
	{0x014d, ".PicturePlaceHolders"},
	{0x014e, ".FieldCodes"},
	{0x0150, ".Show"},
	{0x0156, ".FastSaves"},
	{0x0157, ".SaveInterval"},
	{0x0161, ".LineColor"},
	{0x017d, ".Wrap"},
	{0x0183, ".AutoFit"},
	{0x0184, ".CharNum"},
	{0x018b, ".View"},
	{0x0190, ".Options"},
	{0x0194, ".Find"},
	{0x0196, ".Path"},
	{0x01a8, ".Background"},
	{0x01a9, ".SearchPath"},
	{0x01ab, ".CustomDict1"},
	{0x01ac, ".CustomDict2"},
	{0x01ad, ".CustomDict3"},
	{0x01ae, ".CustomDict4"},
	{0x01b1, ".Collate"},
	{0x01b2, ".Shadow"},
	{0x01b4, ".Button"},
	{0x01b9, ".Remove"},
	{0x01ba, ".Protect"},
	{0x01d7, ".Store"},
	{0x01da, ".Class"},
	{0x01de, ".Hide"},
	{0x01df, ".Toolbar"},
	{0x01e0, ".ReplaceAll"},
	{0x01eb, ".Address"},
	{0x01f4, ".SelectedFile"},
	{0x01f5, ".Run"},
	{0x01f6, ".Edit"},
	{0x0218, ".LastSaved"},
	{0x0219, ".Revision"},
	{0x021c, ".Pages"},
	{0x021d, ".Words"},
	{0x0232, ".WPHelp"},
	{0x0233, ".WPDocNavKeys"},
	{0x0234, ".SetDesc"},
	{0x023d, ".CountFootNodes"},
	{0x0255, ".AddToMru"},
	{0x0262, ".NoteTypes"},
	{0x0272, ".With"},
	{0x0275, ".CustoDict5"},
	{0x0276, ".CustoDict6"},
	{0x0277, ".CustoDict7"},
	{0x0278, ".CustoDict8"},
	{0x0279, ".CustoDict9"},
	{0x027a, ".CustoDict10"},
	{0x027e, ".ErrorBeeps"},
	{0x0285, ".Goto"},
	{0x0287, ".Copy"},
	{0x028e, ".Caption"},
	{0x0299, ".AddBelow"},
	{0x02a4, ".Effects3d"},
	{0x02ac, ".MenuType"},
	{0x02ad, ".DraftFont"},
	{0x02af, ".WrapToWindow"},
	{0x02b0, ".Drawings"},
	{0x02c0, ".NumLines"},
	{0x02c6, ".SuperScript"},
	{0x02c7, ".Subscript"},
	{0x02c8, ".WritePassword"},
	{0x02c9, ".RecommendReadOnly"},
	{0x02ca, ".DocumentPassword"},
	{0x02d5, ".HelpText"},
	{0x02d6, ".InsertAs"},
	{0x02dc, ".Formatting"},
	{0x02de, ".InitialCaps"},
	{0x02df, ".SentenceCaps"},
	{0x02e0, ".Days"},
	{0x02e1, ".ReplaceText"},
	{0x02e4, ".Product"},
	{0x02f1, ".SoundsLike"},
	{0x02f2, ".KerningMin"},
	{0x02f3, ".PatternMatch"},
	{0x0308, ".EmbedFonts"},
	{0x030a, ".Width"},
	{0x030b, ".Height"},
	{0x0316, ".SendMailAttach"},
	{0x0318, ".Kerning"},
	{0x0319, ".Exit"},
	{0x031a, ".Enable"},
	{0x031b, ".OwnHelp"},
	{0x031c, ".OwnStat"},
	{0x031d, ".StatText"},
	{0x031e, ".FormsData"},
	{0x0320, ".BookMarks"},
	{0x0327, ".LinkStyles"},
	{0x032a, ".Message"},
	{0x032d, ".AllAtOnce"},
	{0x032f, ".TrackStatus"},
	{0x0330, ".FillColor"},
	{0x0332, ".FillPatternColor"},
	{0x033a, ".RoundCorners"},
	{0x0349, ".TextType"},
	{0x0353, ".TextWidth"},
	{0x0354, ".TextDefault"},
	{0x0355, ".TextFormat"},
	{0x0366, ".SearchName"},
	{0x0370, ".BlueScreen"},
	{0x0377, ".ListBy"},
	{0x0378, ".SubDir"},
	{0x0388, ".HorizontalPos"},
	{0x0389, ".HorizontalFrom"},
	{0x038a, ".VerticalPos"},
	{0x038b, ".VerticalFrom"},
	{0x038f, ".Tab"},
	{0x039a, ".Strikethrough"},
	{0x039b, ".Face"},
	{0x039d, ".NativePictureFormat"},
	{0x039e, ".FileSize"},
	{0x03a2, ".LineType"},
	{0x03a4, ".DisplayIcon"},
	{0x03a8, ".IconFilename"},
	{0x03a9, ".IconNumber"},
	{0x03ac, ".GlobalDotPrompt"},
	{0x03b2, ".NoReset"},
	{0x03db, ".SaveAsAOCELetter"},
	{0x041b, ".CapsLock"},
	{0x0422, ".FindAllWordForms"},
	{0x045e, ".VirusProtection"},
	{0x6200, ".Title"},
	{0x6300, ".Subject"},
	{0x6400, ".Author"},
	{0x6500, ".Keywords"},
	{0x6600, ".Comments"},
	{0xcb00, ".Format"},
	{0x0000, NULL},
    };

    for (i = 0; mac_token[i].token != 0x0000; i++) {
	if (token == mac_token[i].token) {
	    printf ("%s", mac_token[i].str);
	    return;
	}
    }
    printf ("[#73(0x%x)]", token);
    return;
}

static void print_hex_buff (unsigned char *start, unsigned char *end, int hex_output)
{
    if (!hex_output) {
	return;
    }
    printf ("[clam hex:");
    while (start < end) {
	printf (" %.2x", *start);
	start++;
    }
    printf ("]\n");
}

#ifdef __GNUC__
static void wm_decode_macro (unsigned char *buff, uint32_t len, int hex_output) __attribute__((unused));
#endif
static void wm_decode_macro (unsigned char *buff, uint32_t len, int hex_output)
{
    uint32_t i;
    uint8_t s_length, j;
    uint16_t w_length, int_val;
    unsigned char *tmp_buff, *tmp_name, *line_start;

    i = 2;
    line_start = buff;
    while (i < len) {
	switch (buff[i]) {
	case 0x65:
	    s_length = (uint8_t) buff[i + 1];
	    tmp_buff = (unsigned char *) malloc (s_length + 1);
	    strncpy ((char *) tmp_buff, (char *) (buff + i + 2), s_length);
	    tmp_buff[s_length] = '\0';
	    print_hex_buff (line_start, buff + i + 2 + s_length, hex_output);
	    printf ("\n%s", tmp_buff);
	    free (tmp_buff);
	    i += 2 + s_length;
	    line_start = buff + i;
	    break;
	case 0x69:
	    s_length = (uint8_t) buff[i + 1];
	    tmp_buff = (unsigned char *) malloc (s_length + 1);
	    strncpy ((char *) tmp_buff, (char *) (buff + i + 2), s_length);
	    tmp_buff[s_length] = '\0';
	    printf (" %s", tmp_buff);
	    free (tmp_buff);
	    i += 2 + s_length;
	    break;
	case 0x6a:
	    s_length = (uint8_t) buff[i + 1];
	    tmp_buff = (unsigned char *) malloc (s_length + 1);
	    strncpy ((char *) tmp_buff, (char *) (buff + i + 2), s_length);
	    tmp_buff[s_length] = '\0';
	    printf (" \"%s\"", tmp_buff);
	    free (tmp_buff);
	    i += 2 + s_length;
	    break;
	case 0x6b:
	    s_length = (uint8_t) buff[i + 1];
	    tmp_buff = (unsigned char *) malloc (s_length + 1);
	    strncpy ((char *) tmp_buff, (char *) (buff + i + 2), s_length);
	    tmp_buff[s_length] = '\0';
	    printf (" '%s", tmp_buff);
	    free (tmp_buff);
	    i += 2 + s_length;
	    break;
	case 0x6d:
	    s_length = (uint8_t) buff[i + 1];
	    tmp_buff = (unsigned char *) malloc (s_length + 1);
	    strncpy ((char *) tmp_buff, (char *) (buff + i + 2), s_length);
	    tmp_buff[s_length] = '\0';
	    printf (" %s", tmp_buff);
	    free (tmp_buff);
	    i += 2 + s_length;
	    break;
	case 0x70:
	    s_length = (uint8_t) buff[i + 1];
	    tmp_buff = (unsigned char *) malloc (s_length + 1);
	    strncpy ((char *) tmp_buff, (char *) (buff + i + 2), s_length);
	    tmp_buff[s_length] = '\0';
	    printf ("REM%s", tmp_buff);
	    free (tmp_buff);
	    i += 2 + s_length;
	    break;
	case 0x76:
	    s_length = (uint8_t) buff[i + 1];
	    tmp_buff = (unsigned char *) malloc (s_length + 1);
	    strncpy ((char *) tmp_buff, (char *) (buff + i + 2), s_length);
	    tmp_buff[s_length] = '\0';
	    printf (" .%s", tmp_buff);
	    free (tmp_buff);
	    i += 2 + s_length;
	    break;
	case 0x77:
	    s_length = (uint8_t) buff[i + 1];
	    tmp_buff = (unsigned char *) malloc (s_length + 1);
	    strncpy ((char *) tmp_buff, (char *) (buff + i + 2), s_length);
	    tmp_buff[s_length] = '\0';
	    printf ("%s", tmp_buff);
	    free (tmp_buff);
	    i += 2 + s_length;
	    break;
	case 0x79:		/* unicode "string" */
	    w_length = (uint16_t) (buff[i + 2] << 8) + buff[i + 1];
	    tmp_buff = (unsigned char *) malloc ((w_length * 2) + 1);
	    memcpy (tmp_buff, buff + i + 3, w_length * 2);
	    tmp_name = (unsigned char *) get_unicode_name ((char *) tmp_buff, w_length * 2);
	    free (tmp_buff);
	    printf ("\"%s\"", tmp_name);
	    free (tmp_name);
	    i += 3 + (w_length * 2);
	    break;

	case 0x7c:		/* unicode 'string */
	    s_length = (uint8_t) buff[i + 1];
	    tmp_buff = (unsigned char *) malloc ((s_length * 2) + 1);
	    memcpy (tmp_buff, buff + i + 2, s_length * 2);
	    tmp_name = (unsigned char *) get_unicode_name ((char *) tmp_buff, s_length * 2);
	    free (tmp_buff);
	    printf ("'%s", tmp_name);
	    free (tmp_name);
	    i += 2 + (s_length * 2);
	    break;

	case 0x66:
	    int_val = (uint8_t) (buff[i + 2] << 8) + buff[i + 1];
	    print_hex_buff (line_start, buff + i + 3, hex_output);
	    printf ("\n%d", int_val);
	    i += 3;
	    line_start = buff + i;
	    break;
	case 0x67:
	    w_length = (uint16_t) (buff[i + 2] << 8) + buff[i + 1];
	    output_token67 (w_length);
	    i += 3;
	    break;
	case 0x68:
	    /* 8-byte float */
	    printf ("(float)");
	    i += 9;
	    break;
	case 0x6c:
	    int_val = (uint16_t) (buff[i + 2] << 8) + buff[i + 1];
	    printf (" %d", int_val);
	    i += 3;
	    break;
	case 0x6e:
	    s_length = (uint8_t) buff[i + 1];
	    for (j = 0; j < s_length; j++) {
		printf (" ");
	    }
	    i += 2;
	    break;
	case 0x6f:
	    s_length = (uint8_t) buff[i + 1];
	    for (j = 0; j < s_length; j++) {
		printf ("\t");
	    }
	    i += 2;
	    break;
	case 0x73:
	    w_length = (uint16_t) (buff[i + 2] << 8) + buff[i + 1];
	    output_token73 (w_length);
	    i += 3;
	    break;
	case 0x64:
	    print_hex_buff (line_start, buff + i + 1, hex_output);
	    printf ("\n");
	    i++;
	    line_start = buff + i;
	    break;
	default:
	    output_token (buff[i]);
	    i++;
	    break;
	}
    }
    print_hex_buff (line_start, buff + i, hex_output);
}

static int sigtool_scandir (const char *dirname, int hex_output)
{
    DIR *dd;
    struct dirent *dent;
    STATBUF statbuf;
    char *fname;
    const char *tmpdir;
    char *dir;
    int ret = CL_CLEAN, desc;
    cli_ctx *ctx;

    fname = NULL;
    if ((dd = opendir (dirname)) != NULL) {
	while ((dent = readdir (dd))) {
	    if (dent->d_ino) {
		if (strcmp (dent->d_name, ".") && strcmp (dent->d_name, "..")) {
		    /* build the full name */
		    fname = (char *) cli_calloc (strlen (dirname) + strlen (dent->d_name) + 2, sizeof (char));
		    if(!fname){
		        closedir(dd);
		        return -1;	    
		    }	
		    sprintf (fname, "%s"PATHSEP"%s", dirname, dent->d_name);

		    /* stat the file */
		    if (LSTAT (fname, &statbuf) != -1) {
			if (S_ISDIR (statbuf.st_mode) && !S_ISLNK (statbuf.st_mode)) {
			    if (sigtool_scandir (fname, hex_output)) {
				free (fname);
				closedir (dd);
				return CL_VIRUS;
			    }
			} else {
			    if (S_ISREG (statbuf.st_mode)) {
			        struct uniq *vba = NULL;
				tmpdir = cli_gettmpdir();

				/* generate the temporary directory */
				dir = cli_gentemp (tmpdir);
				if(!dir) {
				    printf("cli_gentemp() failed\n");
				    free(fname);
				    closedir (dd);
				    return -1;
				}

				if (mkdir (dir, 0700)) {
				    printf ("Can't create temporary directory %s\n", dir);
				    free(fname);
				    closedir (dd);
				    free(dir);
				    return CL_ETMPDIR;
				}

				if ((desc = open (fname, O_RDONLY|O_BINARY)) == -1) {
				    printf ("Can't open file %s\n", fname);
				    free(fname);
				    closedir (dd);
				    free(dir);
				    return 1;
				}

				if(!(ctx = convenience_ctx(desc))) {
				    free(fname);	
				    close(desc);
				    closedir(dd);
				    free(dir);
				    return 1;
				}
				if ((ret = cli_ole2_extract (dir, ctx, &vba))) {
				    printf ("ERROR %s\n", cl_strerror (ret));
				    destroy_ctx(desc, ctx);
				    cli_rmdirs (dir);
				    free (dir);
				    closedir (dd);
				    free(fname);
				    return ret;
				}

				if(vba)
				    sigtool_vba_scandir (dir, hex_output, vba);
				destroy_ctx(desc, ctx);
				cli_rmdirs (dir);
				free (dir);
			    }
			}

		    }
		    free (fname);
		}
	    }
	}
    } else {
	logg("!Can't open directory %s.\n", dirname);
	return CL_EOPEN;
    }

    closedir (dd);
    return 0;
}

int sigtool_vba_scandir (const char *dirname, int hex_output, struct uniq *U)
{
    cl_error_t status = CL_CLEAN;
    cl_error_t ret;
    int i, fd, data_len;
    vba_project_t *vba_project = NULL;
    DIR *dd;
    struct dirent *dent;
    STATBUF statbuf;
    char *fullname, vbaname[1024], *hash;
    unsigned char *data;
    uint32_t hashcnt;
    unsigned int j;

    if (CL_SUCCESS != (ret = uniq_get(U, "_vba_project", 12, NULL, &hashcnt))) {
        logg("!ScanDir -> uniq_get('_vba_project') failed.\n");
        return ret;
    }

    while (hashcnt) {
        if (!(vba_project = (vba_project_t *)cli_vba_readdir(dirname, U, hashcnt))) {
            hashcnt--;
            continue;
        }

	for(i = 0; i < vba_project->count; i++) {
	    for(j = 0; j < vba_project->colls[i]; j++) {
		snprintf(vbaname, 1024, "%s"PATHSEP"%s_%u", vba_project->dir, vba_project->name[i], j);
		vbaname[sizeof(vbaname)-1] = '\0';

		fd = open(vbaname, O_RDONLY|O_BINARY);
		if(fd == -1) continue;
		data = (unsigned char *)cli_vba_inflate(fd, vba_project->offset[i], &data_len);
		close(fd);

		if(data) {
		    data = (unsigned char *) realloc (data, data_len + 1);
		    data[data_len]='\0';
		    printf ("-------------- start of code ------------------\n%s\n-------------- end of code ------------------\n", data);
		    free(data);
		}
	    }
	}

        cli_free_vba_project(vba_project);
        vba_project = NULL;

        hashcnt--;
    }

    if (CL_SUCCESS != (ret = uniq_get(U, "powerpoint document", 19, &hash, &hashcnt))) {
        logg("!ScanDir -> uniq_get('powerpoint document') failed.\n");
        return ret;
    }

    while (hashcnt) {
	    snprintf(vbaname, 1024, "%s"PATHSEP"%s_%u", dirname, hash, hashcnt);
	    vbaname[sizeof(vbaname)-1] = '\0';

	    fd = open(vbaname, O_RDONLY|O_BINARY);
        if (fd == -1) {
            hashcnt--;
            continue;
        }
	    if ((fullname = cli_ppt_vba_read(fd, NULL))) {
	      sigtool_scandir(fullname, hex_output);
	      cli_rmdirs(fullname);
	      free(fullname);
	    }
	    close(fd);
        hashcnt--;
	}

    if (CL_SUCCESS != (ret = uniq_get(U, "worddocument", 12, &hash, &hashcnt))) {
        logg("!ScanDir -> uniq_get('worddocument') failed.\n");
        return ret;
    }

    while (hashcnt) {
	    snprintf(vbaname, sizeof(vbaname), "%s"PATHSEP"%s_%u", dirname, hash, hashcnt);
	    vbaname[sizeof(vbaname)-1] = '\0';

	    fd = open(vbaname, O_RDONLY|O_BINARY);
        if (fd == -1) {
            hashcnt--;
            continue;
        }
	    
	    if (!(vba_project = (vba_project_t *)cli_wm_readdir(fd))) {
		close(fd);
            hashcnt--;
		continue;
	    }

	    for (i = 0; i < vba_project->count; i++) {
		data_len = vba_project->length[i];
		data = (unsigned char *)cli_wm_decrypt_macro(fd, vba_project->offset[i], data_len , vba_project->key[i]);
		if(data) {
		    data = (unsigned char *) realloc (data, data_len + 1);
		    data[data_len]='\0';
		    printf ("-------------- start of code ------------------\n%s\n-------------- end of code ------------------\n", data);
		    free(data);
		}
	    }

	    close(fd);
        cli_free_vba_project(vba_project);
        vba_project = NULL;
        hashcnt--;
    }

    if ((dd = opendir (dirname)) != NULL) {
	while ((dent = readdir (dd))) {
	    if (dent->d_ino) {
		if (strcmp (dent->d_name, ".") && strcmp (dent->d_name, "..")) {
		    /* build the full name */
		    fullname = calloc (strlen (dirname) + strlen (dent->d_name) + 2, sizeof (char));
		    sprintf (fullname, "%s"PATHSEP"%s", dirname, dent->d_name);

		    /* stat the file */
		    if (LSTAT (fullname, &statbuf) != -1) {
			if (S_ISDIR (statbuf.st_mode) && !S_ISLNK (statbuf.st_mode))
			    sigtool_vba_scandir (fullname, hex_output, U); 
		    }
		    free (fullname);
		}
	    }
	}
    } else {
	logg("!ScanDir -> Can't open directory %s.\n", dirname);
	return CL_EOPEN;
    }


    closedir (dd);
    return status;
}
