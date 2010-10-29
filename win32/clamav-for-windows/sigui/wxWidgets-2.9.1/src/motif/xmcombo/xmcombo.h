/*
 * ComboBox.h - Das schon lange schmerzlich vermisste Combo-Box-
 *              Widget -- nun endlich auf fuer Motif!
 * 
 * Letzte Modifikation: 04.10.1995    Revisionsstand: 1.32a
 * 
 * (c) 1993, 1994 Harald Albrecht
 * Institut fuer Geometrie und Praktische Mathematik
 * RWTH Aachen, Germany
 * albrecht@igpm.rwth-aachen.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING for more details);
 * if not, write to the Free Software Foundation, Inc., 675 Mass Ave, 
 * Cambridge, MA 02139, USA.
 *
 */
#ifndef __ComboBoxWidget_h
#define __ComboBoxWidget_h

#include <Xm/Xm.h>

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#ifdef XmNselectionCallback
#undef XmNselectionCallback
#endif
    
#define XmNselectionCallback		"selectionCallback"
#define XmCSelectionCallback		"SelectionCallback"
#define XmNunselectionCallback		"unselectionCallback"
#define XmCUnselectionCallback		"UnselectionCallback"
#define XmNdropDownCallback		"dropDownCallback"
#define XmCDropDownCallback		"DropDownCallback"

#define XmNdropDownCursor		"dropDownCursor"
#define XmCDropDownCursor		"DropDownCursor"

/* ICH GLAUB' ES JA EINFACH NICHT! DIESE @#$!%^ BEI DER OSF HABEN
 * DOCH TATSAECHLICH VERGESSEN, DASS DIE EINTRAEGE IN DER LISTBOX
 * VIELLEICHT AUCH SORTIERT SEIN SOLLEN -- MUSS MAN DENN ALLES
 * SELBST MACHEN?!
 */
#define XmNsorted			"sorted"
#define XmCSorted			"Sorted"
#define XmNsortingCallback		"sortingCallback"
#define XmCSortingCallback		"SortingCallback"

#define XmNstaticList			"staticList"
#define XmCStaticList			"StaticList"

#define XmNsquareArrow			"squareArrow"
#define XmCSquareArrow			"SquareArrow"
#define XmNarrowSpacingOn		"arrowSpacingOn"
#define XmCArrowSpacingOn		"ArrowSpacingOn"

/*
 * Wie verhaeltsich die Liste, wenn der Focus verloren geht, sobald
 * der Mauszeiger aus dem Dialog herausbewegt wird?
 */
#define XmNpersistentDropDown		"persistentDropDown"
#define XmCPersistentDropDown		"PersistentDropDown"
#define XmNtwmHandlingOn		"twmHandlingOn"
#define XmCTwmHandlingOn		"TwmHandlingOn"
/*
 * alles fuer das Label...
 */
#define XmNshowLabel			"showLabel"
#define XmCShowLabel			"ShowLabel"
#define XmNdropDownOffset		"dropDownOffset"
#define XmCDropDownOffset		"DropDownOffset"

#define XmNlabelMarginBottom		"labelMarginBottom"
#define XmCLabelMarginBottom		"LabelMarginBottom"
#define XmNlabelMarginHeight		"labelMarginHeight"
#define XmCLabelMarginHeight		"LabelMarginHeight"
#define XmNlabelMarginLeft		"labelMarginLeft"
#define XmCLabelMarginLeft		"LabelMarginLeft"
#define XmNlabelMarginRight		"labelMarginRight"
#define XmCLabelMarginRight		"LabelMarginRight"
#define XmNlabelMarginTop		"labelMarginTop"
#define XmCLabelMarginTop		"LabelMarginTop"
#define XmNlabelMarginWidth		"labelMarginWidth"
#define XmCLabelMarginWidth		"LabelMarginWidth"

/* Callback reasons: (part. predefined)
 *
 * XmCR_SINGLE_SELECT	    user selected item in the list
 */

typedef struct {
    int      reason;	/* Grund                  */
    XEvent   *event;	/* Ausloesender Event     */
    XmString value;     /* Ausgewaehlter Eintrag  */
    int      index;	/* Index dieses Eintrages */
} XmComboBoxSelectionCallbackStruct,XmComboBoxDefaultActionCallbackStruct;

typedef struct {
    int         reason;
    XEvent      *event;
    Boolean     doit;
    Position    currInsert, newInsert;
    Position    startPos, endPos;
    XmTextBlock text;
} XmComboBoxTextVerifyCallbackStruct, *XmComboBoxTextVerifyPtr;

/* Callback reasons: new
 * 
 * XmCR_SHOW_LIST	    list is dropping down
 * XmCR_HIDE_LIST	    list is getting hidden
 * 
 * XmCR_UNSELECT	    unselecting item from list or osfDelete
 */
#define XmCR_SHOW_LIST	4200	/* ten times "42", that should   */
#define XmCR_HIDE_LIST	4201	/* explain everything of live... */
#define XmCR_UNSELECT   4202
typedef struct {
    int	     reason;	/* Grund		  */
    XEvent   *event;    /* Ausloesender Event     */
} XmComboBoxDropDownCallbackStruct, XmComboBoxUnselectionCallbackStruct;

#define XmCR_SORTING	4203
#define XmOP_INIT	1
#define XmOP_DONE	2
#define XmOP_COMPARE	3
typedef struct {
    int      reason;
    XEvent   *event;    /* IMMER NULL!! */
    int      operation;
    void     *item_internal;
    XmString item;
    int      result;
} XmComboBoxSortingCallbackStruct, *XmComboBoxSortingPtr;

/* Alle Funktionen, um auf die Liste der Combo-Box zuzugreifen.
 * Bitte immer diese Funktionen dazu benutzen und nicht direkt
 * auf das entsprechende Widget in der Combo-Box zugreifen!
 * Aus diesem Grunde sind auch nicht alle Funktionen einer Listbox
 * verfuegbar, da sich einige Funktionen mit der Verwaltung der
 * Combo-Box beissen wuerden.
 */
extern void    XmComboBoxAddItem(Widget w, XmString item, int pos);
extern void    XmComboBoxAddItems(Widget w, XmString *items, int item_count, int pos);
extern void    XmComboBoxAddItemUnselected(Widget w, XmString item, int pos);
extern void    XmComboBoxDeleteItem(Widget w, XmString item);
extern void    XmComboBoxDeleteItems(Widget w, XmString *items, int item_count);
extern void    XmComboBoxDeletePos(Widget w, int pos);
extern void    XmComboBoxDeleteItemsPos(Widget w, int item_count, int pos);
extern void    XmComboBoxDeleteAllItems(Widget w);
extern void    XmComboBoxReplaceItems(Widget w, XmString *old_items, int item_count, XmString *new_items);
extern void    XmComboBoxReplaceItemsPos(Widget w, XmString *new_items, int item_count, int position);
extern Boolean XmComboBoxItemExists(Widget w, XmString item);
extern int     XmComboBoxItemPos(Widget w, XmString item);
extern Boolean XmComboBoxGetMatchPos(Widget w, XmString item, int **pos_list, int *pos_count);
extern void    XmComboBoxSelectPos(Widget w, int pos, Boolean notify);
extern void    XmComboBoxSelectItem(Widget w, XmString item, Boolean notify);
/* Etwas anders als bei der Listbox, da es sowieso nur einen ausge-
 * waehlten Eintrag in der Listbox geben kann!
 * Liefert Index des ausgewaehlten Eintrages oder 0.
 */
extern int     XmComboBoxGetSelectedPos(Widget w);
extern void    XmComboBoxClearItemSelection(Widget w);
/*
 * Nun alle Funktionen, die auf das Eingabefeld zugreifen...
 * Auch hier gilt wieder, es gibt 'was auf die Finger, wenn jemand
 * versucht, direkt auf das Eingabefeld direkt zuzugreifen!
 */
extern void    XmComboBoxClearSelection(Widget w, Time time);
extern Boolean XmComboBoxCopy(Widget w, Time time);
extern Boolean XmComboBoxCut(Widget w, Time time);
extern XmTextPosition XmComboBoxGetInsertionPosition(Widget w);
extern XmTextPosition XmComboBoxGetLastPosition(Widget w);
extern int     XmComboBoxGetMaxLength(Widget w);
extern char *  XmComboBoxGetSelection(Widget w);
extern Boolean XmComboBoxGetSelectionPosition(Widget w, XmTextPosition *left, 
                                               XmTextPosition *right);
extern char *  XmComboBoxGetString(Widget w);
extern void    XmComboBoxInsert(Widget w, XmTextPosition position, char *value);
extern Boolean XmComboBoxPaste(Widget w);
extern Boolean XmComboBoxRemove(Widget w);
extern void    XmComboBoxReplace(Widget w, XmTextPosition from_pos, 
                                 XmTextPosition to_pos, char *value);
extern void    XmComboBoxSetAddMode(Widget w, Boolean state);
extern void    XmComboBoxSetHighlight(Widget w, XmTextPosition left, 
                                      XmTextPosition right, XmHighlightMode mode);
extern void    XmComboBoxSetInsertionPosition(Widget w, XmTextPosition position);
extern void    XmComboBoxSetMaxLength(Widget w, int max_length);
extern void    XmComboBoxSetSelection(Widget w, XmTextPosition first, 
                                      XmTextPosition last, Time time);
extern void    XmComboBoxSetString(Widget w, char *value);
extern void    XmComboBoxShowPosition(Widget w, XmTextPosition position);

extern WidgetClass xmComboBoxWidgetClass; /* Die Klasse hoechstselbst */

#ifndef XmIsComboBox
#define XmIsComboBox(w)	    XtIsSubclass(w, xmComboBoxWidgetClass)
#endif /* XmIsComboBox */

typedef struct _XmComboBoxClassRec *XmComboBoxWidgetClass;
typedef struct _XmComboBoxRec      *XmComboBoxWidget;

extern Widget XmCreateComboBox(Widget parent, String name, ArgList arglist,
                               Cardinal argcount);

/* PLEASE do not use this functions if you really not need to do so !!! */
extern Widget XmComboBoxGetEditWidget(Widget w);
extern Widget XmComboBoxGetListWidget(Widget w);
extern Widget XmComboBoxGetLabelWidget(Widget w);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __ComboBoxWidget_h */
/* Ende von ComboBox.h */
