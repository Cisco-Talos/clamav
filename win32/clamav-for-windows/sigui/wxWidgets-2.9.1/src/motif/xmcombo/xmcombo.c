/*
 * ComboBox.c - Das schon lange schmerzlich vermisste Combo-Box-
 *              Widget -- nun endlich auf fuer Motif!
 * 
 * Version 1.32a -- 04.10.95
 *
 * Letzte Modifikation:
 * 04.10.1995    Layoutfehler behoben, der bei angezeigter horizontaler Liste
 *               dazu fuehrt, dass das Listenfeld schrumpft. Daneben wird
 *               jetzt auch der Fall beruecksichtigt, dass das Listenfeld am
 *               unteren Bildschirmrand abgeschnitten wuerde. In diesem Fall
 *               erscheint das Listenfeld oberhalb des Eingabefeldes.
 * 20.03.1995    XmNscrollbarDisplayPolicy,... koennen nun immer vom Pro-
 *               grammierer gesetzt werden, statische Liste hin und her.
 * 21.10.1994    Fehler in SetValues behoben, der auftritt, wenn man versucht,
 *               XmNitems und XmNitemCount zu setzen.
 * 01.10.1994    Externe Sortierung wird nun unterstuetzt sowie seitenweises
 *		 Rollen in der Liste mittels PgUp und PgDn.
 * 25.09.1994    Unterstuetzung fuer XmNautomaticSelection implementiert.
 *		 Damit wird die Sache noch ein bischen runder in der Bedienung.
 *		 Des weiteren sind etliche Callbacks neu hinzugekommen.
 * 04.09.1994    Erweiterungen fuer XmSINGLE_SELECT eingebaut. Ausserdem
 *		 kann die Liste jetzt auch statisch unterhalb des Eingabe-
 *		 felds erscheinen. Damit sind wir nun noch kompatibler ge-
 *		 worden -- fragt sich nur, zu was?!
 * 29.08.1994    Alle Mirror-Ressourcen tauchen nun auch in der Ressourcen-
 *		 liste der ComboBox-Klasse auf. Allerdings stehen keine
 *		 sinnvollen Werte fuer die Initialisierung 'drin. Weiterhin
 *		 den GeometryManager so veraendert, dass ab sofort das
 *		 Label in der Breite wachsen oder schrumpfen darf.
 * 07.06.1994    XmNmnemonic und XmNmnemonicCharSet implementiert.
 * 29.05.1994    XmNsensitive angepasst. XmNcursorPositionVisible ist nun
 *               False, falls die ComboBox nicht editierbar ist.
 * 07.05.1994    Drag'n'Drop funktioniert endlich!!! Zudem Anpassung an
 *               den fvwm ausgefuehrt ('st vom Focus-Verhalten ja ein halber
 *               twm). Hach', so'ne Linux-Box mit Motif 1.2 macht doch
 *               einfach Spass... vor allem geht hier so richtig die Post ab.
 *               Das kann man ja von M$ Windoze (Windoze for Mondays) nicht
 *               behaupten!
 * 14.04.1994    Ein paar Speicherlecks korrigiert.
 * 21.02.1994    Die Resourcen XmNitems und XmNitemCount lassen sich nun 
 *               auch von einer Resourcendatei aus initialisieren. ACHTUNG: 
 *		 diese beiden Resourcen mussen immer beide beim Aufruf von 
 *		 XtSetValues zugleich angegeben werden, ansonsten werden
 *               diese Angaben ignoriert.
 * 03.02.1994    Convenience-Funktionen auf Vordermann gebracht und noch
 *		 einen Callback eingebaut, der immer dann aufgerufen wird, 
 *		 wenn die List angezeigt oder wieder versteckt wird.
 * 01.02.1994    Motif 1.2-fest!!! Das wird aber heute abend gefeiert!!
 *               Endlich EIN Alptraum weniger! Naja, Drag'n'Drop bleibt
 *		 noch zu loesen. Spaeter...
 * 31.01.1994    VAX-fest (mit Hilfe von Vincenct Li)
 *               owlm sollte man abschaffen! Aber es scheint so, als ob
 *               ich jetzt doch noch das FocusOut-Problem geknackt habe.
 *               Ebenso die OSF...mit viel Arbeit habe ich nun auch noch
 *               eine anstaendige Initialisierung der Fontliste des Label-
 *               Kinds erreicht.
 * 12.01.1994	 Revisionsstand: 1.10a
 *               nun wirklich voll ANSI-faehiger C-Code
 *               Pixmaps werden ggf. aufgeraeumt; Druckrichtung
 *               wird vom Vater erfragt und an das Label weiter-
 *               gegeben.
 *               ESC-Behandlung implementiert.
 *               Spiegel-Ressourcen-Initialisierung aus Ressourcen-Daten-
 *               bank implementiert.
 *               Weitergabe von neu gesetzten Farben an die Kinder
 *               implementiert.
 *               Combo-Box kann jetzt wahlweise auch links neben dem
 *               Eingabefeld ein Label anzeigen.
 * 09.12.1993    Revisionsstand: 1.00
 *               erste oeffentlich zugaengliche Version der Combo-Box
 * 
 * (c) 1993, 1994, 1995 Harald Albrecht
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
#ifdef __VMS
/* vms_x_fix.h should be included before any of the X11/Motif headers */
#include <wx/vms_x_fix.h>
#undef XtDisplay
#undef XtScreen
#undef XtWindow
#undef XtIsRealized
#undef XtParent
#undef XtClass
#endif

/* get XmVersion definition */
#include <Xm/Xm.h>

#if (XmVersion < 2000)

#include <X11/IntrinsicP.h>
#include <X11/StringDefs.h>
#include <X11/cursorfont.h>
#include <X11/Shell.h>
#ifdef VMS /* Huch, wo gibt's denn noch sowas ... ?! */
           /* Bitte keine Mail bzgl. dieser Bemerkung schicken...
	    * Ich weiss, das ist ein Vorurteil...aber es gibt
	    * ja auch wahre Vorurteile....
	    */
#include <Xmu/Converters.h>
#else
#include <X11/Xmu/Converters.h>
#endif
#include <Xm/ArrowB.h>
#include <Xm/TextF.h>
#include <Xm/List.h>
#include <Xm/LabelP.h>

#include <string.h>
#include <ctype.h> /* define toupper */
#include "combop.h"

#include <stdio.h>

/* --- Systemspezifische Definitionen */
#if defined(VMS)
#define strcasecmp(s1, s2) strcmp(s1, s2)
#elif defined(__EMX__)
#define strcasecmp stricmp
#endif

/* --- sonstiger Quark */
/* #ifdef DEBUG */
#if 0
#define LOG(p1)          fprintf(stderr, p1);
#define LOG2(p1, p2)     fprintf(stderr, p1, p2);
#define LOG3(p1, p2, p3) fprintf(stderr, p1, p2, p3);
#else
#define LOG(p1)
#define LOG2(p1, p2)
#define LOG3(p1, p2, p3)
#endif

/* ---------------------------------------------------------------------------
 * Resourcen-Liste...
 * Hier werden diejenigen Resourcen definiert, die von "aussen" - also  fuer
 * den Programmierer oder Anwender - benutzbar und veraenderbar sind.
 * 
 * Der Aufbau der einzelnen Eintraege ist immer wieder gleich:
 * Resourcen-Name	XmN... oder XtN
 * Resourcen-Klasse     XmC... oder XtC
 * Resourcen-Type       XmR... oder XtR (Datentyp der Variable in der
 *                      struct der jeweiligen Widgetinstanz)
 * Resourcen-Groesse	aktuelle Groesse dieses Datentyps
 * Resourcen-Offset     Lage der Variable innerhalb der struct der
 *			Widgetinstanz
 * Defaultwert-Type     Typ des Defaultwertes
 * Defaultwert		(normalerweise) Zeiger auf den Defaultwert
 */
#define offset(field) XtOffsetOf(XmComboBoxRec, field)
static XtResource resources[] = {
    { /* Eingabefeld kann veraendert werden, oder aber es sind nur
       * die Vorgaben aus der Liste auswaehlbar.
       */
	XmNeditable, XmCEditable, XmRBoolean, sizeof(Boolean), 
	offset(combobox.Editable), XmRString, "False"
    }, 
    { /* Liste wird automatisch sortiert -- wie konnten die bei
       * der OSF denn SOETWAS nur vergessen ??
       */
	XmNsorted, XmCSorted, XmRBoolean, sizeof(Boolean),
	offset(combobox.Sorted), XmRString, "False"
    }, 
    { /* externe Sortierreihenfolge */
	XmNsortingCallback, XmCSortingCallback, XmRCallback, 
	sizeof(XtCallbackList), 
	offset(combobox.SortingCBL), XmRCallback, NULL
    }, 
    { /* Anzahl auf einmal sichtbarer Eintraege in der Liste (ent-
       * spricht damit der Listenhoehe.
       */
	XmNvisibleItemCount, XmCVisibleItemCount, XmRInt, sizeof(int), 
	offset(combobox.VisibleItemCount), XmRImmediate, (caddr_t) 8
    }, 
    { /* Fuer das Eingabefeld sowie die Liste verwandte Fonts */
	XmNfontList, XmCFontList, XmRFontList, sizeof(XmFontList), 
	offset(combobox.Font), XmRImmediate, NULL
    }, 
    { /* Rueckruf bei Anwahl */
	XmNselectionCallback, XmCSelectionCallback, XmRCallback, 
	sizeof(XtCallbackList), 
	offset(combobox.SelectionCBL), XmRCallback, NULL
    }, 
    { /* Gegenteil zum vorherigen Callback! */
	XmNunselectionCallback, XmCUnselectionCallback, XmRCallback, 
	sizeof(XtCallbackList), 
	offset(combobox.UnselectionCBL), XmRCallback, NULL
    }, 
    { /* Doppelklick in der Liste */
	XmNdefaultActionCallback, XmCCallback, XmRCallback, 
	sizeof(XtCallbackList), 
	offset(combobox.DefaultActionCBL), XmRCallback, NULL
    }, 
    { /* Rueckruf bei Liste ausklappen/verstecken */
	XmNdropDownCallback, XmCDropDownCallback, XmRCallback, 
	sizeof(XtCallbackList), 
	offset(combobox.DropDownCBL), XmRCallback, NULL
    }, 
    { /* Eingabe abchecken... */
	XmNmodifyVerifyCallback, XmCCallback, XmRCallback, 
	sizeof(XtCallbackList), 
	offset(combobox.ModifyVerifyCBL), XmRCallback, NULL
    }, 
    {
	XmNvalueChangedCallback, XmCCallback, XmRCallback, 
	sizeof(XtCallbackList), 
	offset(combobox.ValueChangedCBL), XmRCallback, NULL
    }, 
    {
	XmNactivateCallback, XmCCallback, XmRCallback, 
	sizeof(XtCallbackList), 
	offset(combobox.ActivateCBL), XmRCallback, NULL
    }, 
    {
	XmNmotionVerifyCallback, XmCCallback, XmRCallback, 
	sizeof(XtCallbackList), 
	offset(combobox.MotionVerifyCBL), XmRCallback, NULL
    }, 
    { /* Verhalten der ausgeklappten Liste bei Focus-Out */
	XmNpersistentDropDown, XmCPersistentDropDown, XmRBoolean, 
	sizeof(Boolean), 
	offset(combobox.Persistent), XmRString, "False"
    }, 
    { /* Wie verhaelt sich der Window-Manager? */
	XmNtwmHandlingOn, XmCTwmHandlingOn, XmRBoolean, sizeof(Boolean), 
	offset(combobox.TwmHandlingOn), XmRString, "False"
    }, 
    { /* Label anzeigen oder nicht? */
	XmNshowLabel, XmCShowLabel, XmRBoolean, sizeof(Boolean), 
	offset(combobox.ShowLabel), XmRString, "False"
    }, 
    { /* Abstand zw. linkem Rand Eingabefeld und linkem Rand Liste */
	XmNdropDownOffset, XmCDropDownOffset, XmRPosition, 
	sizeof(Position), offset(combobox.DropDownOffset), 
	XmRImmediate, (caddr_t) -1
    }, 
    { /* Neue Voreinstellung bzgl. des Randes */
	XmNborderWidth, XmCBorderWidth, XmRDimension, sizeof(Dimension), 
	offset(core.border_width), XmRImmediate, (caddr_t) 0
    },
    { /* welcher Cursor soll in der Dropdown-Liste benutzt werden? */
	XmNdropDownCursor, XmCDropDownCursor, XmRCursor, sizeof(Cursor),
	offset(combobox.ArrowCursor), XmRString, "center_ptr"
    }, 
    { /* wie lassen sich Eintraege auswaehlen? */
	XmNselectionPolicy, XmCSelectionPolicy, XmRSelectionPolicy, sizeof(unsigned char), 
	offset(combobox.SelectionPolicy), XmRImmediate, (caddr_t) XmBROWSE_SELECT
    }, 
    { /* Wann werden die Callbacks aufgerufen? */
	XmNautomaticSelection, XmCAutomaticSelection, XmRBoolean, sizeof(Boolean), 
	offset(combobox.AutomaticSelection), XmRString, "False"
    }, 
    { /* erscheint die Liste staendig? */
	XmNstaticList, XmCStaticList, XmRBoolean, sizeof(Boolean), 
	offset(combobox.StaticList), XmRString, "False"
    }, 
    {
    	XmNscrollBarDisplayPolicy, XmCScrollBarDisplayPolicy, XmRScrollBarDisplayPolicy, sizeof(unsigned char),
    	offset(combobox.ScrollBarDisplayPolicy), XmRImmediate, (caddr_t) XmAS_NEEDED
    },
    {
        XmNlistSizePolicy, XmCListSizePolicy, XmRListSizePolicy, sizeof(unsigned char),
        offset(combobox.ListSizePolicy), XmRImmediate, (caddr_t) XmVARIABLE
    },
    {
        XmNsquareArrow, XmCSquareArrow, XmRBoolean, sizeof(Boolean),
        offset(combobox.SquareArrow), XmRString, "False"
    },
    {
        XmNarrowSpacingOn, XmCArrowSpacingOn, XmRBoolean, sizeof(Boolean),
        offset(combobox.ArrowSpacingOn), XmRString, "True"
    },
#ifndef DONT_LOOK_IN_THE_MIRROR
    /* Mirror-Ressourcen, Adressen sind ungueltig!!!! */
    {
	XmNalignment, XmCAlignment, XmRAlignment, sizeof(unsigned char), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNblinkRate, XmCBlinkRate, XmRInt, sizeof(int), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNcolumns, XmCColumns, XmRShort, sizeof(short), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNcursorPosition, XmCCursorPosition, XmRTextPosition, sizeof(XmTextPosition),
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNitemCount, XmCItemCount, XmRInt, sizeof(int), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNitems, XmCItems, XmRXmStringTable, sizeof(XmStringTable), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelFontList, XmCLabelFontList, XmRFontList, sizeof(XmFontList), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelInsensitivePixmap, XmCLabelInsensitivePixmap, XmRPixmap, sizeof(Pixmap), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelMarginBottom, XmCLabelMarginBottom, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelMarginHeight, XmCLabelMarginHeight, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelMarginLeft, XmCLabelMarginLeft, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelMarginRight, XmCLabelMarginRight, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelMarginTop, XmCLabelMarginTop, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelMarginWidth, XmCLabelMarginWidth, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelPixmap, XmCLabelPixmap, XmRPixmap, sizeof(Pixmap), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelString, XmCLabelString, XmRString, sizeof(XmString), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlabelType, XmCLabelType, XmRLabelType, sizeof(unsigned char), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlistMarginHeight, XmCListMarginHeight, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlistMarginWidth, XmCListMarginWidth, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNlistSpacing, XmCListSpacing, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNmarginHeight, XmCMarginHeight, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNmarginWidth, XmCMarginWidth, XmRDimension, sizeof(Dimension), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNmaxLength, XmCMaxLength, XmRInt, sizeof(int), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNselectThreshold, XmCSelectThreshold, XmRInt, sizeof(int), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNstringDirection, XmCStringDirection, XmRStringDirection, sizeof(XmStringDirection), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNtopItemPosition, XmCTopItemPosition, XmRInt, sizeof(int), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNvalue, XmCValue, XmRString, sizeof(String), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
    {
	XmNvalue, XmCValue, XmRInt, sizeof(int), 
	offset(combobox.Dummy), XmRImmediate, (caddr_t) 0
    }, 
#endif
}; /* resources[] */

/* ---------------------------------------------------------------------------
 * Funktions-Prototypen fuer die 'Methoden' des ComboBox-Widgets. Diese
 * 'Methoden' werden vom Xt-Toolkit aufgerufen und sorgen dafuer, dass eine
 * ComboBox sich wie ein anstaendiges Widget verhaelt.
 */
static void             Initialize     (Widget, XmComboBoxWidget, ArgList, 
			                Cardinal *);
static void             Destroy        (XmComboBoxWidget);
static void             Resize         (XmComboBoxWidget);
static Boolean          SetValues      (XmComboBoxWidget, XmComboBoxWidget, 
                                        XmComboBoxWidget, ArgList, Cardinal *);
static void             GetValuesAlmost(XmComboBoxWidget, ArgList, Cardinal *);
static XtGeometryResult QueryGeometry  (XmComboBoxWidget, XtWidgetGeometry *, 
			                XtWidgetGeometry *); 
static XtGeometryResult GeometryManager(Widget, XtWidgetGeometry *, 
                                        XtWidgetGeometry *);
static void		ClassInit      ();
static void             Realize        (XmComboBoxWidget, Mask *, 
                                        XSetWindowAttributes *);
/* ---------------------------------------------------------------------------
 * diverse restliche Prototypen... naja, hier halt etwas mager! Hierbei
 */
static void ShowHideDropDownList       (XmComboBoxWidget w, XEvent *event, 
                                        Boolean Show);
static void ShellCallback              (Widget w, XtPointer cbw, 
                                        XEvent *event, Boolean *ContDispatch);
static void DoLayout                   (XmComboBoxWidget w);
/* --------------------------------------------------------------------
 * Klassen-Definition
 */
XmComboBoxClassRec xmComboBoxClassRec = {
    { /*** core-Klasse ***/
    /* superclass		    */	(WidgetClass) &xmManagerClassRec, 
    /* class_name		    */	"XmComboBox",
    /* widget_size		    */	sizeof(XmComboBoxRec),
    /* class_initialize   	    */	(XtProc) ClassInit,
    /* class_part_initialize	    */	NULL,
    /* class_inited       	    */	False, /* IMMER mit FALSE initialisieren !! */
    /* initialize	  	    */	(XtInitProc) Initialize,
    /* initialize_hook		    */	NULL,
    /* realize		  	    */	(XtRealizeProc) Realize,
    /* actions		  	    */	NULL,
    /* num_actions	  	    */	0,
    /* resources	  	    */	resources,
    /* num_resources	  	    */	XtNumber(resources),
    /* xrm_class	  	    */	NULLQUARK,
    /* compress_motion	  	    */	True,
    /* compress_exposure  	    */	XtExposeCompressMultiple,
    /* compress_enterleave	    */	True,
    /* visible_interest	  	    */	False,
    /* destroy		  	    */	(XtWidgetProc) Destroy,
    /* resize		  	    */	(XtWidgetProc) Resize,
    /* expose		  	    */	NULL,
    /* set_values	  	    */	(XtSetValuesFunc) SetValues,
    /* set_values_hook		    */	NULL,
    /* set_values_almost	    */	XtInheritSetValuesAlmost,
    /* get_values_hook		    */	(XtArgsProc) GetValuesAlmost,
    /* accept_focus	 	    */	NULL,
    /* version			    */	XtVersion,
    /* callback_private   	    */	NULL,
    /* tm_table		   	    */	XtInheritTranslations, /* Changed from NULL: Bug #406153 */
    /* query_geometry		    */	(XtGeometryHandler) QueryGeometry,
    /* display_accelerator	    */	XtInheritDisplayAccelerator,
    /* extension          	    */	NULL
    }, 
    { /*** composite-Klasse ***/
    /* geometry_manager		    */	(XtGeometryHandler) GeometryManager,
    /* change_managed		    */	XtInheritChangeManaged,
    /* insert_child		    */	XtInheritInsertChild,
    /* delete_child		    */	XtInheritDeleteChild,
    /* extension		    */	NULL
    }, 
    { /*** constraint-Klasse ***/
    /* resources		    */	NULL,
    /* num_resources		    */	0,
    /* constraint_size		    */	sizeof(XmManagerConstraintPart),
    /* initialize		    */	NULL,
    /* destroy			    */	NULL,
    /* set_values		    */	NULL,
    /* extension		    */	NULL
    }, 
    { /*** xmManager-Klasse ***/
    /* translations                 */	XtInheritTranslations,
    /* syn_resources                */	NULL,
    /* num_syn_resources            */	0,
    /* syn_constraint_resources     */	NULL,
    /* num_syn_constraint_resources */	0,
    /* parent_process		    */	XmInheritParentProcess,
    /* extension		    */	NULL
    }, 
    { /*** combobox-Klasse ***/
    /*				    */	0
    }
}; /* xmComboBoxClassRec */
WidgetClass xmComboBoxWidgetClass = (WidgetClass) &xmComboBoxClassRec;

/* --------------------------------------------------------------------
 * --------------------------------------------------------------------
 * Translation-Tabelle (hier allerdings fuer das Eingabefeld!)
 * Tjaja....mit der Reihenfolge von Translations ist das schon so eine
 * ziemlich boese Sache!
 */
static char newEditTranslations[] =
    "Alt<Key>osfDown:	    ComboBox-Manager(show-hide-list)	\n\
     Meta<Key>osfDown:	    ComboBox-Manager(show-hide-list)	\n\
     Alt<Key>osfUp:	    ComboBox-Manager(hide-list)		\n\
     Meta<Key>osfUp:	    ComboBox-Manager(hide-list)		\n\
     <Key>osfUp:	    ComboBox-Manager(up)		\n\
     <Key>osfDown:	    ComboBox-Manager(down)		\n\
     <Key>osfPageUp:	    ComboBox-Manager(page-up)		\n\
     <Key>osfPageDown:	    ComboBox-Manager(page-down)		\n\
     <Key>osfCancel:	    ComboBox-Manager(cancel)		\n\
     <Key>Return:	    ComboBox-Manager(activate) activate()"
    ;
/* speziell bei der nicht editierbaren Combo-Box sind noch einige
 * andere Tasten belegt, die sonst dem Eingabefeld alleine gehoeren.
 * Die dazugehoerigen neuen Translations befinden sich in dieser
 * zusaetzlichen Tabelle, das Anhaengsel ...NE ist dabei die Ab-
 * kuerzung fuer "non editable".
 */
static char newEditTranslationsNE[] = 
    "<Key>osfDelete:	    ComboBox-Manager(wipe-out)		\n\
     <Key>osfBeginLine:	    ComboBox-Manager(top)		\n\
     <Key>osfEndLine:	    ComboBox-Manager(bottom)		  "
    ;
/* Momentan gibt es noch Aerger mit dem Drag'n'Drop-Mechanismus
 * von Motif 1.2. Legen wir ihn deshalb erst einmal still, solange
 * bis ich weiss, warum, und eine Loesung parat habe. NEU: Nur wenn
 * Sie mit einer libXm geschlagen sind, die partout nicht funktionieren
 * will, muessen Sie Drag'n'Drop stillegen, ansonsten klappts doch!
 */
#ifdef NODRAGNDROP
static char newListTranslations[] =
    "<Btn2Down>:	    ComboBox-Manager(no-operation)	";
#endif
static char newListTranslationsE[] =
    "<Key>osfPageUp:	    ComboBox-Manager(page-up)		\n\
     <Key>osfPageDown:	    ComboBox-Manager(page-down)		";
   
/* ---------------------------------------------------------------------------
 * ---------------------------------------------------------------------------
 * Aktionen-Tabelle: Hierdurch werden den einzelnen Translations die dazuge-
 * hoerigen C-Routinen zugeordnet. Da wir hier ein anstaendiges ANSI-C be-
 * nutzen, werden hier zuerst einmal die Prototypen faellig... Ach ja, noch
 * ein Hinweis in eigener Sache... der ComboBox-Manager muss applikationsweit
 * registriert werden, da er auch von Translationen in den Kindern der Combo-
 * Box aktiviert wird. Bei diesem Namen der 'Aktion' steht aber nicht zu be-
 * fuerchten, dass er anderweitig bereits in Anwendung ist.
 */
static void CBoxManager(Widget w, XEvent *event, String *params, 
                        Cardinal *num_params);

static XtActionsRec actions[] = {
    { "ComboBox-Manager", CBoxManager },
    { NULL, NULL }
}; /* actions */

    
/* --------------------------------------------------------------------
 * Eine Instanz dieser Widget-Klasse wird erstmalig in Betrieb ge-
 * nommen, daher sind noch Vorbereitungen notwendig, die nun hier
 * durchgefuehrt werden.
 */
static XtTranslations NewEditTranslations, NewEditTranslationsNE, 
#ifdef NODRAGNDROP
                      NewListTranslations,
#endif
                      NewListTranslationsE;

static XtConvertArgRec ConverterScreenConvertArg[] = {
    { XtBaseOffset, (XtPointer) XtOffset(Widget, core.screen), 
      sizeof(Screen *) }
};

static void ClassInit()
{
    NewEditTranslations =
	    XtParseTranslationTable(newEditTranslations);
    NewEditTranslationsNE =
	    XtParseTranslationTable(newEditTranslationsNE);
#ifdef NODRAGNDROP
    NewListTranslations =
	    XtParseTranslationTable(newListTranslations);
#endif
    NewListTranslationsE =
	    XtParseTranslationTable(newListTranslationsE);
    XtAddConverter(XtRString, XtRBitmap, 
                   XmuCvtStringToBitmap, 
		   ConverterScreenConvertArg, 
                   XtNumber(ConverterScreenConvertArg));
} /* ClassInit */

/* ---------------------------------------------------------------------------
 * Weil es sich bei diesem Widget um ein etwas komplizierteres zusammengesetz-
 * tes Widget handelt, muessen wir hier - wo eigentlich nur das die Combobox
 * bildende Fenster auf dem X-Server erzeugt wird - noch einmal das Layout
 * auf Vordermann bringen. Den Aerger loest dabei das Listenfeld der OSF aus,
 * das einfach keine Geometrie-Nachfragen verschickt, solange es nicht 
 * 'realized' ist!!! Nicht, dass ich mich ueber so einen Sauhaufen aufregen 
 * wuerde...ich doch nicht! ABER MACHT IHR DENN NUR SO'N MIST...? WARUM KOENNT
 * IHR DENN NICHT EINMAL DIESES ****(BIEP)**** MOTIF TOOLKIT ANSTAENDIG
 * DOKUMENTIEREN! Ich glaub', ich kann mich nach dem Chaos eigentlich nur noch
 * hemmungslos besaufen... Die Suche nach der Ursache (bzw. Urheber = OSF) hat
 * mich doch einige Tage gekostet (jaja...die Mannstunden!).
 */
static void Realize(XmComboBoxWidget w, Mask *ValueMask, 
                    XSetWindowAttributes *Attributes)
{
    /* 
     * Also: wenn die Liste staendig sichtbar ist, dann zuerst noch einmal
     * das Layout berechnen. Sonst wird vorne und hinten 'was abgeschnitten.
     */
    if ( w->combobox.StaticList )
	DoLayout(w);
    (*w->core.widget_class->core_class.superclass->core_class.realize)
	((Widget) w, ValueMask, Attributes);
} /* Realize */

/* ---------------------------------------------------------------------------
 * Suche dasjenige Fenster, in dem unsere Shell liegt, in der wiederum die 
 * Combo-Box steckt. Diese Information wird benoetigt, um die Drop-Down-Liste
 * innerhalb des Fensterstacks immer direkt oberhalb der Shell mit der Combo-
 * Box zu halten. Jajaja -- ich muss halt davon ausgehen, dass der Fenster-
 * manager ein sog. "reparenting wm" ist; also die Dekorationen in einem
 * Fenster dargestellt werden und unsere Shell in dieses Fenster hineingepackt
 * ist. Die Dekoration ist damit ein Kind des 'root window' - wie die Shell,
 * in der die Drop-Down-Liste steckt. Und da nur Geschwisterfenster (sibling
 * windows) im gleichen Stapel stecken, reicht das Shellfenster nicht aus.
 * Alle gaengigen Fenstermanager sind solche "reparenting wm's", so dass ich
 * hier zu diesem Trick greifen kann, um die Drop-Down-Liste immer ueber der
 * ComboBox zu halten.
 *
 * Parameter:
 *   w			Diejenige Combo-Box, fuer die wir dasjenige
 *			Fenster des Window-Managers ermitteln sollen,
 *			dass direkt unterhalb des Root-Fensters liegt.
 * Ergebnis:
 *   besagtes zu suchendes Fenster, dass die Dekoration enthaelt (hoffentlich
 *   nur echte Bruesseler Spitze!)
 */
static Window GetDecorationWindow(XmComboBoxWidget w)
{
    Window       Root, Parent, AWindow;
    Window       *Children;
    unsigned int NumChildren;
    
    Parent = XtWindow((Widget) w);
    /* Suche nach dem Dekorationsfenster des Window-Managers */
    do {
	AWindow = Parent;
	XQueryTree(XtDisplay((Widget) w), AWindow, 
		   &Root, &Parent, &Children, &NumChildren);
	XFree((char *) Children);
    } while ( Parent != Root );
    return AWindow;
} /* GetDecorationWindow */

/* --------------------------------------------------------------------
 * Eine Combo-Box aus dem Wege raeumen...
 * Momentan muessen wir hier nur den Cursor wieder los werden sowie
 * eventuell reservierte Pixmaps.
 * Ups -- natuerlich muss auch wieder der Callback entfernt werden, 
 * der noch an der Shell haengt.
 */
static void Destroy(XmComboBoxWidget w)
{
/*    fprintf(stderr, "Destroy: %08X\n", w->core.window);*/
    if ( w->combobox.ConvertBitmapToPixmap )
	XFreePixmap(XtDisplay((Widget) w), 
	            w->combobox.LabelPixmap);
    if ( w->combobox.ConvertBitmapToPixmapInsensitive )
	XFreePixmap(XtDisplay((Widget) w), 
	            w->combobox.LabelInsensitivePixmap);
    if ( w->combobox.PendingFocusOut )
	XtRemoveWorkProc(w->combobox.WorkProcID);
    XtRemoveEventHandler(w->combobox.MyNextShell, 
                      StructureNotifyMask | FocusChangeMask, 
		      True, (XtEventHandler) ShellCallback, 
		      (XtPointer) w);
} /* Destroy */

/* ---------------------------------------------------------------------------
 * Ueberpruefe, ob fuer die Ressource "DropDownOffset" ein gueltiger Wert vom
 * Benutzer angegeben wurde. Diese Ressource gibt an, wie weit die Drop-Down-
 * Liste nach rechts gegenueber dem Eingabefeld eingerueckt sein soll. Wenn
 * hierfuer ein negativer Wert angegeben ist, so berechne statt dessen einen
 * Standardwert: dieser entspricht der Breite der Pfeilschaltflaeche, was 
 * optisch ganz gut wirkt (jedenfall nach meinem Dafuerhalten).
 */
static void CheckDropDownOffset(XmComboBoxWidget w)
{
    if ( w->combobox.DropDownOffset < 0 ) {
	XtWidgetGeometry ArrowGeom;
	
	XtQueryGeometry(w->combobox.ArrowCtrl, NULL, &ArrowGeom);
	w->combobox.DropDownOffset = ArrowGeom.width;
    }
} /* CheckDropDownOffset */

/* --------------------------------------------------------------------
 * Berechne die voreinzustellende Groesse, die diese Combo-Box be-
 * sitzen muss, um ausreichenden Raum fuer das Eingabefeld und den
 * Pfeil rechts daneben zur Verfuegung zu stellen. Bei einer
 * editierbaren Combo-Box ist zwischen dem Eingabefeld und dem Pfeil
 * noch ein Angst-Rasen von der halben Breite eines Pfeiles vorhanden.
 * Wird das Listenfeld staendig dargestellt, so entfallen sowohl Pfeil
 * als auch der Angstrasen, dafuer muss aber die Hoehe des Listenfelds
 * beruecksichtigt werden.
 */
static void DefaultGeometry(XmComboBoxWidget w, 
                            Dimension *TotalWidth, 
			    Dimension *TotalHeight, 
			    Dimension *EditCtrlWidth, 
			    Dimension *LabelCtrlWidth)
{
    XtWidgetGeometry EditGeom, ArrowGeom, LabelGeom, ListGeom;
    
    XtQueryGeometry(w->combobox.EditCtrl,  NULL, &EditGeom);
    XtQueryGeometry(w->combobox.ArrowCtrl, NULL, &ArrowGeom);
    XtQueryGeometry(w->combobox.LabelCtrl, NULL, &LabelGeom);

    /*
     * Soll die Pfeilschaltflaeche quadratisch, praktisch, gut sein?
     */
    if ( w->combobox.SquareArrow )
        ArrowGeom.width = ArrowGeom.height;
    else
        ArrowGeom.width = (ArrowGeom.height * 4) / 5;

    /*
     * Zuerst einmal ein paar einfache Werte ermitteln und zurueckgeben...
     */    
    *TotalHeight    = EditGeom.height;
    *EditCtrlWidth  = EditGeom.width;
    *LabelCtrlWidth = LabelGeom.width;

    /*
     * Ermittele nun die Breite, welche die Combobox benoetigt. Je nach-
     * dem, ob das Eingabefeld oder die Liste breiter sind, wird der
     * entsprechende Wert genommen. Diese Auswahl zwischen der Breite von
     * Eingabefeld und Liste findet aber nur statt, wenn die Liste auch
     * wirklich staendig sichtbar ist. Waehrend der Initialisierung hat
     * allerdings XmNcolumns, so dass in diesem Moment die List nicht
     * mehr die Breite kontrollieren kann!
     */
    if ( w->combobox.StaticList ) {
	/*
	 * Beachte: Frage nicht die Listbox, sondern das ScrolledWindow, 
	 * in welchem die Liste eingebettet ist.
	 */
	CheckDropDownOffset(w);
	XtQueryGeometry(XtParent(w->combobox.ListCtrl), NULL, &ListGeom);
	if ( w->combobox.InInit ) {
	    *TotalWidth = EditGeom.width;
	} else {
            if ( EditGeom.width < (Dimension)
                                   (ListGeom.width + w->combobox.DropDownOffset) )
		*TotalWidth = ListGeom.width + w->combobox.DropDownOffset;
	    else
		*TotalWidth = EditGeom.width;
        }
	*TotalHeight += ListGeom.height;
    } else {
	/*
	 * Das Listenfeld interessiert uns hier nicht. Degegen sollte noch
	 * die Breite fuer den Pfeil und ein evtl. Angstrasen beachtet
	 * werden.
	 */
	*TotalWidth  = EditGeom.width + ArrowGeom.width;
	if ( w->combobox.Editable && w->combobox.ArrowSpacingOn )
	    *TotalWidth += ArrowGeom.width/2;
    }
    
    /*
     * Vergiss nicht, auch noch ein evtl. sichtbares Schriftfeld zu berueck-
     * sichtigen!
     */
    if ( w->combobox.ShowLabel )
	*TotalWidth += LabelGeom.width;
    
} /* DefaultGeometry */

/* --------------------------------------------------------------------
 * Anhand eines Widgets ermittele darueber die Screennummer desjenigen
 * Screens, auf dem das Widget erscheint.
 * Parameter:
 *   w			betroffenes Widget.
 * Ergebnis:
 *   Nummer desjenigen Screens, auf dem das Widget angezeigt wird.
 */
static int WidgetToScreen(Widget w)
{
    Screen  *screen;
    Display *display;
    int     NumScreens, i;
    
    screen = XtScreen(w); NumScreens = ScreenCount(XtDisplay(w));
    display = DisplayOfScreen(screen);
    for ( i = 0; i < NumScreens; ++i )
	if ( ScreenOfDisplay(display, i) == screen )
	    return i;
    XtError("WidgetToScreen: data structures are destroyed.");
    return 0; /* to avoid a compiler warning */
} /* WidgetToScreen */

/* --------------------------------------------------------------------
 * Positioniere die DropDown-Liste (soweit sie natuerlich auch momentan
 * sichtbar ist) so auf dem Bildschirm, dass sie sich unterhalb des
 * Eingabefeldes anschliesst.
 */
static void DoDropDownLayout(XmComboBoxWidget w)
{
    Position       abs_x, abs_y;
    Dimension      ArrowWidth, ListWidth, ListHeight;
    Dimension      ScreenHeight, LabelWidth;
    XWindowChanges WindowChanges;

    /* 
     * etwa nicht sichtbar ?!! Oder etwa immer sichtbar ?!!
     * Dann sind wir jetzt sofort fertig. 
     */
    if ( !w->combobox.ListVisible || w->combobox.StaticList ) return;
    /*
     * Finde zuerst einmal heraus, wo wir uns denn auf dem Bildschirm be-
     * finden sollen... Beachte dabei auch, dass eventuell die Liste zu schmal
     * werden koennte und gib' ihr dann ggf. eine Mindestbreite, damit es
     * keinen core-Dump gibt.
     */
    XtVaGetValues(w->combobox.ArrowCtrl, XmNwidth,  &ArrowWidth, NULL);
    XtTranslateCoords((Widget) w, 0, w->core.height, &abs_x, &abs_y);
    CheckDropDownOffset(w);
    ListWidth  = w->core.width - w->combobox.DropDownOffset - 2;
    abs_x     += w->combobox.DropDownOffset;
    if ( w->combobox.ShowLabel ) {
	XtVaGetValues(w->combobox.LabelCtrl, XmNwidth, &LabelWidth, NULL);
	ListWidth -= LabelWidth;
	abs_x     += LabelWidth;
    }
    if ( ListWidth < 20 ) ListWidth = 20;
    XtVaGetValues(XtParent(w->combobox.ListCtrl), XmNheight, &ListHeight, NULL);
    /*
     * Hier ueberpruefen wir noch, ob die Liste unten aus dem Bildschirm 
     * herausfallen wuerde. In dem Fall klappen wir die Liste oberhalb des
     * Eingabefeldes auf.
     */
    ScreenHeight = DisplayHeight(XtDisplay((Widget) w), 
                                 WidgetToScreen((Widget) w));
    if ( abs_y + ListHeight + 2 > ScreenHeight ) {
        int y;
        
        y = ((int) abs_y) - ListHeight - w->core.height - 1;
        if ( y < 0 ) y = 0;
        abs_y = (Position) y;
    }
    XtConfigureWidget(w->combobox.PopupShell, 
		      abs_x, abs_y, ListWidth, ListHeight, 1);
    /*
     * So...das hier dient der Kosmetik: hier sorgen wir dafuer, dass die
     * Liste auch wirklich immer direkt ueber der ComboBox innerhalb des
     * Fensterstapels schwebt. Siehe dazu auch die Erlaeuterungen und An-
     * merkungen in GetDecorationWindow().
     */
    if ( XtIsRealized((Widget) w) ) {
	WindowChanges.sibling    = GetDecorationWindow(w);
	WindowChanges.stack_mode = Above;
	XReconfigureWMWindow(XtDisplay((Widget) w), 
	    XtWindow(w->combobox.PopupShell), 
	    WidgetToScreen(w->combobox.PopupShell), 
	    CWSibling | CWStackMode, &WindowChanges);
    }
} /* DoDropDownLayout */

/* --------------------------------------------------------------------
 * Naja... diese Routine scheint ja bereits zu einer Institution beim
 * Schreiben von Composite-Widgets geworden zu sein.
 * 
 * Hier beim ComboBox-Widget ist die Aufgabe ziemlich einfach: es
 * genuegt, die Eingabezeile und den Pfeil-Button entsprechend inner-
 * halb des ComboBox-Widgets zu plazieren. Seit allerdings noch das
 * Textlabel hinzukommt, wird's langsam aufwendiger. Nun ja - da sich
 * das Listenfeld wahlweise auch statisch einblenden laesst, ist nun
 * noch mehr zu beruecksichtigen, wenn die Kinder-Widgets an ihre
 * Plaetze geschoben werden.
 */
static void DoLayout(XmComboBoxWidget w)
{
    Dimension        EditCtrlWidth, ArrowCtrlWidth, LabelCtrlWidth;
    Dimension        ComboBoxHeight;
    Dimension        BorderWidth;
    Dimension        HighlightThickness;
    Position         EditX;
    
    XtVaGetValues(w->combobox.ArrowCtrl,
                  XmNheight, &ArrowCtrlWidth, NULL);
    if ( !w->combobox.SquareArrow )
        ArrowCtrlWidth = (ArrowCtrlWidth * 4) / 5;
    XtVaGetValues(w->combobox.LabelCtrl, 
                  XmNwidth, &LabelCtrlWidth, NULL);
    
    /* 
     * In Abhaengigkeit davon, ob die ComboBox editierbar ist und ob das
     * Listenfeld staendig sichtbar sein soll, hier die Breite einzelner
     * Widgets bestimmen.
     */
    if ( w->combobox.StaticList ) {
	ComboBoxHeight = w->combobox.EditCtrl->core.height;
	EditCtrlWidth  = w->core.width;
    } else {
	ComboBoxHeight = w->core.height;
	EditCtrlWidth  = w->core.width - ArrowCtrlWidth;
    	if ( w->combobox.Editable && w->combobox.ArrowSpacingOn )
    	    EditCtrlWidth -= ArrowCtrlWidth/2;
    }
    /* Beruecksichtige noch ein evtl. ebenfalls anzuzeigendes Schriftfeld
     * neben dem Eingabefeld.
     */
    if ( w->combobox.ShowLabel ) {
	EditX          = LabelCtrlWidth;
	EditCtrlWidth -= LabelCtrlWidth;
    } else
        EditX = 0;
    if ( EditCtrlWidth < 20 ) EditCtrlWidth = 20;
/* Plaziere nun das Eingabefeld... */
    XtVaGetValues(w->combobox.EditCtrl, 
                  XmNborderWidth,        &BorderWidth, 
		  XmNhighlightThickness, &HighlightThickness, 
		  NULL);
    XtConfigureWidget(w->combobox.EditCtrl, 
                      EditX, 0, 
		      EditCtrlWidth, ComboBoxHeight, BorderWidth);
/* ...und nun den Pfeil... */
    XtVaGetValues(w->combobox.ArrowCtrl, 
                  XtNborderWidth, &BorderWidth, NULL);
    XtConfigureWidget(w->combobox.ArrowCtrl, 
                      w->core.width-ArrowCtrlWidth, HighlightThickness, 
		      ArrowCtrlWidth, 
		      ComboBoxHeight - 2 * HighlightThickness, 
		      BorderWidth);
/* ...und ggf. das Textlabel. */
    if ( w->combobox.ShowLabel ) {
	XtVaGetValues(w->combobox.LabelCtrl, 
		      XmNborderWidth, &BorderWidth, 
		      NULL);
	XtConfigureWidget(w->combobox.LabelCtrl, 
	                  0, 0, 
			  LabelCtrlWidth, ComboBoxHeight, 
			  BorderWidth);
    }
/* Falls da noch die Liste herumgurkt... */
    if ( w->combobox.StaticList ) {
	Dimension Width, Height;
	
	if ( w->core.height > ComboBoxHeight ) 
	    Height = w->core.height - ComboBoxHeight;
	else
	    Height = 10;
	    
	if ( w->core.width > (Dimension)(ArrowCtrlWidth + EditX) )
	    Width = w->core.width - ArrowCtrlWidth - EditX;
	else
	    Width = 10;
	
	XtConfigureWidget(XtParent(w->combobox.ListCtrl),
	    EditX + ArrowCtrlWidth, ComboBoxHeight, Width, Height, 0);
    } else if ( w->combobox.ListVisible )
	DoDropDownLayout(w); 
} /* DoLayout */

/* --------------------------------------------------------------------
 * Pappi fragt nach, wie gross wir denn sein wollen.
 * Die hier benutzte Vorgehensweise zur Ermittlung der Groesse:
 *   Sobald der Vater uns eine Breite (oder aber Hoehe) vorschlaegt, 
 *   die fuer uns eigentlich zu klein ist, meckern wir und schlagen
 *   die von uns benoetigte Breite (Hoehe) vor.
 * Soweit also zur Theorie... leider sieht es beispielsweise das
 * Motif Form-Widget ueberhaupt nicht ein, uns auch nur ein einziges
 * Mal nach unseren Wuenschen zu fragen! Damit es bei derart unum-
 * gaenglichen Widgets dann doch noch geht, muss ChangedManaged die
 * Kohlen wieder aus dem Feuer holen mit einer Sondertour.
 * Parameter:
 *   *Request	    Vom Vater vorgeschlagene Geometrie
 * Ergebnis:
 *   *Reply	    Unsere Antwort auf die vorgeschlagene Geometrie
 *   sowie XtGeometryYes oder XtGeometryAlmost, je nachdem, wie gut
 *   uns Pappis Vorschlag in den Kram passt.
 */
static XtGeometryResult QueryGeometry(XmComboBoxWidget w, 
                                      XtWidgetGeometry *Request, 
			              XtWidgetGeometry *Reply)
{
    XtGeometryResult result = XtGeometryYes;
    Dimension        minW, minH, editW, labelW;
    
/* Elternteil will nichts weiter aendern, also ist uns das
 * recht so.
 */
    Request->request_mode &= CWWidth | CWHeight;
    if ( Request->request_mode == 0 ) return result;

    DefaultGeometry(w, &minW, &minH, &editW, &labelW);

/* Ueberpruefe, ob uns das in der Breite passt, was Pappi moechte... */
    if ( Request->request_mode & CWWidth ) {
	if ( Request->width < minW ) {
/* Wenn Pappi uns etwas vorschlaegt, was im wahrsten Sinne des Wortes 
 * vorn und hinten nicht reicht, dann versuchen wir ihn entsprechend
 * zu korrigieren. ("Versuchen" deshalb, weil er diesen Vorschlag auch
 * voellig ignorieren kann.)
 */
	    result               = XtGeometryAlmost;
	    Reply->width         = minW;
	    Reply->request_mode |= CWWidth;
	}
    }
/* Die ganze Chose nun noch vertikal */
    if ( Request->request_mode & CWHeight ) {
	if ( Request->height < minH ) {
	    result               = XtGeometryAlmost;
	    Reply->height        = minH;
	    Reply->request_mode |= CWHeight;
	}
    }
    return result;
} /* QueryGeometry */

/* --------------------------------------------------------------------
 * Die Groesse des ComboBox-Widgets hat sich veraendert und deshalb
 * mussen alle Kinder neu positioniert werden.
 * Letzten Endes laeuft hier alles auf ein ordinaeres DoLayout()
 * hinaus, um die Kinder umher zu schieben.
 * Parameter:
 *   w		    Die bereits hinlaenglich bekannte Instanz dieses
 *		    Widgets
 */
static void Resize(XmComboBoxWidget w)
{
    DoLayout(w);
} /* Resize */

/* --------------------------------------------------------------------
 * Dieses Widget hat sich in irgendeiner Form bewegt (und das nicht
 * nur relativ zum Vater, sondern moeglicherweise auch der Vater
 * selbst!) bzw. die Shell, in der sich irgendwo unsere Combo-Box
 * befindet, hat soeben den Fokus verschusselt und kann ihn nicht
 * mehr wiederfinden. Daneben kann es auch sein, dass die Shell
 * ikonisiert wurde. (Welch' Vielfalt! Dieses ist hier halt eine
 * multifunktionale Routine.)
 * 
 * Parameter:
 *   w		    Die naechste Shell in Reichweite ueber unserer
 *		    Combo-Box.
 *   cbw	    Diese Combo-Box.
 *   event	    ^ auf den Event, enthaelt genauerere Informationen
 *		    (naja... sieht so aus, als ob Motif hier auch 
 *		    schon 'mal Schrott 'reinpackt...)
 *   ContDispatch   Auf True setzen, damit dieser Event noch weiter-
 *		    gereicht wird an all' die anderen, die auch noch
 *		    mithoeren.
 */
static void ShellCallback(Widget w, XtPointer pClientData, 
                          XEvent *event, Boolean *ContDispatch)
{
    XmComboBoxWidget cbw = (XmComboBoxWidget) pClientData;
    
    switch ( event->type ) {
	case ConfigureNotify:
	case CirculateNotify:
	    DoDropDownLayout((XmComboBoxWidget) cbw);
	    break;
	case FocusOut:
	    LOG3("ShellCallback: FocusOut, mode: %i, detail: %i\n",
	         (int)event->xfocus.mode, (int)event->xfocus.detail);
	    if ( cbw->combobox.Persistent )
		cbw->combobox.IgnoreFocusOut = True;
	    else if ( (event->xfocus.mode == NotifyGrab) &&
	              cbw->combobox.ListVisible )
	        cbw->combobox.IgnoreFocusOut = True;
	    break;
	case UnmapNotify:
	    ShowHideDropDownList((XmComboBoxWidget) cbw, 
	                         event, False);
	    break;
    }
    *ContDispatch = True;
} /* ShellCallback */

/* --------------------------------------------------------------------
 * Diese Routine sorgt dafuer, dass die Liste nicht irrtuemlich bei
 * manchen Window Managern vom Bildschirm genommen wird, bloss weil
 * diese der OverrideShell den Tastaturfocus schenken bzw. diesen
 * dem Combo-Box-Widget wegnehmen, sobald der Mauszeiger in die Liste
 * bewegt wird.
 */
static void OverrideShellCallback(Widget w, XtPointer pClientData,
                                  XEvent *event, Boolean *ContDispatch)

{
    XmComboBoxWidget cbw = (XmComboBoxWidget) pClientData;
    switch ( event->type ) {
        case EnterNotify:
	    LOG2("OverrideShellCallback: EnterNotify, PendingFO: %s\n", 
	         cbw->combobox.PendingFocusOut ? "True" : "False");
            if ( cbw->combobox.PendingFocusOut )
                cbw->combobox.IgnoreFocusOut = True;
	    if ( cbw->combobox.TwmHandlingOn )
                cbw->combobox.PendingOverrideInOut = True;
            break;
        case LeaveNotify:
            LOG("OverrideShellCallback: LeaveNotify\n");
	    if ( cbw->combobox.TwmHandlingOn )
              cbw->combobox.PendingOverrideInOut = True;
            break;
    }
} /* OverrideShellCallback */

/* --------------------------------------------------------------------
 * Ha! Anscheinend kann man das Problem mit der einklappenden Liste,
 * sobald man den Arrow-Button anklickt, doch loesen! Allerdings geht
 * das auch nur von hinten durch die Brust in's Auge. Hier war die
 * Reihenfolge der Events bislang das Problem: Klickt man den Arrow-
 * Button an, so verliert das Eingabefeld den Focus, dann wird leider
 * schon die WorkProc aktiviert und laesst die Liste verschwinden.
 * Danach erst kommt der Arrow-Button-Callback an die Reihe. Um dieses
 * Dilemma doch noch zu loesen, wird hier darauf gelauert, wann und
 * welcher LeaveNotify kommt. Klickt der Benutzer den Pfeil an, so
 * kommt hier noch rechtzeitig ein LeaveNotify vorbei, der aber durch
 * einen Grab ausgeloest wurde. Und das ist eben nur beim Anklicken
 * der Fall. Damit wissen wir, das der FocusOut getrost ignoriert
 * werden darf.
 * Puhhh -- ist das ein kompliziertes Chaos.
 * Uebrigends...auch wenn manche Befehle zuerst ueberfluessig er-
 * scheinen...sie sind erforderlich, damit die ComboBox auch mit unter-
 * schiedlichen Window Managern zurechtkommt!
 */
static void ArrowCrossingCallback(Widget w, XtPointer pClientData,
                               XEvent *event, Boolean *ContDispatch)

{
    XmComboBoxWidget cbw = (XmComboBoxWidget) pClientData;
    switch ( event->type ) {
        case LeaveNotify:
	    LOG2("ArrowCrossingCallback: LeaveNotify, mode: %i\n", 
	         event->xcrossing.mode);
            if ( event->xcrossing.mode == NotifyGrab )
                cbw->combobox.IgnoreFocusOut = True;
            else
                cbw->combobox.IgnoreFocusOut = False;
            break;
    }
} /* ArrowCrossingCallback */

/* --------------------------------------------------------------------
 * Alle Hilfeaufrufe innerhalb der Kinder gehen an das eigentliche
 * Combo-Box-Widget weiter, so dass auch hier nach aussen hin die
 * Kinder-Widgets nicht in Erscheinung treten.
 */
static void HelpCallback(Widget w, XtPointer cbw, XtPointer CallData)
{
    XtCallCallbacks((Widget) cbw, XmNhelpCallback, CallData);
} /* HelpCallback */

/* --------------------------------------------------------------------
 * Wenn der Benutzer im Eingabefeld osfActivate drueckt, dann dieses
 * Ereignis offiziell bekanntgeben.
 */
static void ActivateCallback(Widget w, XtPointer cbw, XtPointer CallData)
{
    XtCallCallbacks((Widget) cbw, XmNactivateCallback, CallData);
} /* ActivateCallback */

/* --------------------------------------------------------------------
 * Ein Kind moechte sein Groesse veraendern und fragt deshalb hier bei
 * uns an.
 * Parameter:
 *   w		    Naja...
 *   *Request	    Vorschlag des Kindes
 * Ergebnis:
 *   *Reply	    Unsere Antwort darauf
 *   XtGeometryNo, da es uns bislang grundsaetzlich nie passt, es sei
 *   denn, es ist das Label... Naja, jetzt darf auch schon einmal das
 *   Listenfeld quengeln (aber nur, wenn es staendig sichtbar ist, 
 *   ansonsten wird es nicht beruecksichtigt!).
 */
static XtGeometryResult GeometryManager(Widget w, 
                                        XtWidgetGeometry *Request, 
				        XtWidgetGeometry *Reply)
{
    XmComboBoxWidget cbw = (XmComboBoxWidget) XtParent(w);
    XtGeometryResult Result = XtGeometryNo;
    
    /*
     * Falls das Listenfeld statisch dargestellt wird, muessen wir seine
     * Wuensche doch beruecksichtigen. Was fuer ein Aufwand...
     */
    if ( (w == XtParent(cbw->combobox.ListCtrl)) && cbw->combobox.StaticList ) {
        Dimension TotalWidth, TotalHeight, EditWidth, LabelWidth;
        XtWidgetGeometry MyRequest, YourReply, EditGeom;
        
        XtQueryGeometry(cbw->combobox.EditCtrl, NULL, &EditGeom);
        DefaultGeometry(cbw, &TotalWidth, &TotalHeight,
                             &EditWidth, &LabelWidth);
      	CheckDropDownOffset(cbw);
	
        if ( Request->request_mode && CWWidth )
            if ( (Dimension)(LabelWidth + cbw->combobox.DropDownOffset + 
                             Request->width) > TotalWidth )
                TotalWidth = LabelWidth + cbw->combobox.DropDownOffset + 
                             Request->width;
        
        if ( Request->request_mode && CWHeight )
            TotalHeight = EditGeom.height + Request->height;
    /*
     * Bastele nun eine Anfrage an Pappi zusammen und geh' ihm damit auf den
     * Keks. Wenn er zustimmt, ist sofort alles gut, wir muessen dann nur
     * noch das Layout aufpolieren, damit das Listenfeld die neue Groesse
     * bekommt. Wenn Pappi nur halb zustimmt, akzeptieren wir das und fragen
     * ihn damit noch einmal....
     */
        MyRequest.request_mode = CWWidth | CWHeight;
        MyRequest.width        = TotalWidth;
        MyRequest.height       = TotalHeight;
        Result = XtMakeGeometryRequest((Widget) cbw, &MyRequest, &YourReply);
	if ( Result == XtGeometryAlmost ) {
	    MyRequest.width  = YourReply.width;
	    MyRequest.height = YourReply.height;
	    Result = XtMakeGeometryRequest((Widget) cbw, &MyRequest, &YourReply);
	}
	if ( Result == XtGeometryYes )
	    DoLayout(cbw);
    } else 
    /*
     * Ansonsten darf nur noch das Schriftfeld Ansprueche anmelden.
     */
    if ( w != cbw->combobox.LabelCtrl )
        return XtGeometryNo; /* Was ICH hier vorgegeben habe, gilt! */
    else if ( cbw->combobox.ShowLabel ) { /* Naja, 'mal schauen! */
        Dimension TotalWidth, TotalHeight, EditWidth, LabelWidth;
        XtWidgetGeometry MyRequest;
        
        if ( Request->request_mode & CWWidth ) {
            DefaultGeometry(cbw, &TotalWidth, &TotalHeight,
                                 &EditWidth, &LabelWidth);
            TotalWidth = TotalWidth - LabelWidth + 
                         Request->width;
            
            MyRequest.request_mode = CWWidth;
            MyRequest.width        = TotalWidth;
            Result = XtMakeGeometryRequest((Widget) cbw, &MyRequest, NULL);

            if ( Result == XtGeometryYes )
		DoLayout(cbw);
        }
    }
    return Result;
} /* GeometryManager */

/* --------------------------------------------------------------------
 * Hier werden auf Wunsch diejenigen Farben, die bei der Combo-Box neu
 * gesetzt wurden, an alle Kinder weitergegeben.
 */
#define BOTTOMSHADOWCOLOR   0x0001
#define TOPSHADOWCOLOR	    0x0002
#define FOREGROUND	    0x0004
#define BACKGROUND	    0x0008

static struct { String Resource; int Flag; }
       ColorResources[] = {
	   { XmNbottomShadowColor, BOTTOMSHADOWCOLOR }, 
	   { XmNtopShadowColor,    TOPSHADOWCOLOR    }, 
	   { XmNforeground,        FOREGROUND        }, 
	   { XmNbackground,        BACKGROUND        }
       };

static int UpdateColors(XmComboBoxWidget w, int flags)
{
    Pixel  Color, White, Black, EditCol;
    int    i, size = XtNumber(ColorResources);
    Widget ScrolledWin, ScrollBar;
    
    ScrolledWin = XtParent(w->combobox.ListCtrl);
    XtVaGetValues(ScrolledWin, XmNverticalScrollBar, &ScrollBar, NULL);
    White = WhitePixel(XtDisplay(w), WidgetToScreen((Widget) w));
    Black = BlackPixel(XtDisplay(w), WidgetToScreen((Widget) w));
    for ( i=0; i<size; i++ )
	if ( flags & ColorResources[i].Flag ) {
            if ( ColorResources[i].Flag == BACKGROUND )
                EditCol = White;
            else if ( ColorResources[i].Flag == FOREGROUND )
                EditCol = Black;
            else
                EditCol = Color;
	    XtVaGetValues((Widget) w, ColorResources[i].Resource, &Color,
	                  NULL);
	    XtVaSetValues(ScrollBar, 
	                  ColorResources[i].Resource, Color, NULL);
            XtVaSetValues(w->combobox.ListCtrl, 
                          ColorResources[i].Resource, EditCol, NULL);
            XtVaSetValues(w->combobox.EditCtrl, 
                          ColorResources[i].Resource, EditCol, NULL);
            XtVaSetValues(ScrolledWin, 
                          ColorResources[i].Resource, Color, NULL);
	    XtVaSetValues(w->combobox.LabelCtrl, 
	                  ColorResources[i].Resource, Color, NULL);
	    XtVaSetValues(w->combobox.ArrowCtrl, 
	                  ColorResources[i].Resource, Color, NULL);
	    if ( ColorResources[i].Flag & BACKGROUND )
		XtVaSetValues(ScrollBar, XmNtroughColor, Color, NULL);
	}

	return 1;
} /* UpdateColors */

/* --------------------------------------------------------------------
 * Liste aller vorgespiegelten Resourcen, die automatisch verarbeitet
 * werden koennen, ohne weiter darueber nachdenken zu muessen...
 */
typedef enum  { EDITCTRL, LISTCTRL, LABELCTRL } CHILDCTRL;
typedef enum { RO, RW, RWS, RWL, RWI, RWIGNORE } aUniqueName;
typedef struct {
    String                    rsc;
    CHILDCTRL                 ctrl;
/*    enum { RO, RW, RWS, RWL, RWI, RWIGNORE } dir; */
    aUniqueName dir;
    /* nur lesen, lesen&schreiben, lesen&schreiben spezial,
       lesen&schreiben label, lesen&schreiben items */
} MIRROR;

/* Alle mit !!! gekennzeichneten Eintraege werden auf die richtigen
 * Namen des entsprechenden Widgets umgesetzt.
 */
static MIRROR MirroredResources[] = {
    { XmNitems,			    LISTCTRL,  RWI }, /* Urgs! */
    { XmNitemCount,		    LISTCTRL,  RWIGNORE  }, /* dto.  */
    { XmNlistMarginHeight,	    LISTCTRL,  RW  }, 
    { XmNlistMarginWidth,	    LISTCTRL,  RW  }, 
    { XmNlistSpacing,		    LISTCTRL,  RW  }, 
    { XmNstringDirection,	    LISTCTRL,  RO  }, /* Naja? */
    { XmNtopItemPosition,	    LISTCTRL,  RO  }, 
    
    { XmNblinkRate,		    EDITCTRL,  RW  }, 
    { XmNcolumns,		    EDITCTRL,  RW  }, 
    { XmNcursorPosition,	    EDITCTRL,  RW  }, 
    { XmNcursorPositionVisible,	    EDITCTRL,  RW  }, 
    { XmNmarginHeight,		    EDITCTRL,  RW  }, 
    { XmNmarginWidth,		    EDITCTRL,  RW  }, 
    { XmNmaxLength,		    EDITCTRL,  RW  }, 
    { XmNselectThreshold,	    EDITCTRL,  RW  }, 
    { XmNvalue,			    EDITCTRL,  RWS }, 
    
    { XmNalignment,		    LABELCTRL, RW  }, 
    { XmNmnemonic,		    LABELCTRL, RW  }, 
    { XmNmnemonicCharSet,	    LABELCTRL, RW  }, 
    { XmNlabelPixmap,		    LABELCTRL, RW  }, 
    { XmNlabelInsensitivePixmap,    LABELCTRL, RW  }, 
    { XmNlabelString,		    LABELCTRL, RW  }, 
    { XmNlabelType,		    LABELCTRL, RW  }, 
    { XmNlabelMarginBottom,	    LABELCTRL, RWL }, /* !!! */
    { XmNlabelMarginHeight,	    LABELCTRL, RWL }, /* !!! */
    { XmNlabelMarginLeft,	    LABELCTRL, RWL }, /* !!! */
    { XmNlabelMarginRight,	    LABELCTRL, RWL }, /* !!! */
    { XmNlabelMarginTop,	    LABELCTRL, RWL }, /* !!! */
    { XmNlabelMarginWidth,	    LABELCTRL, RWL }, /* !!! */
    { XmNlabelFontList,             LABELCTRL, RWL }, /* !!! */
};

typedef struct {
    char *from, *to;
} TRANSFORMATION;
static TRANSFORMATION Transformations[] = {
    { XmNlabelMarginBottom, XmNmarginBottom }, 
    { XmNlabelMarginHeight, XmNmarginHeight }, 
    { XmNlabelMarginLeft,   XmNmarginLeft   }, 
    { XmNlabelMarginRight,  XmNmarginRight  }, 
    { XmNlabelMarginTop,    XmNmarginTop    }, 
    { XmNlabelMarginWidth,  XmNmarginWidth  }, 
    { XmNlabelFontList,     XmNfontList     },
};

/* --------------------------------------------------------------------
 * Sobald irgendeine Resource veraendert wird, erfolgt der Aufruf
 * hierin als Benachrichtigung, einmal nach dem rechten zu sehen.
 * Parameter:
 *   current	    Kopie der Widget-Instanz, bevor irgendwelche
 *		    Resourcen veraendert oder set_values()-Methoden
 *		    aufgerufen wurden.
 *   req	    Kopie der Widget-Instanz, aber bereits mit den
 *		    durch XtSetValues veraenderten Werten
 *   new	    aktuellster Zustand der Widget-Instanz mit
 *		    veraenderten Werten (entweder durch XtSetValues
 *		    oder set_values()-Methoden der Superklasse)
 *   args	    Argumentenliste beim Aufruf von XtSetValues()
 *   NumArgs	    Anzahl der Argumente in der Liste
 * Ergebnis:
 *   True, falls Widget neu gezeichnet werden soll.
 */
static Boolean SetValues(XmComboBoxWidget current, XmComboBoxWidget req, 
                         XmComboBoxWidget newW, 
	                 ArgList args, Cardinal *NumArgs)
{
    Boolean Update = False;
    int i, j, MirrorSize = XtNumber(MirroredResources);
    int k, TransformationSize = XtNumber(Transformations);
    Arg arg;
    int Flags;
    
/* 
 * Alle Resourcen, die nicht mehr nach dem Erstellen der Widget-Instanz
 * veraendert werden koennen.
 */
    newW->combobox.Editable        = current->combobox.Editable;
    newW->combobox.ListCtrl        = current->combobox.ListCtrl;
    newW->combobox.EditCtrl        = current->combobox.EditCtrl;
    newW->combobox.LabelCtrl       = current->combobox.LabelCtrl;
    newW->combobox.SelectionPolicy = current->combobox.SelectionPolicy;
    newW->combobox.ListSizePolicy  = current->combobox.ListSizePolicy;
    newW->combobox.StaticList      = current->combobox.StaticList;
    
/* 
 * Kontrolliere nun alle Resourcen, die sich veraendert haben koennten
 * und gebe die neuen Einstellungen entsprechend weiter...
 *
 * Hat sich der Sensitive-Zustand veraendert? Dann muessen wir hier dafuer
 * sorgen, dass alle Kinder ebenfalls den neuen Zustand annehmen.
 */
    if ( current->core.sensitive != newW->core.sensitive ) {
        XtSetSensitive(newW->combobox.ListCtrl, newW->core.sensitive);
        XtSetSensitive(newW->combobox.EditCtrl, newW->core.sensitive);
        XtSetSensitive(newW->combobox.ArrowCtrl, newW->core.sensitive);
        XtSetSensitive(newW->combobox.ListCtrl, newW->core.sensitive);
        if ( !newW->core.sensitive )
            ShowHideDropDownList(newW, NULL, False);
    }
/* 
 * Die ScrollBarPolicy kann nur dann geaendert werden, wenn das Listenfeld
 * dauerhaft dargestellt wird.
 */
    if ( newW->combobox.ScrollBarDisplayPolicy != 
	 current->combobox.ScrollBarDisplayPolicy ) {
        if ( newW->combobox.StaticList )
            XtVaSetValues(newW->combobox.ListCtrl,
                          XmNscrollBarDisplayPolicy, newW->combobox.ScrollBarDisplayPolicy,
                          NULL);
        else
            XtWarning(
"XmComboBox: ScrollBarDisplayPolicy can not be changed when StaticList == False."
);
    }
/* Anzahl der in der Liste gleichzeitig darstellbaren Eintraege */
    if ( current->combobox.VisibleItemCount != 
           newW->combobox.VisibleItemCount ) {
	XtVaSetValues(newW->combobox.ListCtrl, 
	              XmNvisibleItemCount, newW->combobox.VisibleItemCount, 
		      NULL);
	Update = True;
    }
    if ( current->combobox.AutomaticSelection != 
	 newW->combobox.AutomaticSelection ) {
	XtVaSetValues(newW->combobox.ListCtrl, 
	              XmNautomaticSelection, newW->combobox.AutomaticSelection, 
		      NULL);
    }
/* 
 * benutzter Font: hier erhalten Liste und Eingabefeld jeweils die
 * gleiche Fontliste, wohingegen das Label getrennt behandelt wird.
 * Das macht auch Sinn, denn Liste und Eingabefeld beinhalten gleich-
 * artigen Text, so dass hier auch tunlichst der gleiche Font zu
 * benutzen ist.
 */
    if ( current->combobox.Font != newW->combobox.Font ) {
	XtVaSetValues(newW->combobox.ListCtrl, 
	              XmNfontList, newW->combobox.Font, NULL);
	XtVaSetValues(newW->combobox.EditCtrl, 
	              XmNfontList, newW->combobox.Font, NULL);
    	Update = True;
    }
    
    Flags = 0;
    if ( newW->manager.top_shadow_color != 
         current->manager.top_shadow_color    ) Flags |= TOPSHADOWCOLOR;
    if ( newW->manager.bottom_shadow_color != 
         current->manager.bottom_shadow_color ) Flags |= BOTTOMSHADOWCOLOR;
    if ( newW->manager.foreground != 
         current->manager.foreground          ) Flags |= FOREGROUND;
    if ( newW->core.background_pixel != 
         current->core.background_pixel       ) Flags |= BACKGROUND;
    if ( Flags ) { UpdateColors(newW, Flags); Update = True; }
    
    
    if ( newW->combobox.ArrowCursor != current->combobox.ArrowCursor ) {
	if ( newW->combobox.ListVisible )
	    XDefineCursor(XtDisplay(newW->combobox.PopupShell), 
			    XtWindow(newW->combobox.PopupShell), 
			    newW->combobox.ArrowCursor); 
   }
/* Hier werden die vorgespiegelten Resourcen verwaltet, die in
 * Wirklichkeit zu einem unserer Kinder gehoeren.
 */
     for ( i = 0; i < *NumArgs; i++ ) {
/* Ist es eine vorgespiegelte Resource ? Wenn ja, dann leite die
 * Anfrage an das entsprechende Kind-Widget weiter.
 */
	for ( j = 0; j < MirrorSize; j++ ) {
	    if ( (strcmp(args[i].name, MirroredResources[j].rsc) == 0) ) {
		switch ( MirroredResources[j].dir ) {
		case RW:   /* schreibender Zugriff erlaubt */
		    XtSetValues(MirroredResources[j].ctrl == LISTCTRL ?
			          newW->combobox.ListCtrl :  
				(MirroredResources[j].ctrl == EDITCTRL ?
				  newW->combobox.EditCtrl :
				  newW->combobox.LabelCtrl), 
			&(args[i]), 1);
		    break;
		case RWS:  /* schreibender Zugriff unter Kontrolle */
		    if ( strcmp(args[i].name, XmNvalue) == 0 ) {
			if ( newW->combobox.Editable )
			    XtSetValues(newW->combobox.EditCtrl, 
			                &(args[i]), 1);
		    }
		    break;
		case RWL: /* Transformation in andere Resource beim
		             Label-Widget */
		    for ( k = 0; k < TransformationSize; k++ )
			if ( strcmp(args[i].name, Transformations[k].from) == 0 ) {
			    arg.value = args[i].value;
			    arg.name = Transformations[k].to;
			    XtSetValues(newW->combobox.LabelCtrl, 
			                &arg, 1);
			    break;
			}
		    break;
		case RWIGNORE: /* Zugriff auf XmNitemCount */
		               /* Wird von XmNitems erledigt! */
		    break;
		case RWI: /* Zugriff auf XmNitems */
		    for ( k = 0; k < *NumArgs; k++ )
			if ( strcmp(args[k].name, XmNitemCount) == 0 ) {
			    Arg MyArgs[2];
			    
			    MyArgs[0].name  = XmNitems;
			    MyArgs[0].value = args[i].value;
			    MyArgs[1].name  = XmNitemCount;
			    MyArgs[1].value = args[k].value;
			    XtSetValues(newW->combobox.ListCtrl,
			                args, 2);
			    /*XtVaSetValues(newW->combobox.ListCtrl, 
			                  XmNitems,     args[i].value, 
					  XmNitemCount, args[k].value, 
					  NULL);*/
			    break;
			}
		    break;
		case RO:
		    break;
		} /* case write mode */
		goto ScanForNextResource;
	    } /* if entry found */
	} /* for every mirrored entry */
        ScanForNextResource: ;
    } /* for every Arg */
    
    if ( (newW->combobox.SquareArrow != current->combobox.SquareArrow) ||
         (newW->combobox.ArrowSpacingOn != current->combobox.ArrowSpacingOn) ) {
        Update = False;
        DoLayout(newW);
    }
    
    return Update;
} /* SetValues */

/* --------------------------------------------------------------------
 * Werden irgendwelche Resourcen abgefragt, so muessen wir hier erst
 * noch vor der Rueckkehr zum Frager klaeren, ob davon eine Resource
 * betroffen ist, die nur vorgespiegelt ist, da sie eigentlich einem
 * der Widgets gehoert, die von uns hier verwaltet werden, um daraus
 * eine ordentliche Combo-Box zu machen.
 * Parameter:
 *   w		    Widget-Instanz
 *   args	    Abgefragte Resourcen
 *   NumArgs	    Anzahl der abgefragten Resourcen
 */
static void GetValuesAlmost(XmComboBoxWidget w, ArgList args, 
                            Cardinal *NumArgs)
{
    int i, j, MirrorSize = XtNumber(MirroredResources);
    int k, TransformationSize = XtNumber(Transformations);
    Arg arg;
    
    for ( i = 0; i < *NumArgs; i++ ) {
/* Ist es eine vorgespiegelte Resource ? Wenn ja, dann leite die
 * Anfrage an das entsprechende Kind-Widget weiter.
 */
	for ( j = 0; j < MirrorSize; j++ ) {
	    if ( strcmp(args[i].name, MirroredResources[j].rsc) == 0 ) {
		switch ( MirroredResources[j].dir ) {
		case RO:
		case RW:
		case RWS:
		case RWI:
		    XtGetValues(MirroredResources[j].ctrl == LISTCTRL ?
			          w->combobox.ListCtrl : 
				MirroredResources[j].ctrl == EDITCTRL ?
				  w->combobox.EditCtrl :
				  w->combobox.LabelCtrl, 
			&(args[i]), 1);
		    break;
		case RWL: /* Umzuleitende Resource bei Label-Widget */
		    for ( k = 0; k < TransformationSize; k++ )
			if ( strcmp(args[i].name, Transformations[k].from) == 0 ) {
			    arg.value = args[i].value;
			    arg.name = Transformations[k].to;
			    XtGetValues(w->combobox.LabelCtrl, 
			                (ArgList) &arg, 1);
			    break;
			}
		    break;
        case RWIGNORE:
            ;
		} /* case read mode */
	    } /* if entry found */
	} /* for every mirrored entry */
    } /* for every Arg */
} /* GetValuesAlmost */

/* --------------------------------------------------------------------
 * Zeige beziehungsweise verstecke die Drop-Down-Liste der Combo-Box.
 * Falls die Liste bereits den entsprechenden Zustand hat, geht's
 * sofort zum Aufrufer zurueck.
 * Parameter:
 *   w		    Her Royal Majesty ComboBox
 *   Show	    True, falls anzuzeigen, andernfalls False
 */
static void ShowHideDropDownList(XmComboBoxWidget w, XEvent *event, 
                                 Boolean Show)
{
    XmComboBoxDropDownCallbackStruct info;
    
    if ( w->combobox.StaticList || 
         (Show == w->combobox.ListVisible) ) return;
    w->combobox.ListVisible = Show;
    if ( Show ) { /* Klapp' die Liste aus! */
	DoDropDownLayout(w);
	info.reason = XmCR_SHOW_LIST;
	info.event  = event;
	XtCallCallbacks((Widget) w, XmNdropDownCallback, 
	                (XtPointer) &info);
	XDefineCursor(XtDisplay(w->combobox.PopupShell), 
	                XtWindow(w->combobox.PopupShell), 
			w->combobox.ArrowCursor); 
	XtPopup(w->combobox.PopupShell, XtGrabNone);
	XtVaSetValues(w->combobox.ArrowCtrl, 
	              XmNarrowDirection, XmARROW_UP, NULL);
    } else {      /* Klapp' die Liste wieder ein... */
	XtPopdown(w->combobox.PopupShell);
	XtVaSetValues(w->combobox.ArrowCtrl, 
	              XmNarrowDirection, XmARROW_DOWN, NULL);
	info.reason = XmCR_HIDE_LIST;
	info.event  = event;
	XtCallCallbacks((Widget) w, XmNdropDownCallback, 
	                (XtPointer) &info);
    }
} /* ShowHideDropDownList */

/* --------------------------------------------------------------------
 * Hier laeuft die Nachricht auf, dass der Pfeil ausgeloest wurde...
 * (Daraufhin sollte die Liste aus- oder eingeklappt werden)
 * ...oder dass der Benutzer da draussen auf der anderen Seite der
 * Mattscheibe den Pfeil bereits anklickte ohne aber bereits losge-
 * gelassen zu haben. Bereits hier bekommt das Eingabefeld den Fokus
 * vor den Latz geknallt, denn sonst kann es passieren, dass zwar die
 * Liste ausgeklappt ist, aber das Eingabefeld noch keinen Tastatur-
 * fokus erhalten hat. Das sollte aber nicht so sein, denn es ist dann
 * keine konsequente Tastaturbedienung.
 */
static void ArrowCallback(Widget w, XtPointer pClientData, 
                          XmAnyCallbackStruct *info)
{
    XmComboBoxWidget cbw = (XmComboBoxWidget) XtParent(w);
    
    switch ( info->reason ) {
	case XmCR_ARM:
	    LOG("ArrowCallback: XmCR_ARM\n");
	    XmProcessTraversal(cbw->combobox.EditCtrl, XmTRAVERSE_CURRENT);
	    if ( cbw->combobox.TwmHandlingOn && cbw->combobox.ListVisible )
	        cbw->combobox.IgnoreFocusOut = True;
	    break;
	case XmCR_ACTIVATE:
	    XmProcessTraversal(cbw->combobox.EditCtrl, XmTRAVERSE_CURRENT);
	    ShowHideDropDownList(cbw, info->event, 
	                         (Boolean)(!cbw->combobox.ListVisible));
	    break;
    }
} /* ArrowCallback */

/* --------------------------------------------------------------------
 * Diese Benachrichtigung moechte uns nur mitteilen, dass wir soeben
 * den Fokus verloren haben (Ohhhh!) Sollte allerdings der Fokus nur
 * aus dem Grunde perdue sein, dass der Anwender den Mauszeiger ausser-
 * halb des Applikationsfensters plaziert hat, so koennen wir diese
 * Nachricht uebergehen. Erst wenn der Fokus an ein anderes Widget in
 * unserer Applikation verlorenging, muessen wir auf diese Information
 * reagieren.
 * Und jetzt zu noch einem total beknackten Problem - alles nur wegen
 * Motif und den diversen Window-Managern (bspw. olwm)... Leider kommt
 * beim FocusOut kein richtiger Hinweis auf den tatsaechlichen Event,
 * der dieses Callback ausloeste -- warum liefert denn dann Motif ueber-
 * haupt noch den Event???? Und ueberhauupt, die Geschichte mit dem
 * Fokus ist schon der reinste Horror. Aktueller Ausweg: wenn wir die
 * Benachrichtigung ueber den Focusabgang bekommen, registrieren wir
 * eine Work-Prozedur, die, sobald der Rechner wieder Luft hat, auf-
 * gerufen wird. Sie kann dann nachschauen, ob nicht inzwischen die
 * OverrideShell den Focus bekahm. Wenn ja, koennen wir den FocusOut
 * uebergehen, ansonsten muessen wir ihn beruecksichtigen.
 * -- Ist das eine ^@#$^*(#$^&! (Meine gute Erziehung hindert mich
 * daran, diesen Begriff hier zu nennen.)
 */
static Boolean DelayedFocusOutWorkProc(XtPointer pClientData)
{
    XmComboBoxWidget cbw = (XmComboBoxWidget) pClientData;
    LOG2("DelayedFocusOutWorkProc: IgnoreFocusOut: %s\n", 
         cbw->combobox.IgnoreFocusOut ? "True" : "False");
    if ( !cbw->combobox.IgnoreFocusOut )
        ShowHideDropDownList(cbw, &(cbw->combobox.xevent), False);
    cbw->combobox.IgnoreFocusOut  = False;
    cbw->combobox.PendingFocusOut = False;
    return True; /* diese Routine wird nicht mehr benoetigt. */
} /* DelayedFocusOutWorkProc */

static void EditFocusCallback(Widget w, XtPointer pClientData, 
                              XmAnyCallbackStruct *info)
{
    XmComboBoxWidget cbw = (XmComboBoxWidget) XtParent(w);

    if ( cbw->combobox.StaticList ) return;
        
    if ( info->reason == XmCR_LOSING_FOCUS ) {
        LOG2("EditFocusCallback: PendingFocusOut: %s, ", 
	     cbw->combobox.PendingFocusOut ? "True" : "False");
	LOG3("mode: %i, detail: %i, ", (int)info->event->xcrossing.mode,
	                               (int)info->event->xcrossing.detail);
	LOG2("PendingOverrideInOut: %s\n",
	     cbw->combobox.PendingOverrideInOut ? "True" : "False");
        if ( !cbw->combobox.PendingFocusOut &&
             !cbw->combobox.PendingOverrideInOut ) {
	    /* Normalerweise duerfen aber keine NULL-Events hier
	     * vorbeikommen...aber man weiss ja nie so genau und
	     * sicher ist sicher. Defensiv programmieren!
	     */
	    if ( info->event )
	        cbw->combobox.xevent = *info->event;
            cbw->combobox.WorkProcID = XtAppAddWorkProc(
	                     XtWidgetToApplicationContext((Widget) cbw),
                             (XtWorkProc) DelayedFocusOutWorkProc,
                             (XtPointer) cbw);
            cbw->combobox.PendingFocusOut = True;
        }
        cbw->combobox.PendingOverrideInOut = False;
    }
} /* EditFocusCallback */

/* --------------------------------------------------------------------
 * Hier wird der angegebene Eintrag in der Listbox der Combo-Box
 * markiert und zudem in den sichtbaren Bereich gerollt, sollte er
 * sich ausserhalb des dargestellten Bereichs der Liste befinden.
 * Parameter:
 *   w		    Die Combo-Box (ueblicher Parameter)
 *   Index	    Index des neu zu markierenden Eintrages.
 *   Notify	    Schickt Mitteilung via Callback
 * Ergebnis:
 *   Index des markierten Eintrages oder 0, falls die Listbox leer
 *   war und deshalb auch kein Eintrag markiert werden konnte.
 */
static int SetSelectionPos(XmComboBoxWidget w, int Index, Boolean Notify)
{
    Widget ListBox = w->combobox.ListCtrl;
    int            ItemCount;      /* Anzahl Eintraege in Listbox   */
    int            TopItem, VisibleItems;
     
    XtVaGetValues(ListBox, XmNitemCount,        &ItemCount, 
			   XmNtopItemPosition,  &TopItem, 
			   XmNvisibleItemCount, &VisibleItems,
	                   NULL);
    if ( Index < 1         ) Index = 1;
    if ( Index > ItemCount ) Index = ItemCount;
    if ( Index != 0 && ItemCount != 0 ) {
	if ( Index < TopItem )
	    XmListSetPos(ListBox, Index);
	if ( Index >= TopItem + VisibleItems )
	    XmListSetBottomPos(ListBox, Index);
	XmListSelectPos(ListBox, Index, Notify);
	return Index;
    } else
	return 0;
} /* SetSelectionPos */

/* --------------------------------------------------------------------
 * Diese Routine kuemmert sich darum, denjenigen Eintrag aus der List-
 * box mit der angegebenen Nummer herauszufischen und an die Eingabe-
 * zeile zu uebergeben. Dabei wird der Index auf den Eintrag auto-
 * matisch auf den zulaessigen Bereich begrenzt. Zugleich wird auch
 * noch der angegebene Eintrag in der Listbox markiert.
 */
static void TransferToEditCtrl(XmComboBoxWidget w, int SelectionIndex, 
                               Boolean MayWipeOut)
{
    Widget ListBox = w->combobox.ListCtrl;
    XmStringTable  Items;
    char           *pItemText;
    
    XtVaGetValues(ListBox, XmNitems, &Items, NULL);
    
    if ( MayWipeOut &&
         (SelectionIndex == w->combobox.LastSelection) &&
         (w->combobox.SelectionPolicy == XmSINGLE_SELECT) ) {
	SelectionIndex = 0;
    }
    
    if ( (SelectionIndex == 0) && 
         (w->combobox.SelectionPolicy == XmSINGLE_SELECT) ) {
	XmListDeselectAllItems(w->combobox.ListCtrl);
	w->combobox.PassVerification = True;
	XmTextFieldSetString(w->combobox.EditCtrl, "");
    } else {
	SelectionIndex = SetSelectionPos(w, SelectionIndex, False);
	if ( SelectionIndex > 0 ) {
	    XmStringGetLtoR(Items[SelectionIndex-1], 
			    XmSTRING_DEFAULT_CHARSET, &pItemText);
	    w->combobox.PassVerification = True;
	    XmTextFieldSetString(w->combobox.EditCtrl, pItemText);
	    XtFree(pItemText);
	}
    }
    w->combobox.LastSelection = SelectionIndex;
} /* TransferToEditCtrl */

/* --------------------------------------------------------------------
 * Alle registrierten Callbacks bei Anwahl eines neuen Eintrages in
 * der Listbox aktivieren.
 */
static void CallSelectionCBL(XmComboBoxWidget w, XEvent *Event)
{
    int index;
    
    index  = XmComboBoxGetSelectedPos((Widget) w);
    /*
     * Wenn momentan KEIN Eintrag selektiert ist, dann rufe den neuen
     * XmNunselectionCallback auf!
     */
    if ( index == 0 ) {
	XmComboBoxUnselectionCallbackStruct info;
	
	info.reason = XmCR_UNSELECT;
	info.event  = Event;
	XtCallCallbacks((Widget) w, XmNunselectionCallback, (XtPointer) &info);
    } else {
    /*
     * Ansonsten den ueblichen SelectionCallback!
     */
	XmComboBoxSelectionCallbackStruct info;
	XmStringTable                     Items;

	info.reason = w->combobox.SelectionPolicy == XmSINGLE_SELECT ? 
			    XmCR_SINGLE_SELECT : XmCR_BROWSE_SELECT;
	info.event  = Event;
	info.index  = index;
	XtVaGetValues(w->combobox.ListCtrl, XmNitems, &Items, NULL);
	info.value  = Items[info.index-1];
	XtCallCallbacks((Widget) w, XmNselectionCallback, (XtPointer) &info);
    }
} /* CallSelectionCBL */

/* --------------------------------------------------------------------
 * Hier laeuft das Tastatur-Management fuer die ComboBox zusammen.
 * ACHTUNG: Der 'w'-Parameter wird nur benoetigt, um das eigentliche
 * ComboBox-Widget zu ermitteln. Er muss daher die ID eines direkten
 * Kinds der ComboBox enthalten!
 */
static void CBoxManager(Widget w, XEvent *Event, String *params, 
                        Cardinal *num_params)
{
    XmComboBoxWidget cbw;
    Widget           ListBox;
    int              *SelectionList;
    int              SelectionCount;
    int              SelectionIndex; /* Wer denn nun markiert wird... */
    int              ItemCount;      /* Anzahl Eintraege in Listbox   */
    int		     VisibleItems;   /* Hoehe der Liste in Eintraegen */
    char             opt;
    
    /*
     * Nur wenn eine der Translationen page-up und page-down direkt im
     * Listenfeld ausgeloest wurden, wird auch als "w" die Liste ueber-
     * geben. Bei allen anderen Faellen ist dieses zumeist das TextField.
     */
    if ( XtClass(w) == xmListWidgetClass )
        cbw = (XmComboBoxWidget) XtParent(XtParent(w));
    else
        cbw = (XmComboBoxWidget) XtParent(w);
    ListBox = cbw->combobox.ListCtrl;
    
    switch ( *(params[0]) ) {
/* --------------------------------------------------------------------
 * Klappe die Liste auf Wunsch des Benutzers aus oder wieder ein.
 */
    case 's': /* show-hide-list */
	ShowHideDropDownList(cbw, Event, 
	                     (Boolean)(!cbw->combobox.ListVisible));
	break;
    case 'h': /* hide-list */
	ShowHideDropDownList(cbw, Event, False);
	break;
/* --------------------------------------------------------------------
 * Hier werden die Bewegungen in der Listbox behandelt.
 */
    case 'u': /* up                */
    case 'd': /* down              */
    case 't': /* top               */
    case 'b': /* bottom            */
    case 'p': /* page-up/page-down */
	opt = *(params[0]);
	XtVaGetValues(ListBox, XmNitemCount,        &ItemCount, 
	                       XmNvisibleItemCount, &VisibleItems, NULL);
	if ( XmListGetSelectedPos(ListBox,
	                          &SelectionList, &SelectionCount) ) {
	    SelectionIndex = *SelectionList;
	    XtFree((char *)SelectionList);
	    switch ( opt ) {
		case 'u': SelectionIndex--;		  break;
		case 'd': SelectionIndex++;		  break;
		case 't': SelectionIndex = 1;		  break;
		case 'b': SelectionIndex = ItemCount;	  break;
		case 'p': if ( *(params[0]+5) == 'u' )
		              SelectionIndex -= VisibleItems;
		          else
		              SelectionIndex += VisibleItems;
		          break;
	    }
	} else { /* momentan noch kein Eintrag in der Liste ausgewaehlt */
	    if ( opt == 'b' ) SelectionIndex = ItemCount;
	    else              SelectionIndex = 1; /* nun ersten Eintrag nehmen */
	}
	TransferToEditCtrl(cbw, SelectionIndex, False);
	CallSelectionCBL(cbw, Event);
	break;
/* --------------------------------------------------------------------
 * Der Benutzer hat die Eingabetaste gedrueckt oder einen Eintrag in
 * der Listbox angeklickt.
 */
    case 'a': /* Return = activate */
    case 'S': /* Selection */
	if ( !cbw->combobox.StaticList && !cbw->combobox.ListVisible ) break;
	XtVaGetValues(ListBox, XmNitemCount, &ItemCount, NULL);
	if ( ItemCount == 0 ) break;
	if ( XmListGetSelectedPos(ListBox,
	                          &SelectionList, &SelectionCount) ) {
	    SelectionIndex = *SelectionList;
	    XtFree((char *)SelectionList);
	} else {
	    if ( cbw->combobox.SelectionPolicy != XmSINGLE_SELECT )
		SelectionIndex = 1;
	    else
		SelectionIndex = 0;
	}
	
	TransferToEditCtrl(cbw, SelectionIndex, 
	    *(params[0]) == 'S');
	CallSelectionCBL(cbw, Event);
	ShowHideDropDownList(cbw, Event, (Boolean)
	                      (*(params[0]) == 'S' ? True : False));
	break;
/* --------------------------------------------------------------------
 * Der Benutzer hat die ESC-Taste gedrueckt. Ist die Liste zu diesem
 * Zeitpunkt noch ausgeklappt, so wird sie einfach nur eingeklappt und
 * weiter passiert nichts. Ist die Liste jedoch eingeklappt, so wird
 * das ESC an die normale Action-Routine des Eingabefeldes weiter-
 * gegeben, damit damit bspw. Dialog u.a. abgebrochen werden koennen.
 */
    case 'c': /* Cancel */
	if ( cbw->combobox.ListVisible )
	    ShowHideDropDownList(cbw, Event, False);
	else
	    XtCallActionProc(cbw->combobox.EditCtrl, 
	                     "process-cancel", Event, NULL, 0);
	break;
/* --------------------------------------------------------------------
 * Wenn es erlaubt ist, dass auch einmal kein Eintrag in einer ComboBox
 * mit nicht editierbarem Eingabefeld ausgewaehlt ist, dann darf der
 * Anwender mittels osfDelete den aktuellen Eintrag deselektieren.
 */
    case 'w': /* wipe */
	if ( cbw->combobox.SelectionPolicy == XmSINGLE_SELECT ) {
	    TransferToEditCtrl(cbw, 0, True);
	    CallSelectionCBL(cbw, Event);
	}
	break;
/* --------------------------------------------------------------------
 * Dummy-Operation
 */
    case 'n': /* no-operation */
        break;
    }
} /* CBoxManager */

/* --------------------------------------------------------------------
 * Der Benutzer hat einen Eintrag in der Listbox angeklickt. Der Ein-
 * fachkeit halber wird einfach nur ein Druecken der Eingabetaste
 * simuliert.
 */
static void ListSelectionCallback(Widget w, XtPointer pClientData, 
                                  XmAnyCallbackStruct *info)
{
    String           paramsMouse[1] = { "a" }, paramsKeyboard[1] = { "S" };
    Cardinal         NumParams = 1;
    XmComboBoxWidget cbw = (XmComboBoxWidget) pClientData;
/* 
 * Wurde der Event durch die Tastatur oder einen Mausklick
 * ausgeloest? Wenn es ein Mausklick auf das Listenfeld war und es
 * sich um ein staendig angezeigtes Listenfeld einer nicht editierbaren
 * ComboBox handelt, dann gib' dem Eingabefeld den Tastaturfokus.
 */
    if ( info->event == NULL )
	CBoxManager(cbw->combobox.EditCtrl, info->event, 
	            paramsKeyboard, &NumParams);
    else {
	CBoxManager(cbw->combobox.EditCtrl, info->event, 
	            paramsMouse, &NumParams);
	if ( !cbw->combobox.StaticList ||
	     (cbw->combobox.StaticList && !cbw->combobox.Editable) )
	    XmProcessTraversal(cbw->combobox.EditCtrl, 
	                       XmTRAVERSE_CURRENT);
    }
} /* ListSelectionCallback */

/* --------------------------------------------------------------------
 * Nach einem Doppelklick innerhalb des Listenfelds wird diese Routine
 * aufgerufen. Zunaechst einmal wird ganz normal wie bei einem ein-
 * fachen Anklicken vorgegangen, danach aber noch der ein spezieller
 * Callback aufgerufen.
 */
static void ListDefaultActionCallback(Widget w, XtPointer pClientData, 
                                      XmAnyCallbackStruct *OldInfo)
{
    XmComboBoxWidget                      cbw = (XmComboBoxWidget) pClientData;
    XmComboBoxDefaultActionCallbackStruct info;
    XmStringTable                         Items;
    
    ListSelectionCallback(w, pClientData, OldInfo);
    info.reason = XmCR_DEFAULT_ACTION;
    info.event  = OldInfo->event;
    info.index  = XmComboBoxGetSelectedPos((Widget) cbw);
    XtVaGetValues(cbw->combobox.ListCtrl, XmNitems, &Items, NULL);
    info.value  = Items[info.index-1];
    XtCallCallbacks((Widget) cbw, XmNdefaultActionCallback, (XtPointer) &info);
} /* ListDefaultActionCallback */


/* --------------------------------------------------------------------
 * Ohweh!! Diese Routine wurde erforderlich, um XmNautomaticSelection
 * zu unterstuetzen. Denn wenn der Benutzer in der Liste herumsucht und
 * automaticSelection 'True' ist, kommt kein Callback-Aufruf mehr, wenn
 * die Maustaste losgelassen wird. Und damit wuessten wir sonst nicht, 
 * wann die Liste einzuklappen ist! Irgendwie wird das alles mit der
 * Zeit immer konfuser und aufwendiger. Wenn das Chaos gequantelt
 * sein sollte, dann muss das Chaos-Quant (sog. 'Chaotonen') aber jede
 * Menge Chaos transportieren!!!
 */
static void Button1UpInList(Widget w, XtPointer pClientData, 
                           XEvent *Event, Boolean *ContDispatch)
{
    XmComboBoxWidget cbw = (XmComboBoxWidget) pClientData;

    if ( Event->xbutton.button == Button1 ) {
	if ( cbw->combobox.AutomaticSelection )
	    ShowHideDropDownList(cbw, Event, False);
    }
} /* Button1UpInList */

/* --------------------------------------------------------------------
 * Sobald sich irgendetwas im Eingabefeld veraenderte, kommt das
 * TextField-Widget zuerst zu uns gelaufen, um sich unser Okay zu
 * holen. Bei einer nicht editierbaren Combo-Box wird hierueber die
 * Schnellsuche realisiert.
 */
static void EditVerifyCallback(Widget w, XtPointer pClientData, 
                               XmTextVerifyCallbackStruct *info)
{
    XmComboBoxWidget cbw = (XmComboBoxWidget) XtParent(w);

/* 
 * Sollte gerade dem Eingabefeld Text aus der Listbox einverleibt
 * werden, so duerfen wir hier darueber natuerlich nicht meckern, 
 * sondern unser <<ok>> dazu geben. (D.h. in diesem Fall haben wir
 * kein Recht, zu intervenieren.)
 */
    if ( cbw->combobox.PassVerification ) {
	cbw->combobox.PassVerification = False;
	info->doit = True;
	return;
    }
/* 
 * Ist es eine Combo-Box, in die kein Text vom Benutzer eingegeben
 * werden kann, so wird bei der Eingabe von Zeichen die Schnellsuche
 * ausgeloest.
 */
    if ( !cbw->combobox.Editable ) {
	Widget         ListBox = cbw->combobox.ListCtrl;
	char           WarpCharLow, WarpCharHigh;
	XmString       Item;
	XmStringTable  Items;
	int            *SelectionList;
	int            SelectionCount;
	int            i, ItemCount, Start;
	char           *pItem;
	Boolean        Ignore;
	
	info->doit = False;
	if ( (info->text         == NULL ) ||
	     (info->text->length == 0    ) ) return; /* Hoppala! */
/* 
 * Nun aus dem Zeichen einen String (Motif-like) basteln und
 * in der Listbox danach auf die Suche gehen.
 */
        if ( info->text->length > 1 ) {
            /* Das ist nun endweder ein normaler Paste, oder aber
             * das Ergebnis einer Drag'n'Drop-Operation.
             */
            Item = XmStringCreateSimple(info->text->ptr);
            XmComboBoxSelectItem((Widget) cbw, Item, True);
            XmStringFree(Item);
        } else {
            /* Ansonsten soll nur eine Schnellsuche ausgefuehrt
             * werden, der entsprechende Buchstabe ist das einzige 
             * Zeichen im dem Callback uebergebenen Text.
             */
	    WarpCharLow  = tolower(*(info->text->ptr));
	    WarpCharHigh = toupper(WarpCharLow);

            XtVaGetValues(ListBox, XmNitemCount, &ItemCount, 
    			           XmNitems,     &Items,  
    	                           NULL);
            if ( ItemCount < 1 ) return;
    	    /* Ermittele, wo's los geht mit der Suche... */
    	    if ( XmListGetSelectedPos(ListBox, 
    	                              &SelectionList, &SelectionCount) ) {
    	        Start = *SelectionList; i = Start + 1;
    	        XtFree((char *)SelectionList);
    	    } else i = Start = 1;
    	
    	    if ( i > ItemCount ) i = 1;
    	    Ignore = True;
    	    while ( i != Start || Ignore ) {
    	        Ignore = False;
    	        XmStringGetLtoR(Items[i-1], XmSTRING_DEFAULT_CHARSET, 
    	                        &pItem);
    	        if ( (strchr(pItem, WarpCharLow ) == pItem) ||
    	             (strchr(pItem, WarpCharHigh) == pItem) ) { 
    	            XtFree(pItem);
    		    TransferToEditCtrl(cbw, i, False);
    		    CallSelectionCBL(cbw, info->event);
    		    break;
    	        }
    	        XtFree(pItem);
    	        if ( ++i > ItemCount ) i = 1;
    	    }
    	}
    } else {
/*
 * Wenn das Eingabefeld editierbar ist, dann fragen wir ueber die Callbacks
 * nach, ob es genehm ist, den neuen Text einzufuegen.
 */
	XtCallCallbacks((Widget) cbw, XmNmodifyVerifyCallback, 
	                (XtPointer) info);
    }
} /* EditVerifyCallback */

/* --------------------------------------------------------------------
 * Dieser Callback wird immer dann aufgerufen, wenn in einer ComboBox
 * mit einem veraenderlichem Eingabefeld der Eingabetext veraendert
 * wurde. In diesem Fall suchen wir hier nach einem passenden gleich-
 * lautenden Eintrag. Wenn wir einen finden, heben wir ihn in der Liste
 * sogleich hervor, ansonsten ist kein Eintrag hervorgehoben.
 */
static void EditChangedCallback(Widget w, XtPointer pClientDate, 
                                XmAnyCallbackStruct *info)
{
    XmComboBoxWidget cbw = (XmComboBoxWidget) XtParent(w);
    XmStringTable    Items;
    int              ItemCount, i;
    XmString         EditStr;
    String           EditLine;
    
    /*
     * Zuerst nach einem passenden Eintrag zum Eingabefeld in der Liste
     * suchen...
     */
    XtVaGetValues(cbw->combobox.EditCtrl, XmNvalue, &EditLine, NULL);
    XtVaGetValues(cbw->combobox.ListCtrl, 
                  XmNitemCount, &ItemCount, 
		  XmNitems,     &Items, 
		  NULL);
    EditStr = XmStringCreateSimple(EditLine);
    XtVaSetValues(cbw->combobox.ListCtrl, XmNselectedItemCount, 0, NULL);
    if ( ItemCount < 1 ) return;
    for ( i = 0; i < ItemCount; i++ )
	if ( XmStringCompare(Items[i], EditStr) ) {
	    SetSelectionPos(cbw, i+1, False);
	    break;
	}
    XmStringFree(EditStr);
    /*
     * Zum Abschluss noch den Callback aufrufen...
     */
    XtCallCallbacks((Widget) cbw, XmNvalueChangedCallback, (XtPointer) info);
} /* EditChangedCallback */

/* --------------------------------------------------------------------
 * Dieser Callback wird immer dann aufgerufen, wenn in einer ComboBox
 * mit einem veraenderlichem Eingabefeld der Cursor bewegt wurde.
 * Dieser Callback ist nur fuer echte Fans von Callbacks da...
 */
static void MotionVerifyCallback(Widget w, XtPointer pClientDate, 
                                 XmTextVerifyCallbackStruct *info)
{
    XmComboBoxWidget cbw = (XmComboBoxWidget) XtParent(w);

    XtCallCallbacks((Widget) cbw, XmNmotionVerifyCallback, (XtPointer) info);
} /* MotionVerifyCallback */

/* --------------------------------------------------------------------
 * Bastele einen vollstaendigen Namens- und Klassenbezeichner anhand
 * des angegebenen Widgets zusammen.
 */
static void MakeNameAndClass(Widget w, char *NameBuff, char *ClassBuff)
{
    Widget Parent = XtParent(w);
    
    if ( Parent ) MakeNameAndClass(Parent, NameBuff, ClassBuff);
    if ( XtIsSubclass(w, applicationShellWidgetClass) ) {
	/* Wenn wir ganz oben angekommen sind, holen wir uns den
	 * Namen und die Klasse der Applikation selbst und nicht die
	 * des Widgets.
	 */
	String AppName, AppClass;
	XtGetApplicationNameAndClass(
	    XtDisplayOfObject(w), &AppName, &AppClass);
	strcpy(NameBuff, AppName);
	strcpy(ClassBuff, AppClass);
    } else {
	/* Ansonsten sind wir noch mitten irgendwo in der Hierarchie
	 * und besorgen uns den Namen und die Klasse dieses Widgets
	 */
	strcat(NameBuff,  "."); 
	strcat(NameBuff,  XtName(w));
	strcat(ClassBuff, "."); 
	strcat(ClassBuff, ((CoreClassRec *) XtClass(w))->core_class.class_name);
    }
} /* MakeNameAndClass */

/* --------------------------------------------------------------------
 * Eine einzelne Resource aus der Datenbank herausholen. Diese Resource
 * kommt im Allgemeinen immer als String zurueck und muss daher erst
 * noch in das gewuenschte Zielformat konvertiert werden.
 */
static Boolean FetchResource(Widget w, 
                             char *FullName, char *FullClass, 
                             char *RscName, char *RscClass, 
			     XrmValue *RscValue, 
			     String   *RepresentationType)
{
    Boolean ok;
    char *EndOfName  = FullName  + strlen(FullName);
    char *EndOfClass = FullClass + strlen(FullClass);
    
    strcat(FullName,  "."); strcat(FullName,  RscName);
    strcat(FullClass, "."); strcat(FullClass, RscClass);
    ok = XrmGetResource(
	XtDatabase(XtDisplayOfObject(w)), 
	FullName, FullClass, RepresentationType, RscValue);
    /* Wieder den alten Namens- und Klassenrumpf herstellen */
    *EndOfName = 0; *EndOfClass = 0;
    return ok;
} /* FetchResource */

/* --------------------------------------------------------------------
 * Nun folgen diejenigen Routinen, mit denen die Konvertierung in das
 * gewuenschte Zielformat einer Resource moeglich ist.
 * Verfuegbar:
 *   String --> Int
 *   String --> Short
 *   String XmPIXMAP / XmSTRING --> unsigned char
 *   String --> Dimension
 *   String --> XmString
 *   String --> XmStringTable
 *   String --> XmFontList
 *   String --> Pixmap (genauer: Bitmap)
 *   String --> String
 *   String --> KeySym
 */
static Boolean FetchIntResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass, 
			        int *pInt)
{
    XrmValue RscValue, RscDest;
    String   RepresentationType;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	RscDest.size = sizeof(int);
	RscDest.addr = (caddr_t) pInt;
	if ( XtConvertAndStore(w, RepresentationType, &RscValue, 
	                       XtRInt, &RscDest) )
	    return True;
    }
    return False;
} /* FetchIntResource */

static Boolean FetchShortResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass, 
			        short *pShort)
{
    XrmValue RscValue, RscDest;
    String   RepresentationType;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	RscDest.size = sizeof(short);
	RscDest.addr = (caddr_t) pShort;
	if ( XtConvertAndStore(w, RepresentationType, &RscValue, 
	                       XtRShort, &RscDest) )
	    return True;
    }
    return False;
} /* FetchShortResource */

static Boolean FetchLabelTypeResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass, 
			        unsigned char *pUChar)
{
    XrmValue RscValue;
    String   RepresentationType;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	if ( strcasecmp((char *) RscValue.addr, "XmPIXMAP") == 0 )
	    *pUChar = XmPIXMAP;
	else
	    *pUChar = XmSTRING;
	return True;
   }
    return False;
} /* FetchLabelTypeResource */

static Boolean FetchDimensionResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass, 
			        Dimension *pDimension)
{
    XrmValue RscValue, RscDest;
    String   RepresentationType;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	RscDest.size = sizeof(Dimension);
	RscDest.addr = (caddr_t) pDimension;
	if ( XtConvertAndStore(w, RepresentationType, &RscValue, 
	                       XtRDimension, &RscDest) )
	    return True;
    }
    return False;
} /* FetchDimensionResource */

static Boolean FetchStringResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass, 
			        String *pString)
{
    XrmValue RscValue;
    String   RepresentationType;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	*pString = (char *) RscValue.addr;
	return True;
    }
    return False;
} /* FetchStringResource */

static Boolean FetchKeySymResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass, 
			        KeySym *pKeySym)
{
    XrmValue RscValue, RscDest;
    String   RepresentationType;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	RscDest.size = sizeof(KeySym);
	RscDest.addr = (caddr_t) pKeySym;
	if ( XtConvertAndStore(w, RepresentationType, &RscValue, 
	                       XmRKeySym, &RscDest) )
	    return True;
    }
    return False;
} /* FetchKeySymResource */

static Boolean FetchXmStringResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass, 
			        XmString *pString)
{
    XrmValue RscValue;
    String   RepresentationType;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	*pString = XmCvtCTToXmString((char *) RscValue.addr);
	return True;
    }
    return False;
} /* FetchXmStringResource */

static Boolean FetchXmStringTableResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass, 
			        XmStringTable *pStringTable, 
				int *pTableSize)
{
    XrmValue RscValue;
    String   RepresentationType;
    String   TmpList, p, pStart;
    int      Entries, Entry;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	/* 
	 * Zuerst eine Kopie erzeugen und dann daraus die Liste
	 * zusammenbasteln.
	 */
	TmpList = XtNewString((String)RscValue.addr);
	if ( TmpList == NULL ) return False;
	if ( *TmpList == 0 ) { XtFree(TmpList); return False; }
	/* Ermittele, wieviele Eintrage in der Liste sind und
	 * erstelle dann daraus die Liste.
	 */
	Entries = 1; p = TmpList;
	while ( *p )
	    if ( *p++ == ',' ) ++Entries;
	*pStringTable = (XmStringTable) 
	    XtMalloc(Entries * sizeof(XmString));
	
	p = TmpList;
	for ( Entry = 0; Entry < Entries; ++Entry ) {
	    pStart = p;
	    while ( (*p != 0) && (*p != ',') ) ++p;
	    *p++ = 0;
	    (*pStringTable)[Entry] = (XmString)
	        XmStringCreateSimple(pStart);
	}
	/* Hier geht ausnahmsweise einmal Rueckgabe vor
	 * Entschaedigung... hey, das war doch nur ein
	 * (wenn auch ziemlich miserabler) Scherz
	 */
	XtFree(TmpList);
	*pTableSize = Entries;
	return True;
    }
    return False;
} /* FetchXmStringTableResource */

static Boolean FetchXmFontListResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass, 
			        XmFontList *pFontList)
{
    XrmValue RscValue, RscDest;
    String   RepresentationType;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	RscDest.size = sizeof(XmFontList);
	RscDest.addr = (caddr_t) pFontList;
	if ( XtConvertAndStore(w, RepresentationType, &RscValue, 
	                       XmRFontList, &RscDest) )
	    return True;
    }
    return False;
} /* FetchXmFontListResource */

static Boolean FetchPixmapResource(Widget w, 
                                char *FullName, char *FullClass, 
                                char *RscName, char *RscClass,
				Pixmap *pPixmap)
{
    XrmValue RscValue, RscDest;
    String   RepresentationType;
    
    if ( FetchResource(w, FullName, FullClass, 
                       RscName, RscClass, 
		       &RscValue, &RepresentationType) ) {
	RscDest.size = sizeof(Pixmap);
	RscDest.addr = (caddr_t) pPixmap;
	if ( XtConvertAndStore(w, RepresentationType, &RscValue, 
	                       XtRBitmap, &RscDest) )
	    return True;
    }
    return False;
} /* FetchPixmapResource */

/* --------------------------------------------------------------------
 * Waehrend der Initialisierung alle gespiegelten Resourcen, fuer die
 * Eintraege in der Resourcen-Datenbank existieren an die passenden
 * Kinder-Widgets weiterleiten. Der Trick an der Sache: wir setzen
 * die betroffenen Resourcen vie XtSetValues mit uns selbst als Ziel.
 * Dadurch bekommt SetValues die Arbeit aufgehalst, die Resourcen den
 * richtigen Kindern zuzuordnen...
 */

#define RInt		0
#define RShort		1
#define RLType		2
#define RDimension	3	
#define RXmString	4
#define RPixmap		5
#define RXmFontList	6
#define RKeySym		7
#define RString		8
#define RXmStringTable	9
#define RXmItemCount	10


typedef struct
{
    String Name, Class;

    int Converter;
    
} RESOURCEMIRROR;

static RESOURCEMIRROR ResourceMirror[] = {
    { XmNblinkRate,		 XmCBlinkRate,		    RInt,          }, 
    { XmNcolumns,		 XmCColumns,		    RShort,        }, 
    { XmNmaxLength,		 XmCMaxLength,		    RInt,          }, 
    { XmNmarginHeight,		 XmCMarginHeight,	    RDimension     }, 
    { XmNmarginWidth,		 XmCMarginWidth,	    RDimension     },
    { XmNselectThreshold,	 XmCSelectThreshold,	    RInt           }, 
     
    { XmNlistMarginHeight,	 XmCListMarginHeight,	    RDimension     }, 
    { XmNlistMarginWidth,	 XmCListMarginWidth,	    RDimension     }, 
    { XmNlistSpacing,		 XmCListSpacing,	    RDimension     },
    { XmNitems,		         XmCItems,		    RXmStringTable },
    { XmNitemCount,		 XmCItemCount,	    	    RXmItemCount   },
    
    { XmNmnemonic,		 XmCMnemonic,		    RKeySym        }, 
    { XmNmnemonicCharSet,        XmCMnemonicCharSet,        RString        }, 
    { XmNlabelString,		 XmCLabelString,	    RXmString      }, 
    { XmNlabelMarginBottom,	 XmCLabelMarginBottom,	    RDimension     }, 
    { XmNlabelMarginHeight,	 XmCLabelMarginHeight,	    RDimension     }, 
    { XmNlabelMarginLeft,	 XmCLabelMarginLeft,	    RDimension     }, 
    { XmNlabelMarginRight,	 XmCLabelMarginRight,	    RDimension     }, 
    { XmNlabelMarginTop,	 XmCLabelMarginTop,	    RDimension     }, 
    { XmNlabelMarginWidth,	 XmCLabelMarginWidth,	    RDimension     }, 
    { XmNlabelPixmap,		 XmCLabelPixmap,	    RPixmap        },
    { XmNlabelInsensitivePixmap, XmCLabelInsensitivePixmap, RPixmap        }, 
    { XmNlabelType,		 XmCLabelType,		    RLType         }, 
    { XmNlabelFontList,          XmCLabelFontList,	    RXmFontList    }, 
};

static void InitMirrorResources(XmComboBoxWidget w)
{
    char          FullName[1024], FullClass[1024];
    int           AInt, TableSize;
    short         AShort;
    unsigned char AUChar;
    Dimension     ADimension;
    XmString      AXmString;
    XmStringTable AStringTable;
    Pixmap        APixmap;
    XmFontList    AFontList;
    String        AString;
    KeySym        AKeySym;
    int           i, size = XtNumber(ResourceMirror);
    
    FullName[0] = 0; FullClass[0] = 0;
    MakeNameAndClass((Widget) w, FullName, FullClass);

    for ( i=0; i < size; i++ ) {
	switch ( ResourceMirror[i].Converter ) {
	    case RInt:
		if ( FetchIntResource((Widget) w, 
			FullName, FullClass, 
			ResourceMirror[i].Name, ResourceMirror[i].Class, 
			&AInt) )
		    XtVaSetValues((Widget) w, ResourceMirror[i].Name, 
		                  AInt, NULL);
		break;
	    case RXmItemCount:
		if ( FetchIntResource((Widget) w, 
			FullName, FullClass, 
			ResourceMirror[i].Name, ResourceMirror[i].Class, 
			&AInt) && ( AInt != 0) )
		    XtVaSetValues((Widget) w, ResourceMirror[i].Name, 
		                  AInt, NULL);
		break;
	    case RShort:
		if ( FetchShortResource((Widget) w, 
			FullName, FullClass, 
			ResourceMirror[i].Name, ResourceMirror[i].Class, 
			&AShort) )
		    XtVaSetValues((Widget) w, ResourceMirror[i].Name, 
		                  AShort, NULL);
		break;
	    case RLType:
		if ( FetchLabelTypeResource((Widget) w, 
			FullName, FullClass, 
			ResourceMirror[i].Name, ResourceMirror[i].Class, 
			&AUChar) )
		    XtVaSetValues((Widget) w, ResourceMirror[i].Name, 
		                  AUChar, NULL);
		break;
	    case RDimension:
		if ( FetchDimensionResource((Widget) w, 
			FullName, FullClass, 
			ResourceMirror[i].Name, ResourceMirror[i].Class, 
			&ADimension) )
		    XtVaSetValues((Widget) w, ResourceMirror[i].Name, 
		                  ADimension, NULL);
		break;
	    case RXmString:
		if ( FetchXmStringResource((Widget) w, 
			FullName, FullClass, 
			ResourceMirror[i].Name, ResourceMirror[i].Class, 
			&AXmString) )
		    XtVaSetValues((Widget) w, ResourceMirror[i].Name, 
		                  AXmString, NULL);
		break;
	    case RXmStringTable:
	        if ( FetchXmStringTableResource((Widget) w,
	                 FullName, FullClass,
	                 ResourceMirror[i].Name, ResourceMirror[i].Class,
	                 &AStringTable, &TableSize) ) {
		    XtVaSetValues((Widget) w, 
		         XmNitems, (XtPointer) AStringTable, 
			 XmNitemCount, TableSize, NULL);
		}
	        break;
	    case RKeySym:
		if ( FetchKeySymResource((Widget) w, 
			FullName, FullClass, 
			ResourceMirror[i].Name, ResourceMirror[i].Class, 
			&AKeySym) )
		    XtVaSetValues((Widget) w, ResourceMirror[i].Name, 
		                  AKeySym, NULL);
		break;
	    case RString:
		if ( FetchStringResource((Widget) w, 
			FullName, FullClass, 
			ResourceMirror[i].Name, ResourceMirror[i].Class, 
			&AString) )
		    XtVaSetValues((Widget) w, ResourceMirror[i].Name, 
		                  AString, NULL);
		break;
	    case RPixmap:
		if ( FetchPixmapResource((Widget) w, 
			FullName, FullClass, 
			ResourceMirror[i].Name, ResourceMirror[i].Class, 
			&APixmap) ) {
		    XtVaSetValues((Widget) w, ResourceMirror[i].Name, 
		                  APixmap, NULL);
		    if ( strcmp(ResourceMirror[i].Name, XmNlabelPixmap) == 0 )
			w->combobox.ConvertBitmapToPixmap = True;
		    else
			w->combobox.ConvertBitmapToPixmapInsensitive = True;
		}
		break;
	    case RXmFontList:
	    	if ( FetchXmFontListResource((Widget) w,
	    	       FullName, FullClass,
	    	       ResourceMirror[i].Name, ResourceMirror[i].Class,
	    	       &AFontList) )
	    	    XtVaSetValues((Widget) w, ResourceMirror[i].Name,
	    	                  AFontList, NULL);
	    	break;
	}
    }
} /* InitMirrorResources */

/* --------------------------------------------------------------------
 * Wandelt ein 1-Bit tiefes Bitmap in ein n-Bit tiefes Pixmap um, dass
 * die gleiche Tiefe besitzt, wie der Bildschirm, auf dem das Pixmap
 * spaeter erscheinen soll.
 */
static Pixmap BitmapToPixmap(XmComboBoxWidget w, 
                           String Resource, GC ColorGC)
{
    Pixmap       LabelPixmap, LabelBitmap;
    Display      *display = XtDisplay(w);
    Window       root;
    int          PixX, PixY;
    unsigned int PixW, PixH, PixBW, PixDepth;

    XtVaGetValues(w->combobox.LabelCtrl, Resource, &LabelBitmap, NULL);
    XGetGeometry(display, LabelBitmap, &root, 
		 &PixX, &PixY, &PixW, &PixH, &PixBW, &PixDepth);
    LabelPixmap = XCreatePixmap(
			display, RootWindowOfScreen(XtScreen(w)), 
			PixW, PixH, 
			(w->combobox.LabelCtrl)->core.depth);
    XCopyPlane(display, LabelBitmap, LabelPixmap, 
	       ColorGC, 0, 0, PixW, PixH, 0, 0, 1);
    XtVaSetValues(w->combobox.LabelCtrl, Resource, LabelPixmap, NULL);
    XFreePixmap(display, LabelBitmap);
    return LabelPixmap;
} /* BitmapToPixmap */

/* --------------------------------------------------------------------
 * Alles initialisieren, sobald das Widget eingerichtet wird. Das sagt
 * sich hier so einfach, ist es aber *definitiv* nicht!!!!
 */
static void Initialize(Widget request, XmComboBoxWidget newW, 
                       ArgList wargs, Cardinal *ArgCount)
{
    Dimension    width, height, dummy;
    Widget       w;
    Arg          args[10];
    int          n = 0;
    
/* 
 * Da zu allem Ueberfluss die einzelnen Instanzen einer XmComboBox
 * auf verschiedenen Displays auftauchen koennen, wird hier:
 * 1. pro Widget ein eigener Cursor erzeugt (benoetigt fuer die Liste)
 * 2. pro Widget (hier = pro Applikation) die benoetigte Action-Routine
 * registiert. Doppelte Registrierung macht dem Toolkit nichts aus, da es
 * dann eine evtl. aeltere Definition loescht.
 */
    XtAppAddActions(XtWidgetToApplicationContext((Widget) newW), 
	                actions, XtNumber(actions));
    
/* Allgemeine Initialisierungen... */
    newW->combobox.ConvertBitmapToPixmap            = False;
    newW->combobox.ConvertBitmapToPixmapInsensitive = False;
    
    newW->combobox.LastSelection                    = 0;
    
    newW->combobox.InInit                           = True;
    
/* 
 * Das folgende Problem mit der Kontrolle, ob sich das Widget absolut auf
 * dem Bildschirm verschoben hat, trifft uns nur, wenn die Liste nicht
 * dauernd auf dem Bildschirm erscheint:
 * Lass' dich benachrichtigen, sobald dieses Widget in irgendeiner
 * Form bewegt wird -- und sei es nur, dass das gesamte Applikations-
 * fenster umhergeschoben wurde. Um die Benachrichtigung ueberhaupt
 * zu erreichen, ist es erforderlich, sich benachrichtigen zu lassen, 
 * sobald die naechste Shell (oder ein Nachkomme) im Widget-Instanzen-
 * Baum verschoben wurde.
 */
    if ( !newW->combobox.StaticList ) {
	w = (Widget) newW;
	while ( !XtIsSubclass(w, shellWidgetClass) )
	    w = XtParent(w);
	newW->combobox.MyNextShell = w;
	XtAddEventHandler(w, 
			  StructureNotifyMask | FocusChangeMask, 
			  False, (XtEventHandler) ShellCallback, 
			  (XtPointer) newW);
    }
 
/* Richte nun alle zu diesem Widget gehoerenden Kinder ein, als da
 * waeren:
 * 1 x editierbares Eingabefeld
 * 1 x ein Pfeil nach unten
 * 1 x ein Schriftfeld
 */
    newW->combobox.EditCtrl = XtVaCreateManagedWidget(
	"edit", xmTextFieldWidgetClass, (Widget) newW,
	XmNverifyBell, False, 
	NULL);
    XtAddCallback(newW->combobox.EditCtrl, 
                  XmNlosingFocusCallback, 
		  (XtCallbackProc) EditFocusCallback, NULL);
    XtAddCallback(newW->combobox.EditCtrl, 
                  XmNmodifyVerifyCallback, 
		  (XtCallbackProc) EditVerifyCallback, NULL);
    XtAddCallback(newW->combobox.EditCtrl, 
                  XmNvalueChangedCallback, 
		  (XtCallbackProc) EditChangedCallback, NULL);
    XtAddCallback(newW->combobox.EditCtrl, 
                  XmNhelpCallback, 
		  (XtCallbackProc) HelpCallback, 
		  (XtPointer) newW);
    XtAddCallback(newW->combobox.EditCtrl, 
                  XmNactivateCallback, 
		  (XtCallbackProc) ActivateCallback, 
		  (XtPointer) newW);
    if ( newW->combobox.Editable )
	XtAddCallback(newW->combobox.EditCtrl, 
		      XmNmotionVerifyCallback, 
		      (XtCallbackProc) MotionVerifyCallback, 
		      (XtPointer) newW);
/* Neue Translations fuer das Eingabefeld aufnehmen */
    XtOverrideTranslations(newW->combobox.EditCtrl, 
                           NewEditTranslations);
    if ( !newW->combobox.Editable ) {
	XtOverrideTranslations(newW->combobox.EditCtrl, 
                               NewEditTranslationsNE);
        XtVaSetValues(newW->combobox.EditCtrl, 
                      XmNcursorPositionVisible, False, NULL);
    }
#ifdef NODRAGNDROP
    XtOverrideTranslations(newW->combobox.EditCtrl, 
                           NewListTranslations); /* Btn2Dwn aus! */
#endif

/* --- */
    newW->combobox.ArrowCtrl = XtVaCreateManagedWidget(
	"arrow", xmArrowButtonWidgetClass, (Widget) newW, 
	XmNarrowDirection,     XmARROW_DOWN, 
	XmNtraversalOn,	       False, 
	XmNnavigationType,     XmNONE,
	XmNborderWidth,        0, 
	XmNhighlightThickness, 0, 
	NULL);
    XmRemoveTabGroup(newW->combobox.ArrowCtrl);
    if ( newW->combobox.StaticList ) {
	XtVaSetValues(newW->combobox.ArrowCtrl, 
	    XmNmappedWhenManaged, False, NULL);
    } else {
	XtAddEventHandler(newW->combobox.ArrowCtrl, 
			  EnterWindowMask | LeaveWindowMask,
			  False, (XtEventHandler) ArrowCrossingCallback,
			  (XtPointer) newW);
	XtAddCallback(newW->combobox.ArrowCtrl, 
		      XmNactivateCallback, 
		      (XtCallbackProc) ArrowCallback, NULL);
	XtAddCallback(newW->combobox.ArrowCtrl, 
		      XmNarmCallback, 
		      (XtCallbackProc) ArrowCallback, NULL);
	XtAddCallback(newW->combobox.ArrowCtrl, 
		      XmNhelpCallback, 
		      (XtCallbackProc) HelpCallback, 
		      (XtPointer) newW);
    }

/* --- */
    newW->combobox.LabelCtrl = XtVaCreateWidget(
	"label", xmLabelWidgetClass, (Widget) newW, 
	XmNstringDirection, newW->manager.string_direction, 
	NULL);
    if ( newW->combobox.ShowLabel ) {
	XtManageChild((Widget) newW->combobox.LabelCtrl);
	XtAddCallback(newW->combobox.LabelCtrl, 
		      XmNhelpCallback, 
		      (XtCallbackProc) HelpCallback, 
		      (XtPointer) newW);
    }

/* 
 * Zuerst noch die Shell erzeugen, die so einfach mir nichts dir nichts
 * frei auf dem Bildschirm herumschweben kann und damit das Ausklappen
 * der Liste erst ermoeglicht -- und uns allerhand Scherereien bereitet!
 * War das ein bloeder Fehler in Motif 1.2! Diese Version vertraegt ab-
 * solut keine ShellWidgetClass noch overrideShellWidgetClass!!!! Naja,
 * mit einer vendorShellWidgetClass laesst sich aber exakt der gleiche
 * Effekt erreichen. NEU: vor allem funktioniert dann endlich auch
 * Drag'n'Drop!!!
 * Noch neuer: Wenn die Liste dauerhaft angezeigt werden muss, entfaellt
 * diese Shell zwangslaeufig. Dann ist das Listenfeld ein direktes Kind
 * der ComboBox.
 */
    if ( !newW->combobox.StaticList ) {
	newW->combobox.PopupShell = XtVaCreateWidget(
	    "combobox_shell", vendorShellWidgetClass, (Widget) newW, 
	    XmNoverrideRedirect, True,
	    XmNsaveUnder,        False,
	    XmNallowShellResize, True, 
	    NULL);
	XtAddEventHandler(newW->combobox.PopupShell, 
			  EnterWindowMask | LeaveWindowMask, 
			  False, (XtEventHandler) OverrideShellCallback, 
			  (XtPointer) newW);
    } else {
    /*
     * Sieht ja pervers nach einer Rekursion aus...daher: OBACHT!
     */
	newW->combobox.PopupShell = (Widget) newW;
    }

/*
 * Nun kommt die Drop-Down-Liste an die Reihe. Die Liste muss dabei
 * mit einer Convenience-Funktion erstellt werden, damit ein Rollbalken
 * 'dran ist und das Ganze wird dann in eine Override-Shell gepackt.
 * Nicht zu vergessen ist der XtManageChild-Aufruf, damit die Liste
 * sofort nach dem Aufklappen der Shell sichtbar wird.
 */
    XtSetArg(args[n], XmNselectionPolicy, newW->combobox.SelectionPolicy); n++;
    
    if ( !newW->combobox.StaticList ) {
    /*
     * Es gibt halt so eine ganze Reihe von Einstellungen, die koennen nicht
     * veraendert werden, wenn das Listenfeld nur bei Bedarf ausgeklappt wird.
     */
	XtSetArg(args[n], XmNhighlightThickness, 0); n++;
    }
    XtSetArg(args[n], XmNlistSizePolicy, 
                      newW->combobox.ListSizePolicy); n++;
    XtSetArg(args[n], XmNscrollBarDisplayPolicy, 
                      newW->combobox.ScrollBarDisplayPolicy); n++;
    
    XtSetArg(args[n], XmNautomaticSelection, 
                      newW->combobox.AutomaticSelection); n++;
    XtSetArg(args[n], XmNvisibleItemCount, 
                      newW->combobox.VisibleItemCount); n++;
    newW->combobox.ListCtrl = XmCreateScrolledList(
	newW->combobox.PopupShell, "list",  
	args, n);

/*
 * Fuer den Fall, dass die Liste in einer eigenen Shell steckt und daher frei
 * auf dem Bildschirm herumschweben kann, sollten wir sicherheitshalber die
 * Tastaturbedienung (Fokus) abschalten, um Probleme zu vermeiden (jedenfalls
 * hoffentlich...!)
 */
    if ( !newW->combobox.StaticList ) {
	XtVaSetValues(newW->combobox.ListCtrl, 
		      XmNtraversalOn,  False,  NULL);
	XtVaSetValues(XtParent(newW->combobox.ListCtrl), 
		      XmNtraversalOn, False, NULL);
    } else {
	if ( !newW->combobox.Editable ) {
	    XtVaSetValues(XtParent(newW->combobox.ListCtrl), 
		      XmNtraversalOn, False, NULL);
	    XmRemoveTabGroup(newW->combobox.ListCtrl);
	}
    }
    
    XtManageChild(newW->combobox.ListCtrl);
    XtAddCallback(newW->combobox.ListCtrl, 
                  XmNsingleSelectionCallback, 
		  (XtCallbackProc) ListSelectionCallback, 
		  (XtPointer) newW);
    XtAddCallback(newW->combobox.ListCtrl, 
                  XmNbrowseSelectionCallback, 
		  (XtCallbackProc) ListSelectionCallback, 
		  (XtPointer) newW);
    XtAddCallback(newW->combobox.ListCtrl, 
                  XmNdefaultActionCallback, 
		  (XtCallbackProc) ListDefaultActionCallback, 
		  (XtPointer) newW);
    XtAddCallback(newW->combobox.ListCtrl, 
                  XmNhelpCallback, 
		  (XtCallbackProc) HelpCallback, 
		  (XtPointer) newW);
    
    XtAddEventHandler(newW->combobox.ListCtrl, 
                      ButtonReleaseMask, 
		      False, (XtEventHandler) Button1UpInList, 
		      (XtPointer) newW);

#ifdef NODRAGNDROP
    XtOverrideTranslations(newW->combobox.ListCtrl, 
                           NewListTranslations);
#endif
    if ( newW->combobox.StaticList && newW->combobox.Editable )
        XtOverrideTranslations(newW->combobox.ListCtrl, 
                               NewListTranslationsE);

/* Jetzt wird es dann erst richtig spannend... Zuerst alle evtl.
 * in der Resource-Datenbank abgelegten Resourcen an die Kinder
 * weitergeben. Danach die uebergebenen Parameter ebenfalls an
 * die Kinder weiterreichen und schliesslich das Layout ermitteln.
 */
    InitMirrorResources(newW);
    UpdateColors(newW, -1);
    SetValues(newW, newW, newW, wargs, ArgCount);
    
    if ( newW->combobox.ConvertBitmapToPixmap ) 
	newW->combobox.LabelPixmap = 
	    BitmapToPixmap(newW, XmNlabelPixmap, 
	               ((XmLabelRec *) newW->combobox.LabelCtrl)->
		         label.normal_GC);
    if ( newW->combobox.ConvertBitmapToPixmapInsensitive ) 
	newW->combobox.LabelInsensitivePixmap = 
	    BitmapToPixmap(newW, XmNlabelInsensitivePixmap, 
	               ((XmLabelRec *) newW->combobox.LabelCtrl)->
		         label.insensitive_GC);
    
    DefaultGeometry(newW, &width, &height, &dummy, &dummy);
    if ( newW->core.width == 0 )
	newW->core.width  = width;
    if ( newW->core.height == 0 )
	newW->core.height = height;

/*
 * Falls wir keine Fontliste besitzen, dann nehmen wir die von
 * dem Eingabefeld...
 */
    if ( newW->combobox.Font == NULL ) {
	XtVaGetValues(newW->combobox.EditCtrl, 
	              XmNfontList, &newW->combobox.Font, NULL);
	XtVaSetValues(newW->combobox.ListCtrl, 
	              XmNfontList, newW->combobox.Font, NULL);
    } else {
	XtVaSetValues(newW->combobox.ListCtrl, 
	              XmNfontList, newW->combobox.Font, NULL);
	XtVaSetValues(newW->combobox.EditCtrl, 
	              XmNfontList, newW->combobox.Font, NULL);
    }
    
/* 
 * Initialisiere alle Statusflaggen, die mit diesem unseligen Focus-
 * problem zu tun haben...
 */
    newW->combobox.ListVisible          = False;
    newW->combobox.IgnoreFocusOut       = False;
    newW->combobox.PendingFocusOut      = False;
    newW->combobox.PendingOverrideInOut = False;
    
    newW->combobox.PassVerification = False;

/* 
 * Jooa... bei der OSF pennen die wohl komplett?! Zusammen mit Form-
 * Widgets gibt das wohl immer Aerger...daher hier ein DoLayout()
 * aufrufen, damit Eingabefeld und Pfeil sowie das Listenfeld an der 
 * richtigen Stelle sitzen!
 */
    DoLayout(newW);
/* 
 * Endlich fertig mit der Initialisierung. Das hier ist aber auch
 * wirklich viel Arbeit fuer so ein Widget!
 */    
    newW->combobox.InInit = False;
} /* Initialize */

/* --------------------------------------------------------------------
 * Diese Funktionen bitte nur im aeussersten Notfall benutzen, da sie
 * die Abstraktion dieser neuen Klasse umgehen und Informationen ueber
 * den internen Aufbau voraussetzen.
 */
Widget XmComboBoxGetEditWidget(Widget w)
{
    return ((XmComboBoxWidget) w)->combobox.EditCtrl;
} /* XmComboBoxGetEditWidget */

Widget XmComboBoxGetListWidget(Widget w)
{
    return ((XmComboBoxWidget) w)->combobox.ListCtrl;
} /* XmComboBoxGetListWidget */

Widget XmComboBoxGetLabelWidget(Widget w)
{
    return ((XmComboBoxWidget) w)->combobox.LabelCtrl;
} /* XmComboBoxGetLabelWidget */


/* --------------------------------------------------------------------
 * Sobald sich im Listenfeld Eintraege veraenderten, sei es, dass sie
 * geloescht wurden, sei es, dass sie veraendert wurden, so muss hier
 * gegebenenfalls auch der Text im Eingabefeld angepasst werden.
 * Letzteres betrifft aber nur Combo-Boxen mit nicht editierbarem
 * Eingabefeld. In jedem Fall wird aber bei jeder Combo-Box-Type in
 * dem Fall, dass ein Eintrag geloescht wird, der darauffolgende
 * Eintrag markiert. Eigentlich ist dieses nur eine nette Geste
 * gegenueber dem Benutzer...
 * 
 * Parameter:
 *   w		    Combo-Box-Widget
 *   Index	    Index auf denjenigen Eintrag der sich geaendert
 *		    hat, oder der geloescht wurde.
 *   Deleted	    Zeigt an, ob der Eintrag geloescht wurde (True)
 *		    oder sich nur veraenderte (False)
 */
static int UpdateComboBox(XmComboBoxWidget w, int Index, Boolean Deleted)
{
    int OldIndex, ItemCount;
    
    OldIndex = XmComboBoxGetSelectedPos((Widget) w);
    if ( OldIndex == Index ) {
/* Es betrifft den Eintrag, der auch momentan ausgewaehlt ist.
 * Sollte er geloescht werden, so nimm' (soweit vorhanden) den
 * naechsten Eintrag, wurde er ausgetauscht, so lass ihn ausge-
 * waehlt.
 */
	if ( Deleted ) {
	    XtVaGetValues(w->combobox.ListCtrl, 
	                  XmNitemCount, &ItemCount, NULL);
	    if ( ItemCount != 0 ) {
		if ( Index >= ItemCount ) Index = ItemCount;
		/* Markieren des Eintrags, ohne jedoch jetzt schon
		 * den Eintrag in die Eingabezeile zu kopieren.
		 */
		SetSelectionPos(w, Index, False);
	    }
	}
    }
/* Das Problem betrifft uns nur bei nicht editierbaren Combo-Boxen
 * im vollen Umfang. Denn dann muss auch der Text im Eingabefeld
 * veraendert werden.
 */
    if ( !w->combobox.Editable ) {
	TransferToEditCtrl(w, Index, False);
    }

    return 1;
} /* UpdateComboBox */


/* --------------------------------------------------------------------
 * Die Eintragsposition finden, an der der Eintrag sortiert stehen
 * muesste. Naja, es wurde ja 'mal langsam Zeit, diese Routine etwas
 * aufzupolieren, damit sie schneller wird.
 */
static int FindSortedItemPos(XmComboBoxWidget w, XmString item)
{
    Widget                          ListBox = w->combobox.ListCtrl;
    XmStringTable                   Items;
    int                             ItemCount, index, Left, Right, Result;
    char                            *pItemText, *pCompareText;
    Boolean	                    ExternSort;
    XmComboBoxSortingCallbackStruct data;
    
    XtVaGetValues(ListBox, XmNitems,     &Items, 
                           XmNitemCount, &ItemCount, NULL);
    if ( ItemCount == 0 ) return 1;
    
    /*
     * Moechte das Programm die Kontrolle ueber den Sortiervorgang
     * uebernehmen? Dann bereite alles vor...
     */
    ExternSort = XtHasCallbacks((Widget) w, XmNsortingCallback) == 
                     XtCallbackHasSome;
    if ( ExternSort ) {
        data.reason    = XmCR_SORTING;
        data.event     = NULL;
        data.operation = XmOP_INIT;
        data.item      = item;
        XtCallCallbacks((Widget) w, XmNsortingCallback, (XtPointer) &data);
    } else
        XmStringGetLtoR(item, XmSTRING_DEFAULT_CHARSET, &pCompareText);

    Left = 0; Right = ItemCount - 1;    
    do {
	index = (Left + Right) / 2;
	if ( ExternSort ) {
	    data.operation = XmOP_COMPARE;
	    data.item      = Items[index];
	    data.result    = 1;
            XtCallCallbacks((Widget) w, XmNsortingCallback, (XtPointer) &data);
            Result = data.result;
	} else {
	    XmStringGetLtoR(Items[index], XmSTRING_DEFAULT_CHARSET, &pItemText);
	    Result = strcmp(pCompareText, pItemText);
	    XtFree(pItemText);
	}
	if      ( Result < 0 ) Right = index - 1;
	else if ( Result > 0 ) Left  = index + 1;
    } while ( (Result != 0) && (Left <= Right) );

    /*
     * Nach Gebrauch wieder alles aufraeumen (bei einer externen Sortierung
     * muss das das Programm uebernehmen!)
     */
    if ( ExternSort ) {
        data.operation = XmOP_DONE;
        XtCallCallbacks((Widget) w, XmNsortingCallback, (XtPointer) &data);
    } else
        XtFree(pCompareText);
        
    if ( Result < 0 )
	return index + 1; /* Beachte, dass Indizes mit 1 beginnen! */
    else
	return index + 2; /* Beachte, dass Indizes mit 1 beginnen! */
} /* FindSortedItemPos */

/* --------------------------------------------------------------------
 * Kontrolliere, ob es sich ueberhaupt um eine Combo-Box (bzw. einen
 * hypothetischen Nachkommen) handelt -- ansonsten mecker kraeftig
 * herum!
 * Ergebnis:
 *   True, falls wir hier ein falsches Widget untergejubelt bekommen!
 */
static Boolean CheckComboBox(Widget w, char *pFuncName)
{
    char buff[256];
    char *pWName;

#if (XmVersion >= 2000)
    return False; /* temporary workaround */
#else    
    if ( XmIsComboBox(w) ) return False;
    pWName = XrmQuarkToString(w->core.xrm_name);
    sprintf(buff, 
"Warning: %s called on widget named %s beeing \
not a descendant of class XmComboBox!", 
		  pFuncName, pWName);
    XtWarning(buff);
    return True;
#endif
} /* CheckComboBox */

/* --------------------------------------------------------------------
 * Saemtliche Interface-Routinen zur Combo-Box
 */
/* Zunaechst alles fuer die Listbox */
#define ListBox (((XmComboBoxWidget) w)->combobox.ListCtrl)
#define EditBox (((XmComboBoxWidget) w)->combobox.EditCtrl)
#define ComboBox ((XmComboBoxWidget) w)

/* !!!
 * So angepasst, dass bei doppelt auftretenden Eintraegen, der
 * alte Eintrag weiterhin markiert bleibt. Diese Massnahme soll
 * eigentlich nur verhindern, dass zufaellig zwei Eintraege
 * markiert sind, falls nach der Anwahl eines Eintrages ein zweiter
 * gleichlautender Eintrag hinzugefuegt wurde.
 * Was hier die reine Lehre (oder war das die Leere?) anbetrifft:
 * in einer Combo-Box sollten sich sowieso nie gleichlautende
 * Eintraege befinden, da sie dort unsinnig sind und den Benutzer
 * nur verwirren...
 */
void    XmComboBoxAddItem(Widget w, XmString item, int pos)
{
    int OldIndex = XmComboBoxGetSelectedPos(w);
    
    if ( CheckComboBox(w, "XmComboBoxAddItem") ) return;
    if ( ComboBox->combobox.Sorted )
	pos = FindSortedItemPos(ComboBox, item);
    XmListAddItem(ListBox, item, pos);
    if ( OldIndex != XmComboBoxGetSelectedPos(w) )
        /* Hier SetSelectionPos() statt XmComboBoxSelectPos(),
	 * da der Text nicht in das Eingabefeld uebertragen werden
	 * soll!
	 */
	SetSelectionPos(ComboBox, OldIndex, False);
} /* XmComboBoxAddItem */
/* !!!
 * Hier gilt das bereits oben gesagte (siehe XmComboBoxAddItem).
 * Bei sortierten Listboxen wird die Sortierung beim Gebrauch dieser
 * Funktion zerstoert!
 */
void    XmComboBoxAddItems(Widget w, XmString *items, int item_count, int pos)
{
    int OldIndex = XmComboBoxGetSelectedPos(w);

    if ( CheckComboBox(w, "XmComboBoxAddItems") ) return;
    XmListAddItems(ListBox, items, item_count, pos);
    if ( OldIndex != XmComboBoxGetSelectedPos(w) )
	/* Siehe Anmerkung in XmComboBoxAddItem */
	SetSelectionPos(ComboBox, OldIndex, False);
} /* XmComboBoxAddItems */

void    XmComboBoxAddItemUnselected(Widget w, XmString item, int pos)
{ XmListAddItemUnselected(ListBox, item, pos); }

/* !!!
 * Da bei den folgenden Routinen jeweils ein oder mehrere Eintraege
 * geloescht oder veraendert werden, muss gegebenefalls das Eingabe-
 * feld bei nicht editierbaren Combo-Boxen auf Vordermann gebracht
 * werden.
 */
void    XmComboBoxDeleteItem(Widget w, XmString item)
{
    int Index = XmListItemPos(ListBox, item);

    if ( CheckComboBox(w, "XmComboBoxDeleteItem") ) return;
    if ( Index ) XmComboBoxDeletePos(w, Index);
} /* XmComboBoxDeleteItem */

void    XmComboBoxDeleteItems(Widget w, XmString *items, int item_count)
{
    int i;

    if ( CheckComboBox(w, "XmComboBoxDeleteItems") ) return;
    for ( i = 0; i < item_count; i++ )
	XmListDeleteItem(w, items[i]);
} /* XmComboBoxDeleteItems */

void    XmComboBoxDeletePos(Widget w, int pos)
{
    int OldIndex = XmComboBoxGetSelectedPos(w);
    
    if ( CheckComboBox(w, "XmComboBoxDeletePos") ) return;
    XmListDeletePos(ListBox, pos);
    if ( pos == OldIndex ) UpdateComboBox(ComboBox, pos, True);
} /* XmComboBoxDeletePos */

void    XmComboBoxDeleteItemsPos(Widget w, int item_count, int pos)
{
    int i;

    if ( CheckComboBox(w, "XmComboBoxDeleteItemsPos") ) return;
    for ( i = 0; i < item_count; i++ )
	XmComboBoxDeletePos(w, pos++);
} /* XmComboBoxDeleteItemsPos */

void    XmComboBoxDeleteAllItems(Widget w)
{
    if ( CheckComboBox(w, "XmComboBoxAllDeleteItems") ) return;
    XmListDeleteAllItems(ListBox);
    UpdateComboBox(ComboBox, 0, True);
} /* XmComboBoxDeleteAllItems */

/* !!!
 * Werden Eintraege ausgetauscht, so heisst es fuer uns, auch hierbei
 * auf der Hut zu sein.
 */
void    XmComboBoxReplaceItems(Widget w, XmString *old_items, int item_count, XmString *new_items)
{
    if ( CheckComboBox(w, "XmComboBoxReplaceItems") ) return;
    XmListReplaceItems(ListBox, old_items, item_count, new_items);
    UpdateComboBox(ComboBox, XmComboBoxGetSelectedPos(w), False);
} /* XmComboBoxReplaceItems */

void    XmComboBoxReplaceItemsPos(Widget w, XmString *new_items, int item_count, int position)
{
    int OldIndex = XmComboBoxGetSelectedPos(w);

    if ( CheckComboBox(w, "XmComboBoxReplaceItemsPos") ) return;
    XmListReplaceItemsPos(ListBox, new_items, item_count, position);
    if ( (OldIndex >= position) && (OldIndex < position + item_count) )
	UpdateComboBox(ComboBox, OldIndex, False);
} /* XmComboBoxReplaceItemsPos */

Boolean XmComboBoxItemExists(Widget w, XmString item)
{
    if ( CheckComboBox(w, "XmComboBoxItemExists") ) return False;
    return XmListItemExists(ListBox, item);
} /* XmComboBoxItemExists */

int     XmComboBoxItemPos(Widget w, XmString item)
{
    if ( CheckComboBox(w, "XmComboBoxItemPos") ) return 0;
    return XmListItemPos(ListBox, item);
} /* XmComboBoxItemPos */

Boolean XmComboBoxGetMatchPos(Widget w, XmString item, int **pos_list, int *pos_count)
{
    if ( CheckComboBox(w, "XmComboBoxGetMatchPos") ) return False;
    return XmListGetMatchPos(ListBox, item, pos_list, pos_count);
} /* XmComboBoxGetMatchPos */

/* !!!
 * Sobald ein anderer Eintrag in der Listbox ausgewaehlt werden soll,
 * muessen wir hier helfend eingreifen.
 */
void    XmComboBoxSelectPos(Widget w, int pos, Boolean notify)
{
    int index;
    
    if ( CheckComboBox(w, "XmComboBoxSelectPos") ) return;
    index = SetSelectionPos(ComboBox, pos, notify);
    if ( index ) TransferToEditCtrl(ComboBox, index, False);
} /* XmComboBoxSelectPos */

/* !!!
 * dto. analog zu XmComboBoxSelectPos, nur statt des Index wird der
 * Eintragstext angegeben, um einen Eintrag in der Listbox zu
 * markieren.
 */
void    XmComboBoxSelectItem(Widget w, XmString item, Boolean notify)
{
    int index;
    
    if ( CheckComboBox(w, "XmComboBoxSelectItem") ) return;
    XmListSelectItem(ListBox, item, notify);
    index = SetSelectionPos(ComboBox, XmComboBoxGetSelectedPos(w), False);
    if ( index ) TransferToEditCtrl(ComboBox, index, False);
} /* XmComboBoxSelectItem */

/* !!!
 * Geaendert gegenueber dem ListBox-Pendant! Da in einer Combo-Box die
 * Liste nur maximal einen ausgewaehlten Eintrag besitzt, macht die
 * 'alte' Funktionalitaet von XmListGetSelectedPos ziemlich wenig Sinn.
 * Die neue Routine liefert statt dessen direkt den Index des aus-
 * gewaehlten Eintrages oder 0 zurueck.
 */
int     XmComboBoxGetSelectedPos(Widget w)
{
    int *SelectionList, SelectionCount, SelectionIndex;
    
    if ( CheckComboBox(w, "XmComboBoxGetSelectedPos") ) return 0;
    if ( XmListGetSelectedPos(ListBox,
	                      &SelectionList, &SelectionCount) ) {
	SelectionIndex = *SelectionList;
	XtFree((char *)SelectionList);
    } else SelectionIndex = 0;
    return SelectionIndex;
} /* XmComboBoxGetSelectedPos */



void    XmComboBoxClearSelection(Widget w, Time time)
{
    XmTextFieldClearSelection(EditBox, time);
} /* XmComboBoxClearSelection */

Boolean XmComboBoxCopy(Widget w, Time time)
{
    return XmTextFieldCopy(EditBox, time);
} /* XmComboBoxCopy */

Boolean XmComboBoxCut(Widget w, Time time)
{
    return XmTextFieldCut(EditBox, time);
} /* XmComboBoxCut */

XmTextPosition XmComboBoxGetInsertionPosition(Widget w)
{
    return XmTextFieldGetInsertionPosition(EditBox);
} /* XmComboBoxGetInsertionPosition */

XmTextPosition XmComboBoxGetLastPosition(Widget w)
{
    return XmTextFieldGetLastPosition(EditBox);
} /* XmComboBoxGetLastPosition */

int     XmComboBoxGetMaxLength(Widget w)
{
    return XmTextFieldGetMaxLength(EditBox);
} /* XmComboBoxGetMaxLength */

char *  XmComboBoxGetSelection(Widget w)
{
    return XmTextFieldGetSelection(EditBox);
} /* XmComboBoxGetSelection */

Boolean XmComboBoxGetSelectionPosition(Widget w, XmTextPosition *left, 
                                       XmTextPosition *right)
{
    return XmTextFieldGetSelectionPosition(EditBox, left, right);
} /* XmComboBoxGetSelectionPosition */

char *  XmComboBoxGetString(Widget w)
{
    return XmTextFieldGetString(EditBox);
} /* XmComboBoxGetString */

void    XmComboBoxInsert(Widget w, XmTextPosition position, char *value)
{
    XmTextFieldInsert(EditBox, position, value);
} /* XmComboBoxInsert */

Boolean XmComboBoxPaste(Widget w)
{
    return XmTextFieldPaste(EditBox);
} /* XmComboBoxPaste */

Boolean XmComboBoxRemove(Widget w)
{
    return XmTextFieldRemove(EditBox);
} /* XmComboBoxRemove */

void    XmComboBoxReplace(Widget w, XmTextPosition from_pos, 
                          XmTextPosition to_pos, char *value)
{
    XmTextFieldReplace(EditBox, from_pos, to_pos, value);
} /* XmComboBoxReplace */

void    XmComboBoxSetAddMode(Widget w, Boolean state)
{
    XmTextFieldSetAddMode(EditBox, state);
} /* XmComboBoxSetAddMode */

void    XmComboBoxSetHighlight(Widget w, XmTextPosition left, 
                               XmTextPosition right, XmHighlightMode mode)
{
    XmTextFieldSetHighlight(EditBox, left, right, mode);
} /* XmComboBoxSetHighlight */

void    XmComboBoxSetInsertionPosition(Widget w, XmTextPosition position)
{
    XmTextFieldSetInsertionPosition(EditBox, position);
} /* XmComboBoxSetInsertionPosition */

void    XmComboBoxSetMaxLength(Widget w, int max_length)
{
    XmTextFieldSetMaxLength(EditBox, max_length);
} /* XmComboBoxSetMaxLength */

void    XmComboBoxSetSelection(Widget w, XmTextPosition first, 
                               XmTextPosition last, Time time)
{
    XmTextFieldSetSelection(EditBox, first, last, time);
} /* XmComboBoxSetSelection */

void    XmComboBoxSetString(Widget w, char *value)
{
/* Liebe OSF...ihr ^&*#%$*&)*(@$(*^(*&%# habt doch einen ziemlich gemeinen
 * Fehler in XmTextFieldSetString() drin... wenn man einen leeren String
 * (also "") angiebt, gibt's nur noch Aerger, wenn man spaeter wieder an
 * den Inhalt des Eingabefeldes heranwill.
 */
    if ( (value == NULL) || (*value == 0) )
        XtVaSetValues(w, XmNvalue, "", NULL);
    else
	XmTextFieldSetString(EditBox, value);
} /* XmComboBoxSetString */

void    XmComboBoxShowPosition(Widget w, XmTextPosition position)
{
    XmTextFieldShowPosition(EditBox, position);
} /* XmComboBoxShowPosition */

/*
 * Loescht einen evtl. noch ausgewaehlten Eintrag in einer Combo Box, 
 * wenn diese eine SelectionPolicy von XmSINGLE_SELECT hat.
 */
void XmComboBoxClearItemSelection(Widget w)
{
    int index;

    if ( CheckComboBox(w, "XmComboBoxClearItemSelection") ) return;
    
    /*
     * Wenn bereits kein Eintrag markiert ist, dann loeschen wir nur noch
     * eben das Eingabefeld.
     */
    index = XmComboBoxGetSelectedPos(w);
    if ( index == 0 ) {
	XmComboBoxSetString(w, "");
    } else {
    /*
     * Ansonsten aktuellen Eintrag entsorgen (wie bei der Methode wipe-out)
     */
	TransferToEditCtrl(ComboBox, 0, True);
	CallSelectionCBL(ComboBox, NULL);
    }
} /* XmComboBoxClearItemSelection */

/* Die Drop-Down-Liste ein oder ausklappen */
void    XmComboBoxShowList(Widget w)
{
    if ( CheckComboBox(w, "XmComboBoxShowList") ) return;
    ShowHideDropDownList((XmComboBoxWidget) w, NULL, False);
} /* XmComboBoxShowList */

void    XmComboBoxHideList(Widget w)
{
    if ( CheckComboBox(w, "XmComboBoxHideList") ) return;
    ShowHideDropDownList((XmComboBoxWidget) w, NULL, True);
} /* XmComboBoxShowList */

/*
 * Naja, ich komm' ja doch nicht um diese olle Funktion herum...
 */
Widget XmCreateComboBox(Widget parent, String name, ArgList arglist,
                           Cardinal argcount)
{
    return XtCreateWidget(name, xmComboBoxWidgetClass, parent,
                          arglist, argcount);
} /* XmCreateComboBox */

/* Ende von ComboBox.c */

#endif /* XmVersion < 2000 */
