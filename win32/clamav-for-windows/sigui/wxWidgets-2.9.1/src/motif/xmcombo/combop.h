/*
 * ComboBoxP.h - Das schon lange schmerzlich vermisste Combo-Box-
 *               Widget -- nun endlich auf fuer Motif!
 *               Wahlweise Motif 1.1 oder 1.2.
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
#ifndef __ComboBoxWidgetP_h
#define __ComboBoxWidgetP_h

#include "xmcombo.h"
#include <Xm/XmP.h>
#if (XmVersion > 1001) /* sounds like tales from 1000 and 1 night.... */
#include <Xm/ManagerP.h>
#endif

/*********************************************************************
 * Klassendefinition
 *********************************************************************/
/* Neue Datenfelder fuer den Klassenrecord der Center-Widgetklasse */
typedef struct _XmComboBoxClassPart {
    int Just_to_keep_the_compiler_happy; /* Der Name ist Programm */
} XmComboBoxClassPart;
/*
 * Nun folgt die vollstaendige Klassenstruktur, mit all' den Felder,
 * die bereits von den Vorfahren geerbt wurden.
 */
typedef struct _XmComboBoxClassRec {
    CoreClassPart       core_class;
    CompositeClassPart  composite_class;
    ConstraintClassPart constraint_class;
    XmManagerClassPart  manager_class;
    XmComboBoxClassPart combobox_class;
} XmComboBoxClassRec;
extern XmComboBoxClassRec xmComboBoxClassRec;

/*********************************************************************
 *Instanzdefinition
 *********************************************************************/
typedef struct _XmComboBoxPart {
/* Resourcen ... hierauf darf von aussen zugegriffen werden! */
    Boolean	    Editable;		/* Editierbare Eingabezeile ? */
    Boolean	    StaticList;         /* Liste immer dargestellt?   */
    unsigned char   SelectionPolicy;	/* Was geht hier ab?!         */
    unsigned char   ScrollBarDisplayPolicy;
    unsigned char   ListSizePolicy;	/* Rollbalken!                */
    Boolean	    AutomaticSelection; /* Wann Callbacks aufrufen?   */
    Boolean	    Sorted;		/* Liste sortiert             */
    XtCallbackList  SortingCBL;		/* Wie wird extern sortiert?  */
    int		    VisibleItemCount;	/* Anz dargstellte Eintraege  */
    XmFontList	    Font;		/* verwendete Fonts           */
    XtCallbackList  SelectionCBL;       /* Auswahl aus Liste          */
    XtCallbackList  UnselectionCBL;	/* Auswahl zurueckgenommen    */
    XtCallbackList  DefaultActionCBL;	/* bei Doppelklick	      */
    XtCallbackList  DropDownCBL;        /* Liste angezeigt/versteckt  */
    XtCallbackList  ModifyVerifyCBL;	/* Vor Aenderung im Textfeld  */
    XtCallbackList  ValueChangedCBL;	/* Danach...		      */
    XtCallbackList  MotionVerifyCBL;	/* Der Cursor bewegt sich doch*/
    XtCallbackList  ActivateCBL;	/* Eingabe beendet?           */
    Boolean         SquareArrow;        /* Quadratischer Pfeil?       */
    Boolean         ArrowSpacingOn;     /* Abstand zw. Pfeil und Text */
    Boolean	    Persistent;		/* Liste & Focus-Out	      */
    Boolean	    TwmHandlingOn;	/* dto.			      */
    Boolean	    ShowLabel;		/* Label anzeigen?	      */
    Position	    DropDownOffset;	/* delta Ecke Eingabefeld,
                                                 Liste                */
    
/* Ab hier wird's privat! */
    Widget	    EditCtrl;	/* Editorzeile */
    Widget	    ArrowCtrl;  /* Pfeil nach unten */
    Widget	    LabelCtrl;  /* Text links neben dem Eingabefeld */
    
    Widget	    PopupShell; /* Shell, in der die Liste liegt */
    Widget	    ListCtrl;   /* Listenfeld */

    Widget	    MyNextShell;
    
    Cursor          ArrowCursor;
    Boolean         InInit;
    
    int		    LastSelection;

    Boolean         ListVisible;
    Boolean	    IgnoreFocusOut;
    Boolean         PendingFocusOut;
    Boolean	    PendingOverrideInOut;
    XtWorkProcId    WorkProcID;
    XEvent          xevent;
    
    Boolean	    PassVerification;
    Boolean	    ConvertBitmapToPixmap, 
                    ConvertBitmapToPixmapInsensitive;
    Pixmap	    LabelPixmap, LabelInsensitivePixmap;

    XtPointer	    Dummy;
} XmComboBoxPart;

/*
 * vollstaengige Instanzenstruktur
 */
typedef struct _XmComboBoxRec {
    CorePart       core;
    CompositePart  composite;
    ConstraintPart constraint;
    XmManagerPart  manager;
    XmComboBoxPart combobox;
} XmComboBoxRec;

#endif
/* Ende von ComboBoxP.h */
