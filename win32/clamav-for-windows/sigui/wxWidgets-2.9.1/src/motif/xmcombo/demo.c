/*
 * demo.c -- Example how to use a ComboBox
 * 
 * compile and link with:
 * $ cc -DFUNCPROTO ComboBoxDemo.c ComboBox.o -o ComboBoxDemo \
 *   -lXm -lXt -lX11
 * then run:
 * $ ./ComboBoxDemo
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
#include <stdio.h>
#include <Xm/Xm.h>
#include <Xm/Form.h>
#include <Xm/Label.h>
#include <Xm/Separator.h>
#include <Xm/PushB.h>
#include "combobox.h"

Widget TopLevel, Form, Button, Text, Sepp, ComboBox1, ComboBox2, ComboBox3, Label;

void QuitCB(Widget w, caddr_t pClientData, caddr_t pCallData)
{
    char *text;

    text = XmComboBoxGetString(ComboBox1);
    fprintf(stderr, "You choosed \"%s\" out of the first ComboBox\n", text);
    XtFree(text);
    text = XmComboBoxGetString(ComboBox2);
    fprintf(stderr, "You entered \"%s\" into the second ComboBox\n", text);
    XtFree(text);
    fprintf(stderr, "Bye! ... have fun with XmComboBox!\n");
    exit(0);
} /* QuitCB */

int main(int argc, String argv[])
{
    XmString         str;
    Boolean          Trav;
    XtAppContext     AppContext;

#if (XmREVISION > 1)
    XtSetLanguageProc(NULL,NULL,NULL); 
#endif
    TopLevel = XtAppInitialize(&AppContext, "XFontSelDemo", NULL, 0, 
#if (XmREVISION > 1)
        		       &argc, 
#else
                               (Cardinal *) &argc,
#endif
        		       argv, NULL, NULL, 0);
 
    Form = XtVaCreateManagedWidget("form", xmFormWidgetClass, TopLevel, NULL);
    str = XmStringCreateLtoR("Click to quit", XmSTRING_DEFAULT_CHARSET);
    Button = XtVaCreateManagedWidget("quit", xmPushButtonWidgetClass, Form, 
			XmNlabelString, str, 
			XmNleftAttachment, XmATTACH_FORM, 
			XmNleftOffset, 8, 
			XmNtopAttachment,  XmATTACH_FORM, 
			XmNtopOffset, 8, 
			NULL);
    XmStringFree(str);
    XtAddCallback(Button, XmNactivateCallback, (XtCallbackProc) QuitCB, NULL);

    Sepp = XtVaCreateManagedWidget("separator1", xmSeparatorWidgetClass, Form, 
			XmNleftAttachment, XmATTACH_FORM, 
			XmNrightAttachment, XmATTACH_FORM,
			XmNtopAttachment, XmATTACH_WIDGET, 
			XmNtopOffset, 8, 
			XmNtopWidget, Button, 
			NULL); 
			
    str = XmStringCreateLtoR("Choose one:", XmSTRING_DEFAULT_CHARSET);
    ComboBox1 = XtVaCreateManagedWidget("combobox1", xmComboBoxWidgetClass, Form, 
			XmNeditable, False,
			XmNsorted, True,  
			XmNleftAttachment, XmATTACH_FORM, 
			XmNleftOffset, 8, 
			XmNrightAttachment, XmATTACH_FORM,
			XmNrightOffset, 8, 
			XmNtopAttachment, XmATTACH_WIDGET, 
			XmNtopOffset, 8, 
			XmNtopWidget, Sepp, 
			XmNshowLabel, True, 
			XmNlabelString, str,
			NULL);
    XmStringFree(str);
    /* Put string unordered into the combo box! They'll get sorted
     * by the box.
     */
    str = XmStringCreateLtoR("William the conquerior", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("Karl der Gro\337e", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("Henry VIII & his chicken band", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("Louis XIV", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("Louis de Funes", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("Helmut Kohl", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("James Major", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("James Bond", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("Billy Boy (M$ Windoze)", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("Francois Mitterand", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox1, str, 0);
    XmComboBoxSelectItem(ComboBox1, str, False);
    XmStringFree(str);

    str = XmStringCreateLtoR("Choose/edit:", XmSTRING_DEFAULT_CHARSET);
    ComboBox2 = XtVaCreateManagedWidget("combobox2", xmComboBoxWidgetClass, Form, 
			XmNeditable, True,
			XmNsorted, True,  
			XmNleftAttachment, XmATTACH_FORM, 
			XmNleftOffset, 8, 
			XmNrightAttachment, XmATTACH_FORM,
			XmNrightOffset, 8, 
			XmNtopAttachment, XmATTACH_WIDGET, 
			XmNtopOffset, 8, 
			XmNtopWidget, ComboBox1, 
			XmNshowLabel, True, 
			XmNlabelString, str, 
			NULL);
    str = XmStringCreateLtoR("item can be edited after choosing it", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox2, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("just to fill the list", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox2, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("so it contains more entries", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox2, str, 0); XmStringFree(str);

    str = XmStringCreateLtoR("Static ComboBox:", XmSTRING_DEFAULT_CHARSET);
    ComboBox3 = XtVaCreateManagedWidget("combobox3", xmComboBoxWidgetClass, Form, 
			XmNeditable, True,
			XmNstaticList, True,
			XmNsorted, False,
			XmNcolumns, 30,  
			XmNleftAttachment, XmATTACH_FORM, 
			XmNleftOffset, 8, 
			XmNrightAttachment, XmATTACH_FORM,
			XmNrightOffset, 8, 
			XmNtopAttachment, XmATTACH_WIDGET,
			XmNtopOffset, 8, 
			XmNtopWidget, ComboBox2, 
			XmNshowLabel, True, 
			XmNlabelString, str, 
			NULL);
    XmStringFree(str);
    str = XmStringCreateLtoR("ComboBox (noneditable)", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox3, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("ComboBox (editable)", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox3, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("ComboBox (editable & static List)", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox3, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("Center widget", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox3, str, 0); XmStringFree(str);
    str = XmStringCreateLtoR("The ButtonFace Library", XmSTRING_DEFAULT_CHARSET);
    XmComboBoxAddItem(ComboBox3, str, 0); XmStringFree(str); 

    Sepp = XtVaCreateManagedWidget("separator", xmSeparatorWidgetClass, Form, 
			XmNleftAttachment, XmATTACH_FORM, 
			XmNrightAttachment, XmATTACH_FORM,
			XmNtopAttachment, XmATTACH_WIDGET, 
			XmNtopOffset, 8, 
			XmNtopWidget, ComboBox3, 
			NULL); 

    str = XmStringCreateLtoR(
"xmComboBoxWidgetClass Demo\n\nby Harald Albrecht\n\n\
albrecht@igpm.rwth-aachen.de", XmSTRING_DEFAULT_CHARSET); 
    Label = XtVaCreateManagedWidget("label", xmLabelWidgetClass, Form, 
			XmNlabelString, str, 
			XmNleftAttachment, XmATTACH_FORM, 
			XmNleftOffset, 80, 
			XmNrightAttachment, XmATTACH_FORM, 
			XmNrightOffset, 80, 
			XmNbottomAttachment, XmATTACH_FORM, 
			XmNbottomOffset, 24, 
			XmNtopAttachment, XmATTACH_WIDGET, 
			XmNtopWidget, Sepp, 
			XmNtopOffset, 24, 
			NULL); 
    XmStringFree(str);

    XtRealizeWidget(TopLevel);

    XtAppMainLoop(AppContext);
    return 0; /* Never will reach this */
} /* main */


/* End of ComboBoxDemo.c */
