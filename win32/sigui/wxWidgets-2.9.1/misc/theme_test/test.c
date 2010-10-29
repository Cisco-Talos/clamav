
#include <gtk/gtk.h>

/* This function rotates the position of the tabs */
void rotate_book (GtkButton *button, GtkNotebook *notebook)
{
    gtk_notebook_set_tab_pos (notebook, (notebook->tab_pos +1) %4);
}

/* Add/Remove the page tabs and the borders */
void tabsborder_book (GtkButton *button, GtkNotebook *notebook)
{
    gint tval = FALSE;
    gint bval = FALSE;
    if (notebook->show_tabs == 0)
	    tval = TRUE; 
    if (notebook->show_border == 0)
	    bval = TRUE;
    
    gtk_notebook_set_show_tabs (notebook, tval);
    gtk_notebook_set_show_border (notebook, bval);
}

/* Remove a page from the notebook */
void remove_book (GtkButton *button, GtkNotebook *notebook)
{
    gint page;
    
    page = gtk_notebook_get_current_page(notebook);
    gtk_notebook_remove_page (notebook, page);
    /* Need to refresh the widget -- 
     This forces the widget to redraw itself. */
    gtk_widget_draw(GTK_WIDGET(notebook), NULL);
}

void delete (GtkWidget *widget, GtkWidget *event, gpointer data)
{
    gtk_main_quit ();
}

void assign_new_style(GtkWidget *widget)
{
    GtkStyle *default_style,*new_style;
    
    default_style = gtk_rc_get_style( widget );

    if (!default_style)
        default_style = gtk_widget_get_default_style();

    new_style = gtk_style_copy( default_style );
    new_style->engine_data = default_style->engine_data;
    new_style->klass = default_style->klass;
    
    gtk_widget_set_style( widget, new_style );
}


int main (int argc, char *argv[])
{
    GtkWidget *window;
    GtkWidget *button;
    GtkWidget *table;
    GtkWidget *notebook;
    GtkWidget *frame;
    GtkWidget *label;
    
    gtk_init (&argc, &argv);
    
    window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    
    gtk_signal_connect (GTK_OBJECT (window), "delete_event",
			GTK_SIGNAL_FUNC (delete), NULL);
    
    gtk_container_set_border_width (GTK_CONTAINER (window), 10);

    table = gtk_table_new(3,6,FALSE);
    gtk_container_add (GTK_CONTAINER (window), table);
    
    /* Create a new notebook, place the position of the tabs */
    notebook = gtk_notebook_new ();
    assign_new_style( notebook );
    
    gtk_notebook_set_tab_pos (GTK_NOTEBOOK (notebook), GTK_POS_TOP);
    gtk_table_attach_defaults(GTK_TABLE(table), notebook, 0,6,0,1);
    gtk_widget_show(notebook);
    
    /* Now finally lets prepend pages to the notebook */
    
	frame = gtk_frame_new ("frame");
	gtk_container_set_border_width (GTK_CONTAINER (frame), 10);
	gtk_widget_set_usize (frame, 100, 75);
	gtk_widget_show (frame);
	
	label = gtk_label_new ("label");
    assign_new_style( label );
	gtk_container_add (GTK_CONTAINER (frame), label);
	gtk_widget_show (label);
    
	label = gtk_label_new ("page");
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), frame, label);
	

	frame = gtk_frame_new ("frame");
	gtk_container_set_border_width (GTK_CONTAINER (frame), 10);
	gtk_widget_set_usize (frame, 100, 75);
	gtk_widget_show (frame);
	
	label = gtk_button_new_with_label ("button");
    assign_new_style( label );
	gtk_container_add (GTK_CONTAINER (frame), label);
	gtk_widget_show (label);
    
	label = gtk_label_new ("page");
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), frame, label);

	

	frame = gtk_frame_new ("frame");
	gtk_container_set_border_width (GTK_CONTAINER (frame), 10);
	gtk_widget_set_usize (frame, 100, 75);
	gtk_widget_show (frame);
	
	label = gtk_check_button_new_with_label ("check button");
    assign_new_style( label );
	gtk_container_add (GTK_CONTAINER (frame), label);
	gtk_widget_show (label);
    
	label = gtk_label_new ("page");
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), frame, label);
	

	frame = gtk_frame_new ("frame");
	gtk_container_set_border_width (GTK_CONTAINER (frame), 10);
	gtk_widget_set_usize (frame, 100, 75);
	gtk_widget_show (frame);
	
	label = gtk_radio_button_new_with_label (NULL, "radio button");
    assign_new_style( label );
	gtk_container_add (GTK_CONTAINER (frame), label);
	gtk_widget_show (label);
    
	label = gtk_label_new ("page");
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), frame, label);
	

	frame = gtk_frame_new ("frame");
	gtk_container_set_border_width (GTK_CONTAINER (frame), 10);
	gtk_widget_set_usize (frame, 100, 75);
	gtk_widget_show (frame);
	
	label = gtk_entry_new ();
    assign_new_style( label );
	gtk_container_add (GTK_CONTAINER (frame), label);
	gtk_widget_show (label);
    
	label = gtk_label_new ("page");
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), frame, label);
    
    /* Create a bunch of buttons */
    button = gtk_button_new_with_label ("close");
    gtk_signal_connect_object (GTK_OBJECT (button), "clicked",
			       GTK_SIGNAL_FUNC (delete), NULL);
    gtk_table_attach_defaults(GTK_TABLE(table), button, 0,1,1,2);
    gtk_widget_show(button);
    
    button = gtk_button_new_with_label ("next page");
    gtk_signal_connect_object (GTK_OBJECT (button), "clicked",
			       (GtkSignalFunc) gtk_notebook_next_page,
			       GTK_OBJECT (notebook));
    gtk_table_attach_defaults(GTK_TABLE(table), button, 1,2,1,2);
    gtk_widget_show(button);
    
    button = gtk_button_new_with_label ("prev page");
    gtk_signal_connect_object (GTK_OBJECT (button), "clicked",
			       (GtkSignalFunc) gtk_notebook_prev_page,
			       GTK_OBJECT (notebook));
    gtk_table_attach_defaults(GTK_TABLE(table), button, 2,3,1,2);
    gtk_widget_show(button);
    
    button = gtk_button_new_with_label ("tab position");
    gtk_signal_connect (GTK_OBJECT (button), "clicked",
                        (GtkSignalFunc) rotate_book, GTK_OBJECT(notebook));
    gtk_table_attach_defaults(GTK_TABLE(table), button, 3,4,1,2);
    gtk_widget_show(button);
    
    button = gtk_button_new_with_label ("tabs/border on/off");
    gtk_signal_connect (GTK_OBJECT (button), "clicked",
                        (GtkSignalFunc) tabsborder_book,
                        GTK_OBJECT (notebook));
    gtk_table_attach_defaults(GTK_TABLE(table), button, 4,5,1,2);
    gtk_widget_show(button);
    
    button = gtk_button_new_with_label ("remove page");
    gtk_signal_connect (GTK_OBJECT (button), "clicked",
                        (GtkSignalFunc) remove_book,
                        GTK_OBJECT(notebook));
    gtk_table_attach_defaults(GTK_TABLE(table), button, 5,6,1,2);
    gtk_widget_show(button);
    
    gtk_widget_show(table);
    gtk_widget_show(window);
    
    gtk_main ();
    
    return(0);
}
/* example-end */
