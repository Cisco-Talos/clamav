/*
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Selim Menouar, Verene Houdebine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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


#include "shared/misc.h"
#include "shared/output.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifndef PRELUDE
void prelude_logging(const char *filename, const char *virname, const char *virhash, int virsize){
    logg("You have to compile with libprelude using ./configure --enable-prelude\n");
}
#else

#include <libprelude/prelude.h>

#define ANALYZER_MODEL "ClamAV"
#define ANALYZER_CLASS "AntiVirus"
#define ANALYZER_MANUFACTURER "http://www.sourcefire.com"


static prelude_client_t *prelude_client;

int idmef_analyzer_setup(idmef_analyzer_t *analyzer, const char *analyzer_name){
    int ret;
    prelude_string_t *str;

    /* alert->analyzer->name */
    ret = idmef_analyzer_new_name(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, analyzer_name);

    /* alert->analyzer->model */
    ret = idmef_analyzer_new_model(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_MODEL );

    /* alert->analyzer->class */
    ret = idmef_analyzer_new_class(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_CLASS);

    /* alert->analyzer->manufacturer */
    ret = idmef_analyzer_new_manufacturer(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_MANUFACTURER);

    /* alert->analyzer->version */
    ret = idmef_analyzer_new_version(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, get_version());

    return 0;
}

int prelude_initialize_client(const char *analyzer_name){
    int ret;

    prelude_client = NULL;

    ret = prelude_init(0, NULL);
    if ( ret < 0 )  {
        logg("Unable to initialize the prelude library : %s", prelude_strerror(ret));
        return -1;
    }


    ret = prelude_client_new(&prelude_client, analyzer_name);
    if ( ret < 0 )  {
        logg("Unable to create a prelude client object : %s", prelude_strerror(ret));
        return -1;
    }

    ret = idmef_analyzer_setup(prelude_client_get_analyzer(prelude_client), analyzer_name);
    if ( ret < 0 )  {
        logg("%s", prelude_strerror(ret));
        return -1;
    }

    ret = prelude_client_start(prelude_client);
    if ( ret < 0 || ! prelude_client ) {
        logg("Unable to start prelude client : %s", prelude_strerror(ret));
        prelude_client_destroy(prelude_client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
        return -1;
    }

    ret = prelude_client_set_flags(prelude_client, PRELUDE_CLIENT_FLAGS_ASYNC_SEND|PRELUDE_CLIENT_FLAGS_ASYNC_TIMER);
    if ( ret < 0) {
        logg("Unable to send asynchronous send and timer : %s", prelude_strerror(ret));
        prelude_client_destroy(prelude_client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
        return -1;
    }

    return 0;
}

int add_string_additional_data(idmef_alert_t *alert, const char *meaning, const char *ptr){
    int ret;
    prelude_string_t *str;
    idmef_additional_data_t *ad;
    idmef_data_t *data;

    ret = idmef_alert_new_additional_data(alert, &ad, IDMEF_LIST_APPEND);
    if ( ret < 0 )
        return ret;

    idmef_additional_data_set_type(ad, IDMEF_ADDITIONAL_DATA_TYPE_STRING);

    idmef_additional_data_new_data(ad, &data);

    ret = idmef_data_set_char_string_ref(data, ptr);
    if ( ret < 0)
        return ret;


    ret = idmef_additional_data_new_meaning(ad, &str);
    if ( ret < 0)
        return ret;

    ret = prelude_string_set_ref(str, meaning);
    if ( ret < 0 )
        return ret;

    return 0;
}

int add_int_additional_data(idmef_alert_t *alert, const char *meaning, int data){
    int ret;
    prelude_string_t *str;
    idmef_additional_data_t *ad;

    ret = idmef_alert_new_additional_data(alert, &ad, IDMEF_LIST_APPEND);
    if ( ret < 0 )
        return ret;

    idmef_additional_data_set_integer(ad, data);

    ret = idmef_additional_data_new_meaning(ad, &str);
    if ( ret < 0)
        return ret;

    ret = prelude_string_set_ref(str, meaning);
    if ( ret < 0 )
        return ret;

    return 0;
}


void prelude_logging(const char *filename, const char *virname, const char *virhash, int virsize){
    int ret;
    idmef_message_t *idmef = NULL;
    idmef_alert_t *alert;
    idmef_classification_t *class;
    prelude_string_t *str;
    idmef_target_t *target;
    idmef_file_t *file;

    ret = idmef_message_new(&idmef);
    if ( ret < 0 )
        goto err;

    ret = idmef_message_new_alert(idmef, &alert);
    if ( ret < 0 )
        goto err;

    ret = idmef_alert_new_classification(alert, &class);
    if ( ret < 0 )
        goto err;

    ret = idmef_classification_new_text(class, &str);
    if ( ret < 0 )
        goto err;

    prelude_string_set_constant(str, "Virus Found");

    ret = idmef_alert_new_target(alert, &target, 0);
    if ( ret < 0 )
        goto err;

    ret = idmef_target_new_file(target, &file, 0);
    if ( ret < 0 )
        goto err;

    ret = idmef_file_new_path(file, &str);
    if ( ret < 0 )
        goto err;

    prelude_string_set_ref(str, filename);

    if ( virname != NULL ) {
        ret = add_string_additional_data(alert, "virname", virname);
        if ( ret < 0 )
            goto err;
    }

    if ( virhash != NULL){
        ret = add_string_additional_data(alert, "virhash", virhash);
        if ( ret < 0 )
            goto err;
    }
    
    ret = add_int_additional_data(alert, "virsize", virsize);
    if ( ret < 0 )
        goto err;

    logg("le client : %s", prelude_client_get_config_filename(prelude_client));
    prelude_client_send_idmef(prelude_client, idmef);
    idmef_message_destroy(idmef);

    return;

err:
    if (idmef != NULL)
        idmef_message_destroy(idmef);

    logg("%s error: %s", prelude_strsource(ret), prelude_strerror(ret));
    return;
}
#endif
