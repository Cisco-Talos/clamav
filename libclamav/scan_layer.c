/*
 *  Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Valerie Snyder
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

#include "scan_layer.h"

#include "clamav_rust.h"

/**
 * @brief Get the file map associated with a scan layer.
 *
 * @param layer                 The scan layer to query.
 * @param fmap_out              Pointer to a variable to receive the file map.
 * @return cl_error_t           CL_SUCCESS if successful.
 */
extern cl_error_t cl_scan_layer_get_fmap(
    cl_scan_layer_t *layer,
    cl_fmap_t **fmap_out)
{
    cl_error_t status = CL_ERROR;

    cli_scan_layer_t *l = (cli_scan_layer_t *)layer;

    if (!layer || !fmap_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *fmap_out = l->fmap;
    status    = CL_SUCCESS;

done:
    return status;
}

/**
 * @brief Get the parent layer of a scan layer.
 *
 * @param layer                 The scan layer to query.
 * @param parent_layer_out      Pointer to a variable to receive the parent layer.
 * @return cl_error_t           CL_SUCCESS if successful.
 */
extern cl_error_t cl_scan_layer_get_parent_layer(
    cl_scan_layer_t *layer,
    cl_scan_layer_t **parent_layer_out)
{
    cl_error_t status = CL_ERROR;

    cli_scan_layer_t *l = (cli_scan_layer_t *)layer;

    if (!layer || !parent_layer_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *parent_layer_out = (cl_scan_layer_t *)l->parent;
    status            = CL_SUCCESS;

done:
    return status;
}

/**
 * @brief Get the file type of a scan layer.
 *
 * The file type as clamav currently believes it to be.
 * It may change later in the scan, so consider using `clcb_file_type_correction`
 * callback to access the file again if it is re-typed.
 *
 * @param layer                 The scan layer to query.
 * @param type_out              Pointer to a variable to receive the file type.
 * @return cl_error_t           CL_SUCCESS if successful.
 */
extern cl_error_t cl_scan_layer_get_type(
    cl_scan_layer_t *layer,
    const char **type_out)
{
    cl_error_t status = CL_ERROR;

    cli_scan_layer_t *l = (cli_scan_layer_t *)layer;

    if (!layer || !type_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *type_out = cli_ftname(l->type);
    status    = CL_SUCCESS;

done:
    return status;
}

/**
 * @brief Get the recursion level of a scan layer.
 *
 * @param layer                 The scan layer to query.
 * @param recursion_level_out   Pointer to a variable to receive the recursion level.
 * @return cl_error_t           CL_SUCCESS if successful.
 */
extern cl_error_t cl_scan_layer_get_recursion_level(
    cl_scan_layer_t *layer,
    uint32_t *recursion_level_out)
{
    cl_error_t status = CL_ERROR;

    cli_scan_layer_t *l = (cli_scan_layer_t *)layer;

    if (!layer || !recursion_level_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *recursion_level_out = l->recursion_level;
    status               = CL_SUCCESS;

done:
    return status;
}

/**
 * @brief Get the object ID of a scan layer.
 *
 * Object ID is a unique identifier for the scan layer. It counts up from 0, although the callback interface
 * may skip some IDs if the scan layer is processed immediately rather than being handled as distinct file type.
 * For example, HTML may be normalized several ways and they're each given an Object ID, but we immediately
 * pattern match them and do not handle them as distinct file types that were contained within the HTML.
 *
 * @param layer                 The scan layer to query.
 * @param object_id_out         Pointer to a variable to receive the object ID.
 * @return cl_error_t           CL_SUCCESS if successful.
 */
extern cl_error_t cl_scan_layer_get_object_id(
    cl_scan_layer_t *layer,
    uint64_t *object_id_out)
{
    cl_error_t status = CL_ERROR;

    cli_scan_layer_t *l = (cli_scan_layer_t *)layer;

    if (!layer || !object_id_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *object_id_out = l->object_id;
    status         = CL_SUCCESS;

done:
    return status;
}

/**
 * @brief Get the last detected alert (aka Strong indicator) name from a scan layer.
 *
 * @param layer                 The scan layer to query.
 * @param alert_name_out        Pointer to a variable to receive the alert name.
 *                              If the layer has no alerts, this will be set to NULL.
 * @return cl_error_t           CL_SUCCESS if successful.
 */
extern cl_error_t cl_scan_layer_get_last_alert(
    cl_scan_layer_t *layer,
    const char **alert_name_out)
{
    cl_error_t status = CL_ERROR;

    cli_scan_layer_t *l = (cli_scan_layer_t *)layer;

    if (!layer || !alert_name_out) {
        status = CL_ENULLARG;
        goto done;
    }

    if (NULL != l->evidence) {
        const char *alert_name = evidence_get_last_alert(l->evidence);
        if (alert_name) {
            *alert_name_out = alert_name;
        } else {
            *alert_name_out = NULL;
        }
    } else {
        *alert_name_out = NULL;
    }

    status = CL_SUCCESS;

done:
    return status;
}

/**
 * @brief Get the attributes of a scan layer.
 *
 * @param layer                 The scan layer to query.
 * @param attributes_out        Pointer to a variable to receive the layer attributes.
 * @return cl_error_t           CL_SUCCESS if successful.
 */
extern cl_error_t cl_scan_layer_get_attributes(
    cl_scan_layer_t *layer,
    uint32_t *attributes_out)
{
    cl_error_t status = CL_ERROR;

    cli_scan_layer_t *l = (cli_scan_layer_t *)layer;

    if (!layer || !attributes_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *attributes_out = l->attributes;
    status          = CL_SUCCESS;

done:
    return status;
}
