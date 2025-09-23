/*
 * Author: 웃 Sebastian Andrzej Siewior
 * Summary: Glue code for libmspack handling.
 *
 * Acknowledgements: ClamAV uses Stuart Caie's libmspack to parse as number of
 *                   Microsoft file formats.
 * ✉ sebastian @ breakpoint ̣cc
 */

#ifndef __LIBMSPACK_H__
#define __LIBMSPACK_H__

/**
 * @brief Check the CAB header for validity.
 *
 * @param fmap          The fmap containing the CAB file.
 * @param offset        Offset of the start of a CAB file within the current fmap.
 * @param size          The size of the CAB file.
 * @return cl_error_t
 */
cl_error_t cli_mscab_header_check(cli_ctx *ctx, size_t offset, size_t *size);

/**
 * @brief Open and extract a Microsoft CAB file, scanning each extracted file.
 *
 * @param ctx           Scan context
 * @param sfx_offset    Offset of the start of a CAB file within the current fmap.
 * @return cl_error_t   CL_SUCCESS on success, or an error code on failure.
 */
cl_error_t cli_scanmscab(cli_ctx *ctx, size_t sfx_offset);

/**
 * @brief Open and extract a Microsoft CHM file, scanning each extracted file.
 *
 * @param ctx           Scan context
 * @return cl_error_t   CL_SUCCESS on success, or an error code on failure.
 */
cl_error_t cli_scanmschm(cli_ctx *ctx);

#endif
