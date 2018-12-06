/*
 *  Copyright (C) 2007 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __MIRMAN_H
#define __MIRMAN_H

#include "clamav-types.h"
#include "freshclamcodes.h"

typedef enum mir_status_tag {
    MIRROR_OK=0,
    MIRROR_FAILURE,
    MIRROR_IGNORE__PREV_ERRS,
    MIRROR_IGNORE__OUTDATED_VERSION
} mir_status_t;

typedef enum mir_ignore_tag {
    IGNORE_NO=0,
    IGNORE_LONGTERM,
    IGNORE_SHORTTERM
} mir_ignore_t;

struct mirdat_ip
{
    uint32_t ip4;               /* IPv4 address */
    time_t atime;             /* last access time */
    uint32_t succ;              /* number of successful downloads from this ip */
    uint32_t fail;              /* number of failures */
    uint8_t ignore;             /* ignore flag */
    uint32_t ip6[4];            /* IPv6 address */
    char res[16];               /* reserved */
};

struct mirdat
{
    uint8_t active;             /* 1 if active, 2 if disabled */
    unsigned int num;           /* number of mirrors */
    uint32_t currip[4];         /* IP currently attempting */
    uint32_t af;                /* AF_INET or AF_INET6 for current IP */
    uint32_t dbflevel;          /* functionality level of current database */
    struct mirdat_ip *mirtab;   /* mirror table of known mirror IP addresses */
};

/**
 * @brief   Read mirrors.dat into an existing mirdat structur.
 *
 * @param file          The filename (probably mirrors.dat).
 * @param mdat          An existing mirdat structure. Must not be NULL.
 * @param active        1 - active, 0 - inactive (e.g. when using private mirrors or proxies).
 * @return fc_error_t   FC_SUCCESS or an error code.
 */
fc_error_t mirman_read(const char *file, struct mirdat *mdat, uint8_t active);

/**
 * @brief   Check if a mirror is should be ignored, if it's in the mirror table.
 *
 * Will add the mirror to the table if it isn't in the table.
 *
 * @param ip                    The mirror in question.
 * @param af                    AF_INET or AF_INET6.
 * @param mdat                  The mirrors.dat structure.
 * @param[out] md               A pointer to the mirror in mdat
 * @param[out] mirror_status    MIRROR_OK  or an ignore reason, such as:
 *                              MIRROR_IGNORE__PREV_ERRS  or
 *                              MIRROR_IGNORE__OUTDATED_VERSION
 * @return fc_error_t           FC_SUCCESS or an FCE error code.
 */
fc_error_t mirman_check(uint32_t * ip, int af, struct mirdat *mdat,
                        struct mirdat_ip **md, mir_status_t *mirror_status);

/**
 * @brief   Update the mirdat structure with the current mirror status
 *
 * @param ip            IP of current mirror.
 * @param af            AF_INET or AF_INET6.
 * @param mdat          The mirrors.dat structure.
 * @param error         FC_SUCCESS or an FCE error code.
 * @return fc_error_t   FC_SUCCESS or an FCE error code.
 */
fc_error_t mirman_update(uint32_t * ip, int af, struct mirdat *mdat, fc_error_t mirror_status);

/**
 * @brief   Print out the mirror info.
 *
 * @param mdat  The mirdat struct.
 */
void mirman_list(const struct mirdat *mdat);

/**
 * @brief   Remove "ignore" flag on mirrors.
 *
 * @param mdat  Structure
 * @param mode  1: Whitelist _all_ mirrors.
 *              2: Whitelist only mirrors that were in Short-Term ignore.
 */
void mirman_whitelist(struct mirdat *mdat, unsigned int mode);

/**
 * @brief   Update mirrors.dat with the current mirdat struct info.
 *
 * @param file          The filename to write to (probably "mirrors.dat")
 * @param dir           The database directory to store the file in.
 * @param mdat          The mirdat struct to write to disk.
 * @return fc_error_t   FC_SUCCESS or an error code.
 */
fc_error_t mirman_write(const char *file, const char *dir, struct mirdat *mdat);

/**
 * @brief   Free up the mirror table in the mirdat structure.
 *
 * Does not attempt to free mdat itself.
 *
 * @param mdat  The mirdat structure.
 */
void mirman_free(struct mirdat *mdat);

#endif
