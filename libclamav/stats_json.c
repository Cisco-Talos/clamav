/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <errno.h>

#if defined(_WIN32)
#include <WinSock2.h>
#include <Windows.h>
#endif

#include "libclamav/others.h"
#include "libclamav/clamav.h"

#define JSON_BUFSZ 512
#define SAMPLE_PREFIX "sample_"

char *hex_encode(char *buf, char *data, size_t len);
char *ensure_bufsize(char *buf, size_t *oldsize, size_t used, size_t additional);
char *export_stats_to_json(struct cl_engine *engine, cli_intel_t *intel);

char *hex_encode(char *buf, char *data, size_t len)
{
    size_t i;
    char *p;
    int t;

    p = (buf != NULL) ? buf : calloc(1, (len*2)+1);
    if (!(p))
        return NULL;

    for (i=0; i<len; i++) {
        t = data[i] & 0xff;
        sprintf(p+(i*2), "%02x", t);
    }

    return p;
}

char *ensure_bufsize(char *buf, size_t *oldsize, size_t used, size_t additional)
{
    char *p=buf;

    if (*oldsize - used < additional) {
        p = realloc(buf, *oldsize + JSON_BUFSZ);
        if (!(p)) {
            cli_errmsg("ensure_bufsize: Could not allocate more memory: %s (errno: %d)\n", strerror(errno), errno);
            free(buf);
            return NULL;
        }

        *oldsize += JSON_BUFSZ;
    }

    return p;
}

char *export_stats_to_json(struct cl_engine *engine, cli_intel_t *intel)
{
    char *buf=NULL, *hostid, md5[33];
    cli_flagged_sample_t *sample;
    size_t bufsz, curused, i, j;

    if (!(intel->hostid))
        if ((engine->cb_stats_get_hostid))
            intel->hostid = engine->cb_stats_get_hostid(engine->stats_data);

    hostid = (intel->hostid != NULL) ? intel->hostid : STATS_ANON_UUID;

    buf = calloc(1, JSON_BUFSZ);
    if (!(buf))
        return NULL;

    bufsz = JSON_BUFSZ;
    sprintf(buf, "{\n\t\"hostid\": \"%s\",\n", hostid);
    if (intel->host_info)
        sprintf(buf+strlen(buf), "\t\"host_info\": \"%s\",\n", intel->host_info);

    sprintf(buf+strlen(buf), "\t\"samples\": [\n");
    curused = strlen(buf);

    for (sample = intel->samples; sample != NULL; sample = sample->next) {
        if (sample->hits == 0)
            continue;

        memset(md5, 0x00, sizeof(md5));
        hex_encode(md5, sample->md5, sizeof(sample->md5));

        buf = ensure_bufsize(buf, &bufsz, curused, strlen(md5) + sizeof(SAMPLE_PREFIX) + 45);
        if (!(buf))
            return NULL;

        snprintf(buf+curused, bufsz-curused, "\t\t\t{\n");
        curused += strlen(buf+curused);

        buf = ensure_bufsize(buf, &bufsz, curused, sizeof("\t\t\t\"hash\": \"\",\n") + strlen(md5) + 1);
        if (!(buf))
            return NULL;

        snprintf(buf+curused, bufsz-curused, "\t\t\t\"hash\": \"%s\",\n", md5);
        curused += strlen(buf+curused);

        /* Reuse the md5 variable for serializing the number of hits */
        snprintf(md5, sizeof(md5), "%u", sample->hits);

        buf = ensure_bufsize(buf, &bufsz, curused, strlen(md5) + 20);
        if (!(buf))
            return NULL;

        snprintf(buf+curused, bufsz-curused, "\t\t\t\"hits\": %s,\n", md5);
        curused += strlen(buf+curused);

        snprintf(md5, sizeof(md5), "%u", sample->size);

        buf = ensure_bufsize(buf, &bufsz, curused, strlen(md5) + 20);
        if (!(buf))
            return NULL;

        snprintf(buf+curused, bufsz-curused, "\t\t\t\"size\": %s,\n", md5);
        curused += strlen(buf+curused);

        buf = ensure_bufsize(buf, &bufsz, curused, 30);
        if (!(buf))
            return NULL;

        if ((sample->sections) && (sample->sections->nsections)) {
            buf = ensure_bufsize(buf, &bufsz, curused, 30);
            if (!(buf))
                return NULL;

            snprintf(buf+curused, bufsz-curused, "\t\t\t\"sections\": [\n");
            curused += strlen(buf+curused);

            for (i=0; i < sample->sections->nsections; i++) {
                buf = ensure_bufsize(buf, &bufsz, curused, 30);
                if (!(buf))
                    return NULL;

                snprintf(buf+curused, bufsz-curused, "\t\t\t\t%s{\n", (i > 0) ? "," : "");
                curused += strlen(buf+curused);

                buf = ensure_bufsize(buf, &bufsz, curused, 65);
                if (!(buf))
                    return NULL;

                memset(md5, 0x00, sizeof(md5));
                for (j=0; j < 16; j++)
                    sprintf(md5+(j*2), "%02x", sample->sections->sections[i].md5[j]);

                snprintf(buf+curused, bufsz-curused, "\t\t\t\t\t\"hash\": \"%s\",\n", md5);
                curused += strlen(buf+curused);

                buf = ensure_bufsize(buf, &bufsz, curused, 65);
                if (!(buf))
                    return NULL;

                snprintf(buf+curused, bufsz-curused, "\t\t\t\t\t\"size\": %llu\n", (long long unsigned)sample->sections->sections[i].len);
                curused += strlen(buf+curused);

                buf = ensure_bufsize(buf, &bufsz, curused, 30);
                if (!(buf))
                    return NULL;

                snprintf(buf+curused, bufsz-curused, "\t\t\t\t}\n");
                curused += strlen(buf+curused);
            }

            buf = ensure_bufsize(buf, &bufsz, curused, 20);
            if (!(buf))
                return NULL;

            snprintf(buf+curused, bufsz-curused, "\t\t\t],\n");
            curused += strlen(buf+curused);
        }

        snprintf(buf+curused, bufsz-curused, "\t\t\t\"virus_names\": [ ");
        curused += strlen(buf+curused);

        for (i=0; sample->virus_name[i] != NULL; i++) {
            buf = ensure_bufsize(buf, &bufsz, curused, strlen(sample->virus_name[i]) + 5);
            if (!(buf))
                return NULL;

            snprintf(buf+curused, bufsz-curused, "%s\"%s\"", (i > 0) ? ", " : "", sample->virus_name[i]);
            curused += strlen(buf+curused);
        }

        buf = ensure_bufsize(buf, &bufsz, curused, 10);
        if (!(buf))
            return NULL;

        snprintf(buf+curused, bufsz-curused, " ]\n\t\t}%s\n", (sample->next != NULL) ? "," : "");
        curused += strlen(buf+curused);
    }

    buf = ensure_bufsize(buf, &bufsz, curused, 15);
    if (!(buf))
        return NULL;

    snprintf(buf+curused, bufsz-curused, "\t]\n}\n");

    return buf;
}
