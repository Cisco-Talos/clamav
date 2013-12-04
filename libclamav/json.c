#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <errno.h>

#include "libclamav/others.h"
#include "libclamav/clamav.h"

#define JSON_BUFSZ 512
#define SAMPLE_PREFIX "sample_"

char *hex_encode(char *buf, char *data, size_t len)
{
    size_t i;
    char *p;

    p = (buf != NULL) ? buf : calloc(1, (len*2)+1);
    if (!(p))
        return NULL;

    for (i=0; i<len; i++)
        sprintf(p+(i*2), "%02x", *(int *)(data+i) & 0xff);

    return p;
}

const char *get_sample_type(cli_intel_sample_type_t type)
{
    switch (type) {
        case WHOLEFILE:
            return "whole-file";
        case PESECTION:
            return "PE section";
        default:
            return NULL;
    }
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
    char *buf=NULL, *p, *hostid, md5[33];
    const char *type;
    cli_flagged_sample_t *sample;
    size_t bufsz, curused, i;

    if (!(intel->hostid))
        if ((engine->cb_stats_get_hostid))
            intel->hostid = engine->cb_stats_get_hostid(engine->stats_data);

    hostid = (intel->hostid != NULL) ? intel->hostid : STATS_ANON_UUID;

    buf = calloc(1, JSON_BUFSZ);
    if (!(buf))
        return NULL;

    bufsz = JSON_BUFSZ;
    sprintf(buf, "{\n\t\"hostid\": \"%s\",\n", hostid);
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

        snprintf(buf+curused, bufsz-curused, "\t\t\{\n");
        curused += strlen(buf+curused);

        buf = ensure_bufsize(buf, &bufsz, curused, sizeof("\t\t\t\"hash\": \"\",\n") + strlen(md5) + 1);
        if (!(buf))
            return NULL;

        snprintf(buf+curused, bufsz-curused, "\t\t\t\"hash\": \"%s\",\n", md5);
        curused += strlen(buf+curused);

        type = get_sample_type(sample->type);
        if (!(type)) {
            free(buf);
            return NULL;
        }

        buf = ensure_bufsize(buf, &bufsz, curused, sizeof("type") + strlen(type) + 15);
        if (!(buf))
            return NULL;

        snprintf(buf+curused, bufsz-curused, "\t\t\t\"type\": \"%s\",\n", type);
        curused += strlen(buf+curused);

        /* Reuse the md5 variable for serializing the number of hits */
        snprintf(md5, sizeof(md5), "%u", sample->hits);

        buf = ensure_bufsize(buf, &bufsz, curused, strlen(md5) + 20);
        if (!(buf))
            return NULL;

        snprintf(buf+curused, bufsz-curused, "\t\t\t\"hits\": \"%s\",\n", md5);
        curused += strlen(buf+curused);

        snprintf(md5, sizeof(md5), "%zu", sample->size);

        buf = ensure_bufsize(buf, &bufsz, curused, strlen(md5) + 20);
        if (!(buf))
            return NULL;

        snprintf(buf+curused, bufsz-curused, "\t\t\t\"size\": \"%s\",\n", md5);
        curused += strlen(buf+curused);

        buf = ensure_bufsize(buf, &bufsz, curused, 30);
        if (!(buf))
            return NULL;

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
