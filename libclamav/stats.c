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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#if !defined(_WIN32)
#if defined(C_SOLARIS)
#include <sys/utsname.h>
#else
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYSCTLBYNAME
#include <sys/sysctl.h>
#endif
#endif
#else
#include <Windows.h>
#include <tchar.h>
#endif

#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

#include <errno.h>

#include "libclamav/others.h"
#include "libclamav/clamav.h"
#include "libclamav/dconf.h"
#include "libclamav/stats_json.h"
#include "libclamav/stats.h"
#include "libclamav/hostid.h"
#include "libclamav/www.h"

#define DEBUG_STATS 0

static cli_flagged_sample_t *find_sample(cli_intel_t *intel, const char *virname, const unsigned char *md5, size_t size, stats_section_t *sections);
void free_sample(cli_flagged_sample_t *sample);

#if DEBUG_STATS
char *get_hash(unsigned char *md5)
{
    char *hash;
    int i;

    hash = calloc(1, 33);
    if (!(hash))
        return NULL;

    for (i=0; i<16; i++)
        sprintf(hash+(i*2), "%02x", md5[i]);

    return hash;
}

char *get_sample_names(char **names)
{
    char *ret;
    size_t n, i, sz;

    sz = 0;
    for (n=0; names[n] != NULL; n++)
        sz += strlen(names[n]);

    ret = calloc(1, sz + n + 1);
    if (!(ret))
        return NULL;

    for (i=0; names[i] != NULL; i++)
        sprintf(ret+strlen(ret), "%s%s", (i==0) ? "" : " ", names[i]);

    return ret;
}

void print_sample(cli_flagged_sample_t *sample)
{
    char *hash, *names;
    size_t i;

    if (!(sample))
        return;

    hash = get_hash(sample->md5);
    if (!(hash))
        return;

    cli_warnmsg("Sample[%s]:\n", hash);
    cli_warnmsg("    * Size: %zu\n", sample->size);
    cli_warnmsg("    * Hits: %u\n", sample->hits);

    free(hash);

    names = get_sample_names(sample->virus_name);
    if ((names))
        cli_warnmsg("    * Names: %s\n", names);

    if (sample->sections && sample->sections->nsections) {
        for (i=0; i < sample->sections->nsections; i++) {
            hash = get_hash(sample->sections->sections[i].md5);
            if ((hash)) {
                cli_warnmsg("    * Section[%zu] (%zu): %s\n", i, sample->sections->sections[i].len, hash);
                free(hash);
            }
        }
    }

    if ((names))
        free(names);
}
#endif

void clamav_stats_add_sample(const char *virname, const unsigned char *md5, size_t size, stats_section_t *sections, void *cbdata)
{
    cli_intel_t *intel;
    cli_flagged_sample_t *sample;
    size_t i;
    char **p;
    int err, submit=0;

    if (!(cbdata))
        return;

    intel = (cli_intel_t *)cbdata;
    if (!(intel->engine))
        return;

    if (intel->engine->dconf->stats & DCONF_STATS_DISABLED)
        return;

    /* First check if we need to submit stats based on memory/number limits */
    if ((intel->engine->cb_stats_get_size))
        submit = (intel->engine->cb_stats_get_size(cbdata) >= intel->maxmem);
    else
        submit = (clamav_stats_get_size(cbdata) >= intel->maxmem);

    if (submit == 0) {
        if ((intel->engine->cb_stats_get_num))
            submit = (intel->engine->cb_stats_get_num(cbdata) >= intel->maxsamples);
        else
            submit = (clamav_stats_get_num(cbdata) >= intel->maxsamples);
    }

    if (submit) {
        if ((intel->engine->cb_stats_submit)) {
            intel->engine->cb_stats_submit(intel->engine, cbdata);
        } else {
            if ((intel->engine->cb_stats_flush))
                intel->engine->cb_stats_flush(intel->engine, intel);

            return;
        }
    }

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_lock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_add_sample: locking mutex failed (err: %d): %s\n", err, strerror(err));
        return;
    }
#endif

    sample = find_sample(intel, virname, md5, size, sections);
    if (!(sample)) {
        if (!(intel->samples)) {
            sample = intel->samples = calloc(1, sizeof(cli_flagged_sample_t));
            if (!(sample))
                goto end;
        } else {
            sample = calloc(1, sizeof(cli_flagged_sample_t));
            if (!(sample))
                goto end;

            sample->next = intel->samples;
            intel->samples->prev = sample;
            intel->samples = sample;
        }

        if ((sample->virus_name)) {
            for (i=0; sample->virus_name[i] != NULL; i++)
                ;
            p = realloc(sample->virus_name, sizeof(char **) * (i + 1));
            if (!(p)) {
                free(sample->virus_name);
                free(sample);
                if (sample == intel->samples)
                    intel->samples = NULL;

                goto end;
            }

            sample->virus_name = p;
        } else {
            i=0;
            sample->virus_name = calloc(1, sizeof(char **));
            if (!(sample->virus_name)) {
                free(sample);
                if (sample == intel->samples)
                    intel->samples = NULL;

                goto end;
            }
        }

        sample->virus_name[i] = strdup((virname != NULL) ? virname : "[unknown]");
        if (!(sample->virus_name[i])) {
            free(sample->virus_name);
            free(sample);
            if (sample == intel->samples)
                intel->samples = NULL;

            goto end;
        }

        p = realloc(sample->virus_name, sizeof(char **) * (i+2));
        if (!(p)) {
            free(sample->virus_name);
            free(sample);
            if (sample == intel->samples)
                intel->samples = NULL;

            goto end;
        }

        sample->virus_name = p;
        sample->virus_name[i+1] = NULL;

        memcpy(sample->md5, md5, sizeof(sample->md5));
        sample->size = (uint32_t)size;
        intel->nsamples++;

        if (sections && sections->nsections && !(sample->sections)) {
            /* Copy the section data that has already been allocated. We don't care if calloc fails; just skip copying if it does. */
            sample->sections = calloc(1, sizeof(stats_section_t));
            if ((sample->sections)) {
                sample->sections->sections = calloc(sections->nsections, sizeof(struct cli_section_hash));
                if ((sample->sections->sections)) {
                    memcpy(sample->sections->sections, sections->sections, sections->nsections * sizeof(struct cli_section_hash));
                    sample->sections->nsections = sections->nsections;
                } else {
                    free(sample->sections);
                    sample->sections = NULL;
                }
            }
        }
    }

    sample->hits++;

end:
#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_add_sample: unlocking mutex failed (err: %d): %s\n", err, strerror(err));
    }
#endif
    return;
}

void clamav_stats_flush(struct cl_engine *engine, void *cbdata)
{
    cli_intel_t *intel;
    cli_flagged_sample_t *sample, *next;
    int err;

    if (!(cbdata) || !(engine))
        return;

    intel = (cli_intel_t *)cbdata;

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_lock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_flush: locking mutex failed (err: %d): %s\n", err, strerror(err));
        return;
    }
#endif

    for (sample=intel->samples; sample != NULL; sample = next) {
        next = sample->next;

        free_sample(sample);
    }

    intel->samples = NULL;
    intel->nsamples = 0;
    if (intel->hostid) {
        free(intel->hostid);
        intel->hostid = NULL;
    }

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err)
        cli_warnmsg("clamav_stats_flush: unlocking mutex failed (err: %d): %s\n", err, strerror(err));
#endif
}

void free_sample(cli_flagged_sample_t *sample)
{
    size_t i;

    if ((sample->virus_name)) {
        for (i=0; sample->virus_name[i] != NULL; i++)
            free(sample->virus_name[i]);

        free(sample->virus_name);
    }

    if ((sample->sections) && (sample->sections->nsections)) {
        free(sample->sections->sections);
        free(sample->sections);
    }

    free(sample);
}

void clamav_stats_submit(struct cl_engine *engine, void *cbdata)
{
    char *json;
    cli_intel_t *intel, myintel;
    cli_flagged_sample_t *sample, *next;
    int err;

    intel = (cli_intel_t *)cbdata;
    if (!(intel) || !(engine))
        return;

    if (engine->dconf->stats & DCONF_STATS_DISABLED)
        return;

    if (!(engine->cb_stats_get_hostid)) {
        /* Submitting stats is disabled due to HostID being turned off */
        if ((engine->cb_stats_flush))
            engine->cb_stats_flush(engine, cbdata);

        return;
    }

    cli_dbgmsg("stats - start\n");

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_lock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_submit: locking mutex failed (err: %d): %s\n", err, strerror(err));

        if ((intel->engine) && (intel->engine->cb_stats_flush))
            intel->engine->cb_stats_flush(intel->engine, cbdata);

        return;
    }
#endif

    /* Empty out the cached intelligence data so that other threads don't sit waiting to add data to the cache */
    memcpy(&myintel, intel, sizeof(cli_intel_t));
    intel->samples = NULL;
    intel->nsamples = 0;

    json = export_stats_to_json(engine, &myintel);

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_submit: unlocking mutex failed (err: %d): %s\n", err, strerror(err));
    }
#endif

    for (sample=myintel.samples; sample != NULL; sample = next) {
#if DEBUG_STATS
        print_sample(sample);
#endif
        next = sample->next;

        free_sample(sample);
    }

    if (json) {
        submit_post(STATS_HOST, STATS_PORT, "PUT", "/clamav/1/submit/stats", json, myintel.timeout);
        free(json);
    }

    if (myintel.hostid && !(intel->hostid)) {
        free(myintel.hostid);
        myintel.hostid = NULL;
    }

    cli_dbgmsg("stats - end\n");
}

void clamav_stats_remove_sample(const char *virname, const unsigned char *md5, size_t size, void *cbdata)
{
    cli_intel_t *intel;
    cli_flagged_sample_t *sample;
    int err;

    intel = (cli_intel_t *)cbdata;
    if (!(intel))
        return;

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_lock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_remove_sample: locking mutex failed (err: %d): %s\n", err, strerror(err));
        return;
    }
#endif

    while ((sample = find_sample(intel, virname, md5, size, NULL))) {
        if (sample->prev)
            sample->prev->next = sample->next;
        if (sample->next)
            sample->next->prev = sample->prev;
        if (sample == intel->samples)
            intel->samples = sample->next;

        free_sample(sample);
        intel->nsamples--;
    }

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_remove_sample: unlocking mutex failed (err: %d): %s\n", err, strerror(err));
    }
#endif
}

void clamav_stats_decrement_count(const char *virname, const unsigned char *md5, size_t size, void *cbdata)
{
    cli_intel_t *intel;
    cli_flagged_sample_t *sample;
    int err;

    intel = (cli_intel_t *)cbdata;
    if (!(intel))
        return;

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_lock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_decrement_count: locking mutex failed (err: %d): %s\n", err, strerror(err));
        return;
    }
#endif

    sample = find_sample(intel, virname, md5, size, NULL);
    if (!(sample))
        goto clamav_stats_decrement_end;

    if (sample->hits == 1) {
        if ((intel->engine->cb_stats_remove_sample))
            intel->engine->cb_stats_remove_sample(virname, md5, size, intel);
        else
            clamav_stats_remove_sample(virname, md5, size, intel);

        goto clamav_stats_decrement_end;
    }

    sample->hits--;

 clamav_stats_decrement_end:
#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_decrement_count: unlocking mutex failed (err: %d): %s\n", err, strerror(err));
    }
#endif
    return;
}

size_t clamav_stats_get_num(void *cbdata)
{
    cli_intel_t *intel;

    intel = (cli_intel_t *)cbdata;

    if (!(intel))
        return 0;

    return intel->nsamples;
}

size_t clamav_stats_get_size(void *cbdata)
{
    cli_intel_t *intel;
    cli_flagged_sample_t *sample;
    size_t sz, i;
    int err;

    intel = (cli_intel_t *)cbdata;
    if (!(intel))
        return 0;

    sz = sizeof(cli_intel_t);

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_lock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_get_size: locking mutex failed (err: %d): %s\n", err, strerror(err));
        return sz;
    }
#endif

    for (sample = intel->samples; sample != NULL; sample = sample->next) {
        sz += sizeof(cli_flagged_sample_t);
        if ((sample->virus_name)) {
            for (i=0; sample->virus_name[i] != NULL; i++)
                sz += strlen(sample->virus_name[i]);
            sz += sizeof(char **) * i;
        }
    }

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_get_size: unlocking mutex failed (err: %d): %s\n", err, strerror(err));
    }
#endif

    return sz;
}

#if defined(_WIN32)
char *clamav_stats_get_hostid(void *cbdata)
{
    HW_PROFILE_INFO HwProfInfo;

    if (!GetCurrentHwProfile(&HwProfInfo))
        return strdup(STATS_ANON_UUID);

    return strdup(HwProfInfo.szHwProfileGuid);
}
#elif defined(C_SOLARIS)
char *clamav_stats_get_hostid(void *cbdata)
{
    struct utsname utsnm;
    int ret;

    ret = uname(&utsnm);
    if (ret != -1)
        return strdup(utsnm.nodename);

    return strdup(STATS_ANON_UUID);
}
#else
char *clamav_stats_get_hostid(void *cbdata)
{
    char *sysctls[] = {
        "kern.hostuuid",
        NULL
    };
    size_t bufsz, i;
    char *buf;

    UNUSEDPARAM(cbdata);

#if HAVE_SYSCTLBYNAME
    /*
     * FreeBSD provides a handy-dandy sysctl for grabbing the system's HostID. In a jail that
     * hasn't run the hostid rc.d script, the hostid defaults to all zeros.
     */
    for (i=0; sysctls[i] != NULL; i++) {
        if (sysctlbyname(sysctls[i], NULL, &bufsz, NULL, 0))
            continue;

        break; /* Got one */
    }

    if (sysctls[i] != NULL) {
        buf = calloc(1, bufsz+1);
        if (sysctlbyname(sysctls[i], buf, &bufsz, NULL, 0))
            return strdup(STATS_ANON_UUID); /* Not sure why this would happen, but we'll just default to the anon uuid on error */

        return buf;
    }

    return strdup(STATS_ANON_UUID);
#else
    buf = internal_get_host_id();
    if (!(buf))
        return strdup(STATS_ANON_UUID);
    return buf;
#endif
}
#endif

static cli_flagged_sample_t *find_sample(cli_intel_t *intel, const char *virname, const unsigned char *md5, size_t size, stats_section_t *sections)
{
    cli_flagged_sample_t *sample;
    size_t i;

    for (sample = intel->samples; sample != NULL; sample = sample->next) {
        int foundSections = 0;

        if (sample->size != size)
            continue;

        if (memcmp(sample->md5, md5, sizeof(sample->md5)))
            continue;

        if (!(virname))
            return sample;

        if ((sections) && (sample->sections)) {
            if (sections->nsections == sample->sections->nsections) {
                for (i=0; i < sections->nsections; i++)
                    if (sections->sections[i].len == sample->sections->sections[i].len)
                        if (memcmp(sections->sections[i].md5, sample->sections->sections[i].md5, sizeof(stats_section_t)))
                            break;

                if (i == sections->nsections)
                    foundSections = 1;
            }
        } else {
            foundSections = 1;
        }

        if (foundSections)
            for (i=0; sample->virus_name[i] != NULL; i++)
                if (!strcmp(sample->virus_name[i], virname))
                    return sample;
    }

    return NULL;
}

void cl_engine_set_clcb_stats_submit(struct cl_engine *engine, clcb_stats_submit callback)
{
    engine->cb_stats_submit = callback;
}

void cl_engine_set_stats_set_cbdata(struct cl_engine *engine, void *cbdata)
{
    engine->stats_data = cbdata;
}

void cl_engine_set_clcb_stats_add_sample(struct cl_engine *engine, clcb_stats_add_sample callback)
{
    engine->cb_stats_add_sample = callback;
}

void cl_engine_set_clcb_stats_remove_sample(struct cl_engine *engine, clcb_stats_remove_sample callback)
{
    engine->cb_stats_remove_sample = callback;
}

void cl_engine_set_clcb_stats_decrement_count(struct cl_engine *engine, clcb_stats_decrement_count callback)
{
    engine->cb_stats_decrement_count = callback;
}

void cl_engine_set_clcb_stats_flush(struct cl_engine *engine, clcb_stats_flush callback)
{
    engine->cb_stats_flush = callback;
}

void cl_engine_set_clcb_stats_get_num(struct cl_engine *engine, clcb_stats_get_num callback)
{
    engine->cb_stats_get_num = callback;
}

void cl_engine_set_clcb_stats_get_size(struct cl_engine *engine, clcb_stats_get_size callback)
{
    engine->cb_stats_get_size = callback;
}

void cl_engine_set_clcb_stats_get_hostid(struct cl_engine *engine, clcb_stats_get_hostid callback)
{
    engine->cb_stats_get_hostid = callback;
}

void cl_engine_stats_enable(struct cl_engine *engine)
{
    engine->cb_stats_add_sample = clamav_stats_add_sample;
    engine->cb_stats_submit = clamav_stats_submit;
}
