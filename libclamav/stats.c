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
#include <sys/sysctl.h>
#include <dlfcn.h>
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
#include "libclamav/json.h"
#include "libclamav/stats.h"
#include "libclamav/hostid.h"
#include "libclamav/www.h"

static cli_flagged_sample_t *find_sample(cli_intel_t *intel, const char *virname, const unsigned char *md5, size_t size, cli_intel_sample_type_t type);
void free_sample(cli_flagged_sample_t *sample);

void clamav_stats_add_sample(const char *virname, const unsigned char *md5, size_t size, cli_intel_sample_type_t type, void *cbdata)
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

    sample = find_sample(intel, virname, md5, size, type);
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
            free(sample);
            free(sample->virus_name);
            if (sample == intel->samples)
                intel->samples = NULL;

            goto end;
        }

        p = realloc(sample->virus_name, sizeof(char **) * (i == 0 ? 2 : i+1));
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
        sample->type = type;
        sample->size = size;
        intel->nsamples++;
    }

    cli_warnmsg("Added %s to the stats cache\n", (virname != NULL) ? virname: "[unknown]");

    sample->hits++;

end:
#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_add_sample: unlcoking mutex failed (err: %d): %s\n", err, strerror(err));
    }
#endif
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

    if (!(engine->cb_stats_get_hostid)) {
        /* Submitting stats is disabled due to HostID being turned off */
        if ((engine->cb_stats_flush))
            engine->cb_stats_flush(engine, cbdata);

        return;
    }

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
        next = sample->next;

        free_sample(sample);
    }

    if (json) {
        cli_warnmsg("====\tSUBMITTING STATS\t====\n");
        submit_post(STATS_HOST, STATS_PORT, "PUT", "/clamav/1/submit/stats", json);
        free(json);
    }
}

void clamav_stats_remove_sample(const char *virname, const unsigned char *md5, size_t size, cli_intel_sample_type_t type, void *cbdata)
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

    sample = find_sample(intel, virname, md5, size, type);
    if (!(sample))
        return;

    if (sample->prev)
        sample->prev->next = sample->next;
    if (sample->next)
        sample->next->prev = sample;
    if (sample == intel->samples)
        intel->samples = sample->next;

    free_sample(sample);
    intel->nsamples--;

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_remove_sample: unlocking mutex failed (err: %d): %s\n", err, strerror(err));
    }
#endif
}

void clamav_stats_decrement_count(const char *virname, const unsigned char *md5, size_t size, cli_intel_sample_type_t type, void *cbdata)
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

    sample = find_sample(intel, virname, md5, size, type);
    if (!(sample))
        return;

    if (sample->hits == 1) {
        if ((intel->engine->cb_stats_remove_sample))
            intel->engine->cb_stats_remove_sample(virname, md5, size, type, intel);
        else
            clamav_stats_remove_sample(virname, md5, size, type, intel);

        return;
    }

    sample->hits--;

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_decrement_count: unlocking mutex failed (err: %d): %s\n", err, strerror(err));
    }
#endif
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
#else
char *clamav_stats_get_hostid(void *cbdata)
{
    char *sysctls[] = {
        "kern.hostuuid",
        NULL
    };
    size_t bufsz, i;
    char *buf;

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
#else
    buf = internal_get_host_id();
    if (!(buf))
        return strdup(STATS_ANON_UUID);
    return buf;
#endif

    return strdup(STATS_ANON_UUID);
}
#endif

static cli_flagged_sample_t *find_sample(cli_intel_t *intel, const char *virname, const unsigned char *md5, size_t size, cli_intel_sample_type_t type)
{
    cli_flagged_sample_t *sample;
    size_t i;

    for (sample = intel->samples; sample != NULL; sample = sample->next) {
        if (sample->type != type)
            continue;

        if (sample->size != size)
            continue;

        if (memcmp(sample->md5, md5, sizeof(sample->md5)))
            continue;

        if (!(virname))
            return sample;

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

void cl_engine_stats_set_cbdata(struct cl_engine *engine, void *cbdata)
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
