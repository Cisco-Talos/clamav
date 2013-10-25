#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

#include <errno.h>

#include "libclamav/others.h"
#include "libclamav/clamav.h"
#include "libclamav/json.h"

static cli_flagged_sample_t *find_sample(cli_intel_t *intel, const char *virname, const unsigned char *md5, size_t size, cli_intel_sample_type_t type);
void free_sample(cli_flagged_sample_t *sample);

void clamav_stats_add_sample(const char *virname, const unsigned char *md5, size_t size, cli_intel_sample_type_t type, void *cbdata)
{
    cli_intel_t *intel;
    cli_flagged_sample_t *sample;
    size_t i;
    char **p;
    int err;

    if (!(cbdata))
        return;

    intel = (cli_intel_t *)cbdata;

    if (intel->nsamples + 1 >= intel->maxsamples) {
        if (!(intel->engine))
            return;

        if (!(intel->engine->cb_stats_submit)) {
            if ((intel->engine->cb_stats_flush))
                intel->engine->cb_stats_flush(intel->engine, intel);

            return;
        }

        intel->engine->cb_stats_submit(intel->engine, cbdata);
    }

#ifdef CL_THREAD_SAFE
    cli_warnmsg("clamav_stats_add_sample: locking mutex\n");
    err = pthread_mutex_lock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_add_sample: locking mutex failed (err: %d): %s\n", err, strerror(err));
        return;
    }
    cli_warnmsg("clamav_stats_add_sample: locked mutex\n");
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

        p = realloc(sample->virus_name, sizeof(char **) * (i+1));
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
    cli_warnmsg("clamav_stats_add_sample: unlocked mutex\n");
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
    cli_warnmsg("clamav_stats_flush: locking mutex\n");
    err = pthread_mutex_lock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_flush: locking mutex failed (err: %d): %s\n", err, strerror(err));
        return;
    }
    cli_warnmsg("clamav_stats_flush: locked mutex\n");
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
    cli_warnmsg("clamav_stats_flush: unlocked mutex\n");
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
    cli_intel_t *intel;
    int err;

    intel = (cli_intel_t *)cbdata;

#ifdef CL_THREAD_SAFE
    cli_warnmsg("clamav_stats_submit: locking mutex\n");
    err = pthread_mutex_lock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_submit: locking mutex failed (err: %d): %s\n", err, strerror(err));

        if ((intel->engine) && (intel->engine->cb_stats_flush))
            intel->engine->cb_stats_flush(intel->engine, cbdata);

        return;
    }
    cli_warnmsg("clamav_stats_submit: locked mutex\n");
#endif

    json = export_stats_to_json(engine, (cli_intel_t *)cbdata);

#ifdef CL_THREAD_SAFE
    err = pthread_mutex_unlock(&(intel->mutex));
    if (err) {
        cli_warnmsg("clamav_stats_submit: unlocking mutex failed (err: %d): %s\n", err, strerror(err));
    }

    cli_warnmsg("clamav_stats_submit: unlocked mutex\n");
#endif

    cli_warnmsg("--- JSON ---\n%s\n--- END JSON ---\n", json);

    if (json)
        free(json);

    if ((engine->cb_stats_flush))
        engine->cb_stats_flush(engine, cbdata);
}

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
