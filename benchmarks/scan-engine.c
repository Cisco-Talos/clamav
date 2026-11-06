/* SPDX-License-Identifier: GPL-2.0-only
 * Persistent-engine file scan benchmark. Startup is outside the timed region.
 * Usage: scan-engine DATABASE FILE_LIST REPETITIONS THREADS CERTS_DIRECTORY
 * FILE_LIST contains one absolute pathname per line. Output is TSV.
 */
#define _POSIX_C_SOURCE 200809L
#include "clamav.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

struct result {
    int status;
    char *name;
    double seconds;
};

struct work {
    struct cl_engine *engine;
    struct cl_scan_options options;
    char **paths;
    size_t files, tasks, next;
    struct result *results;
    pthread_mutex_t mutex;
};

static void fail(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(2);
}

static double now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) fail("clock failed");
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void *worker(void *opaque)
{
    struct work *work = opaque;
    /* Options are scan-local even though they are constant in this benchmark. */
    struct cl_scan_options options = work->options;
    for (;;) {
        size_t task;
        double start;
        const char *name      = NULL;
        unsigned long scanned = 0;
        pthread_mutex_lock(&work->mutex);
        task = work->next++;
        pthread_mutex_unlock(&work->mutex);
        if (task >= work->tasks) break;
        start                       = now();
        work->results[task].status  = cl_scanfile(work->paths[task % work->files],
                                                  &name, &scanned, work->engine, &options);
        work->results[task].seconds = now() - start;
        work->results[task].name    = strdup(name ? name : "");
        if (!work->results[task].name) fail("name allocation failed");
    }
    return NULL;
}

int main(int argc, char **argv)
{
    struct work work        = {0};
    unsigned int signatures = 0;
    unsigned long repetitions, threads;
    pthread_t *workers;
    FILE *list;
    char *line      = NULL, *end;
    size_t capacity = 0, i;
    ssize_t length;
    double start, elapsed, cpu;
    struct rusage usage_start, usage_end;
    int status;
    if (argc != 6) fail("Usage: scan-engine DATABASE FILE_LIST REPETITIONS THREADS CERTS_DIRECTORY");
    repetitions = strtoul(argv[3], &end, 10);
    if (*end || !repetitions || repetitions > 10000) fail("invalid repetitions");
    threads = strtoul(argv[4], &end, 10);
    if (*end || !threads || threads > 64) fail("invalid threads");
    list = fopen(argv[2], "r");
    if (!list) fail("cannot open file list");
    while ((length = getline(&line, &capacity, list)) >= 0) {
        char **paths;
        if (length && line[length - 1] == '\n') line[--length] = 0;
        if (!length) continue;
        if (strchr(line, '\t') || strchr(line, '\r')) fail("unsupported pathname");
        paths = realloc(work.paths, (work.files + 1) * sizeof(*paths));
        if (!paths) fail("path list allocation failed");
        work.paths             = paths;
        work.paths[work.files] = strdup(line);
        if (!work.paths[work.files++]) fail("path allocation failed");
    }
    if (ferror(list)) fail("cannot read file list");
    free(line);
    fclose(list);
    if (!work.files || work.files > 100000) fail("invalid file count");
    work.tasks   = work.files * repetitions;
    work.results = calloc(work.tasks, sizeof(*work.results));
    workers      = calloc(threads, sizeof(*workers));
    if (!work.results || !workers) fail("result allocation failed");
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) fail("cl_init failed");
    work.engine = cl_engine_new();
    if (!work.engine) fail("engine allocation failed");
    if (cl_engine_set_num(work.engine, CL_ENGINE_DISABLE_CACHE, 1) != CL_SUCCESS)
        fail("cannot disable cache");
    if (cl_engine_set_str(work.engine, CL_ENGINE_CVDCERTSDIR, argv[5]) != CL_SUCCESS)
        fail("cannot set certificate directory");
    start  = now();
    status = cl_load(argv[1], work.engine, &signatures, CL_DB_STDOPT);
    if (status != CL_SUCCESS) fail(cl_strerror(status));
    status = cl_engine_compile(work.engine);
    if (status != CL_SUCCESS) fail(cl_strerror(status));
    fprintf(stderr, "engine_ready\t%u\t%.9f\n", signatures, now() - start);
    work.options.general = CL_SCAN_GENERAL_HEURISTICS;
    work.options.parse   = CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF | CL_SCAN_PARSE_PDF |
                         CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_HWP3 | CL_SCAN_PARSE_XMLDOCS | CL_SCAN_PARSE_MAIL |
                         CL_SCAN_PARSE_OLE2 | CL_SCAN_PARSE_HTML | CL_SCAN_PARSE_PE | CL_SCAN_PARSE_ONENOTE |
                         CL_SCAN_PARSE_IMAGE | CL_SCAN_PARSE_IMAGE_FUZZY_HASH;
    if (pthread_mutex_init(&work.mutex, NULL)) fail("mutex initialization failed");

    /* Untimed full pass warms engine internals and the filesystem cache. */
    start      = now();
    work.tasks = work.files;
    worker(&work);
    for (i = 0; i < work.files; i++) {
        if (work.results[i].status != CL_CLEAN && work.results[i].status != CL_VIRUS)
            fail("warmup scan failed");
        free(work.results[i].name);
    }
    fprintf(stderr, "warmup_complete\t%zu\t%.9f\n", work.files, now() - start);
    work.next  = 0;
    work.tasks = work.files * repetitions;
    if (getrusage(RUSAGE_SELF, &usage_start)) fail("getrusage failed");
    start = now();
    for (i = 0; i < threads; i++)
        if (pthread_create(&workers[i], NULL, worker, &work)) fail("thread creation failed");
    for (i = 0; i < threads; i++)
        if (pthread_join(workers[i], NULL)) fail("thread join failed");
    elapsed = now() - start;
    if (getrusage(RUSAGE_SELF, &usage_end)) fail("getrusage failed");
    cpu = (double)(usage_end.ru_utime.tv_sec - usage_start.ru_utime.tv_sec) +
          (double)(usage_end.ru_stime.tv_sec - usage_start.ru_stime.tv_sec) +
          (double)(usage_end.ru_utime.tv_usec - usage_start.ru_utime.tv_usec) / 1e6 +
          (double)(usage_end.ru_stime.tv_usec - usage_start.ru_stime.tv_usec) / 1e6;

    /* ru_maxrss is KiB on Linux; includes engine loading and the warmup. */
    printf("summary\t%zu\t%u\t%lu\t%.9f\t%.9f\t%ld\n",
           work.tasks, signatures, threads, elapsed, cpu, usage_end.ru_maxrss);
    puts("index\tfile\tstatus\tseconds\tname");
    for (i = 0; i < work.tasks; i++) {
        printf("%zu\t%zu\t%d\t%.9f\t%s\n", i, i % work.files,
               work.results[i].status, work.results[i].seconds, work.results[i].name);
        if (work.results[i].status != CL_CLEAN && work.results[i].status != CL_VIRUS)
            status = work.results[i].status;
        free(work.results[i].name);
    }
    pthread_mutex_destroy(&work.mutex);
    cl_engine_free(work.engine);
    for (i = 0; i < work.files; i++) free(work.paths[i]);
    free(work.paths);
    free(workers);
    free(work.results);
    return status == CL_SUCCESS ? 0 : 1;
}
