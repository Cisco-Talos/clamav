#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <curl/curl.h>

#include "libclamav/clamav.h"
#include "libclamav/others.h"

void usage(char *name)
{
    fprintf(stderr, "USAGE: %s -pnih?\n", name);
    fprintf(stderr, "OPTIONS:\n");
    fprintf(stderr, "    -p [FILE]\tSubmit a fase positive (FP)\n");
    fprintf(stderr, "    -n [FILE]\tSubmit a false negative (FN)\n");
    fprintf(stderr, "    -i [FILE]\tSubmit an \"interesting\" file\n");
    fprintf(stderr, "    -h or -?\tShow the help text\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    CURL *curl;
    CURLcode res;
    int ch;
    struct curl_httppost *post=NULL, *last=NULL;
    struct curl_slist *slist = NULL;
    char *type;
    char *hostid;
    struct cl_engine *engine;

    cl_init(0);
    engine = cl_engine_new();
    if (!(engine)) {
        fprintf(stderr, "Unable to create new ClamAV engine\n");
        return 1;
    }

    hostid = engine->cb_stats_get_hostid(engine->stats_data);
    printf("HostID: %s\n", hostid);

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "http://stats.clamav.dev:8080/clamav/1/submit/file");

    slist = curl_slist_append(slist, "Expect:");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    while ((ch = my_getopt(argc, argv, "p:n:i:h?")) > 0) {
        switch (ch) {
            case 'p':
                type = "fp";
                break;
            case 'n':
                type = "fn";
                break;
            case 'i':
                type = "interesting";
                break;
            case '?':
            case 'h':
            default:
                usage(argv[0]);
        }

        if ((post))
            curl_formfree(post);

        post = last = NULL;

        if (curl_formadd(&post, &last, CURLFORM_COPYNAME, "type", CURLFORM_COPYCONTENTS, type, CURLFORM_END)) {
            fprintf(stderr, "Unable to specify type of file in libcurl form for file %s\n", optarg);
            break;
        }

        if (curl_formadd(&post, &last, CURLFORM_COPYNAME, "file", CURLFORM_FILE, optarg, CURLFORM_END)) {
            fprintf(stderr, "Unable to specify file path in libcurl form for file %s\n", optarg);
            break;
        }

        if (curl_formadd(&post, &last, CURLFORM_COPYNAME, "hostid", CURLFORM_COPYCONTENTS, hostid, CURLFORM_END)) {
            fprintf(stderr, "Unable to specify HostID in libcurl form for file %s\n", optarg);
            break;
        }

        curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
        res = curl_easy_perform(curl);

        if (res) {
            fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
        }
    }

    curl_easy_cleanup(curl);

    return 0;
}
