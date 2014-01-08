#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <curl/curl.h>

#include "libclamav/clamav.h"
#include "libclamav/others.h"

#define OPTS "e:p:n:N:H:h?"

void usage(char *name)
{
    fprintf(stderr, "USAGE: %s -hHinp?\n", name);
    fprintf(stderr, "OPTIONS:\n");
    fprintf(stderr, "    -e [EMAIL]\tYour email address (required)\n");
    fprintf(stderr, "    -h or -?\tShow the help text\n");
    fprintf(stderr, "    -n [FILE]\tSubmit a false negative (FN)\n");
    fprintf(stderr, "    -N [NAME]\tYour name (required)\n");
    fprintf(stderr, "    -p [FILE]\tSubmit a fase positive (FP)\n");
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
    char *name=NULL, *email=NULL;
    struct cl_engine *engine;

    while ((ch = my_getopt(argc, argv, OPTS)) > 0) {
        switch (ch) {
            case 'e':
                email = optarg;
                break;
            case 'N':
                name = optarg;
                break;
            case 'h':
            case '?':
                usage(argv[0]);
        }
    }

    if (!(name) || !(email))
        usage(argv[0]);

    /* Reset getopt */
    optind = opterr = 1;
    optopt = 0;
    optarg = NULL;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();

    slist = curl_slist_append(slist, "Expect:");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    while ((ch = my_getopt(argc, argv, OPTS)) > 0) {
        if (ch == 'p')
            curl_easy_setopt(curl, CURLOPT_URL, "http://cgi.clamav.net/sendfp.cgi");
        else if (ch == 'n')
            curl_easy_setopt(curl, CURLOPT_URL, "http://cgi.clamav.net/sendmalware.cgi");
        else
            continue;

        if ((post))
            curl_formfree(post);

        post = last = NULL;

        if (curl_formadd(&post, &last, CURLFORM_COPYNAME, "sendername", CURLFORM_COPYCONTENTS, name, CURLFORM_END)) {
            fprintf(stderr, "Unable to specify name in libcurl form for file %s\n", optarg);
            break;
        }

        if (curl_formadd(&post, &last, CURLFORM_COPYNAME, "email", CURLFORM_COPYCONTENTS, email, CURLFORM_END)) {
            fprintf(stderr, "Unable to specify email in libcurl form for file %s\n", optarg);
            break;
        }

        if (curl_formadd(&post, &last, CURLFORM_COPYNAME, "file", CURLFORM_FILE, optarg, CURLFORM_END)) {
            fprintf(stderr, "Unable to specify file path in libcurl form for file %s\n", optarg);
            break;
        }

        curl_formadd(&post, &last, CURLFORM_COPYNAME, "action", CURLFORM_COPYCONTENTS, "submit", CURLFORM_END);
        curl_formadd(&post, &last, CURLFORM_COPYNAME, "privacy", CURLFORM_COPYCONTENTS, "yes", CURLFORM_END);
        curl_formadd(&post, &last, CURLFORM_COPYNAME, "notify", CURLFORM_COPYCONTENTS, "yes", CURLFORM_END);

        curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
        res = curl_easy_perform(curl);

        if (res) {
            fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
        }
    }

    curl_easy_cleanup(curl);

    return 0;
}
