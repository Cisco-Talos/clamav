#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include <curl/curl.h>

#include "libclamav/clamav.h"
#include "libclamav/others.h"
#include "shared/misc.h"
#include "shared/getopt.h"

#define OPTS "e:p:n:N:H:h?v"

char *read_stream(void);

void usage(char *name)
{
    fprintf(stderr, "USAGE: %s -hHinp?\n", name);
    fprintf(stderr, "OPTIONS:\n");
    fprintf(stderr, "    -e [EMAIL]\tYour email address (required)\n");
    fprintf(stderr, "    -h or -?\tShow the help text\n");
    fprintf(stderr, "    -n [FILE]\tSubmit a false negative (FN)\n");
    fprintf(stderr, "    -N [NAME]\tYour name (required)\n");
    fprintf(stderr, "    -p [FILE]\tSubmit a fase positive (FP)\n");
    fprintf(stderr, "    -v\t\tShow version number and exit\n");
    fprintf(stderr, "You must specify -n or -p. Both are mutually exclusive. Pass in - as the filename for stdin.\n");
    exit(0);
}

void version(void)
{
    print_version(NULL);
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
    char *name=NULL, *email=NULL, *filename=NULL;
    struct cl_engine *engine;
    int setURL=0, fromStream=0;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if (!(curl)) {
        fprintf(stderr, "ERROR: Could not initialize libcurl\n");
        exit(1);
    }

    while ((ch = my_getopt(argc, argv, OPTS)) > 0) {
        switch (ch) {
            case 'v':
                version();
            case 'e':
                email = optarg;
                break;
            case 'N':
                name = optarg;
                break;
            case 'p':
                if (setURL)
                    usage(argv[0]);

                filename = optarg;

                curl_easy_setopt(curl, CURLOPT_URL, "http://cgi.clamav.net/sendfp.cgi");
                setURL=1;
                break;
            case 'n':
                if (setURL)
                    usage(argv[0]);

                filename = optarg;

                curl_easy_setopt(curl, CURLOPT_URL, "http://cgi.clamav.net/sendmalware.cgi");
                setURL=1;
                break;
            case 'h':
            case '?':
            default:
                usage(argv[0]);
        }
    }

    if (!(name) || !(email) || !(filename))
        usage(argv[0]);

    if (strlen(filename) == 1 && filename[0] == '-') {
        filename = read_stream();
        if (!(filename)) {
            fprintf(stderr, "ERROR: Unable to read stream\n");
            exit(1);
        }

        fromStream=1;
    }

    slist = curl_slist_append(slist, "Expect:");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    if (curl_formadd(&post, &last, CURLFORM_COPYNAME, "sendername", CURLFORM_COPYCONTENTS, name, CURLFORM_END)) {
        fprintf(stderr, "Unable to specify name in libcurl form for file %s\n", optarg);
        goto end;
    }

    if (curl_formadd(&post, &last, CURLFORM_COPYNAME, "email", CURLFORM_COPYCONTENTS, email, CURLFORM_END)) {
        fprintf(stderr, "Unable to specify email in libcurl form for file %s\n", optarg);
        goto end;
    }

    if (curl_formadd(&post, &last, CURLFORM_COPYNAME, "file", CURLFORM_FILE, filename, CURLFORM_END)) {
        fprintf(stderr, "Unable to specify file path in libcurl form for file %s\n", optarg);
        goto end;
    }

    curl_formadd(&post, &last, CURLFORM_COPYNAME, "action", CURLFORM_COPYCONTENTS, "submit", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "privacy", CURLFORM_COPYCONTENTS, "yes", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "notify", CURLFORM_COPYCONTENTS, "yes", CURLFORM_END);

    curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
    res = curl_easy_perform(curl);

    if (res) {
        fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
    }

end:
    curl_easy_cleanup(curl);
    if (fromStream) {
        remove(filename);
        free(filename);
    }

    return 0;
}

char *read_stream(void)
{
    char *filename;
    char buf[512];
    size_t nread, nwritten;
    FILE *fp;

    filename = cli_gentemp(NULL);
    if (!(filename)) {
        return NULL;
    }

    fp = fopen(filename, "w");
    if (!(fp)) {
        free(filename);
        return NULL;
    }

    while (!feof(stdin)) {
        nwritten = 0;
        nread = fread(buf, 1, sizeof(buf), stdin);
        if (nread == 0) {
            fclose(fp);
            remove(filename);
            free(filename);
            return NULL;
        }

        while (nwritten < nread) {
            size_t i;
            i = fwrite(buf, 1, nread, fp);
            if (i == 0) {
                fclose(fp);
                remove(filename);
                free(filename);
                return NULL;
            }

            nwritten += i;
        }
    }

    fclose(fp);

    return filename;
}
