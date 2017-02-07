#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <curl/curl.h>

#include "libclamav/clamav.h"
#include "libclamav/others.h"
#include "shared/misc.h"
#include "shared/getopt.h"

#define OPTS "e:p:n:N:V:H:h?v"

char *read_stream(void);
void usage(char *name);
void version(void);

typedef struct _header_data {
    int len;
    char * cfduid;
    char * session;
} header_data;

typedef struct _write_data {
    int len;
    char * str;
} write_data;

void usage(char *name)
{
    fprintf(stderr, "USAGE: %s -hHinpVv?\n", name);
    fprintf(stderr, "OPTIONS:\n");
    fprintf(stderr, "    -e [EMAIL]\tYour email address (required)\n");
    fprintf(stderr, "    -h or -?\tShow the help text\n");
    fprintf(stderr, "    -n [FILE]\tSubmit a false negative (FN)\n");
    fprintf(stderr, "    -N [NAME]\tYour name contained in quotation marks (required)\n");
    fprintf(stderr, "    -p [FILE]\tSubmit a false positive (FP)\n");
    fprintf(stderr, "    -V [NAME] \tDetected virus name(required with -p)\n");
    fprintf(stderr, "    -v\t\tShow version number and exit\n");
    fprintf(stderr, "You must specify -n or -p. Both are mutually exclusive. Pass in - as the filename for stdin.\n");
    exit(0);
}

void version(void)
{
    print_version(NULL);
    exit(0);
}

size_t header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    int len = size*nmemb;
    char *sp, *ep, *mem;
    header_data *hd = (header_data *) userdata;
    const char *set_cookie = "Set-Cookie:";
    int clen = strlen(set_cookie);

    if (len > clen) {
        if (strncmp(ptr, set_cookie, clen))
            return len;
        sp = ptr + clen + 1;
        ep = strchr(sp, ';');
        if (ep == NULL) {
            fprintf(stderr, "header_cb(): malformed cookie\n");
            return 0;
        }
        mem = malloc(ep-sp+1);
        if (mem == NULL) {
            fprintf(stderr, "header_cb(): malloc failed\n");
            return 0;
        }
        memcpy(mem, sp, ep-sp);
        mem[ep-sp] = '\0';
        if (!strncmp(mem, "__cfduid", 8))
            hd->cfduid = mem;
        else if (!strncmp(mem, "_clamav-net_session", strlen("_clamav-net_session")))
            hd->session = mem;
        else
            fprintf(stderr, "header_cb(): unrecognized cookie\n");
    }
    return len;
}

size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    int len = size*nmemb;
    char * str;
    write_data *wd = (write_data *) userdata;

    if (len) {
        str = realloc(wd->str, wd->len + len + 1);
        if (str == NULL) {
            fprintf (stderr, "write_cb() realloc failure\n");
            return 0;
        }
        memcpy(str + wd->len, ptr, len);
        str[wd->len + len] = '\0';
        wd->str = str;
        wd->len += len;
    }
    return len;
}

const char* presigned_get_string(json_object * ps_json_obj, char * key)
{
    json_object * json_obj = NULL;
    const char * json_str = NULL;

    if (json_object_object_get_ex(ps_json_obj, key, &json_obj)) {
        json_str = json_object_get_string(json_obj);
        if (json_str == NULL) {
            fprintf(stderr, "Error: json_object_get_string() for %s.\n", key);
            exit(1);
        }
    } else {
        fprintf(stderr, "Error: json_object_object_get_ex() for %s.\n", key);
        exit(1);
    }
    return json_str;
}

int main(int argc, char *argv[])
{
    CURL *clam_curl, *aws_curl;
    CURLcode res;
    int ch;
    struct curl_httppost *post=NULL, *last=NULL;
    struct curl_slist *slist = NULL;
    char *name=NULL, *email=NULL, *filename=NULL;
    int setURL=0, fromStream=0;
    const char * json_str;
    write_data wd = {0, NULL};
    header_data hd_malware = {0, NULL, NULL};
    header_data hd_presigned = {0, NULL, NULL};
    json_object * ps_json_obj = NULL;
    json_object * json_obj = NULL;
    int malware = 0;
    int len = 0;
    char * submissionID = NULL;
    char * fpvname = NULL;
    char *sp, *ep, *str;
    char * authenticity_token;
    char * urlp;

    curl_global_init(CURL_GLOBAL_ALL);

    clam_curl = curl_easy_init();
    if (clam_curl == NULL) {
        fprintf(stderr, "ERROR: Could not initialize libcurl.\n");
        exit(1);
    }

    while ((ch = my_getopt(argc, argv, OPTS)) > 0) {
        switch (ch) {
            case 'v':
                version();
                break;
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
                break;
            case 'n':
                if (setURL)
                    usage(argv[0]);
                malware = 1;
                filename = optarg;
                break;
            case 'V':
                fpvname = optarg;
                break;
            case 'h':
            case '?':
            default:
                usage(argv[0]);
        }
    }

    if (!(name) || !(email) || !(filename))
        usage(argv[0]);

    if (malware == 0 && fpvname == NULL) {
        fprintf(stderr, "Detected virus name(-V) required for false positive submissions.\n");
        usage(argv[0]);
    }
    if (strlen(filename) == 1 && filename[0] == '-') {
        filename = read_stream();
        if (!(filename)) {
            fprintf(stderr, "ERROR: Unable to read stream\n");
            exit(1);
        }
        fromStream=1;
    }


    /*** The GET malware|fp ***/
    if (malware == 1)
        urlp = "http://www.clamav.net/reports/malware";
    else
        urlp = "http://www.clamav.net/reports/fp";
    curl_easy_setopt(clam_curl, CURLOPT_URL, urlp);
    curl_easy_setopt(clam_curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(clam_curl, CURLOPT_WRITEDATA, &wd);
    curl_easy_setopt(clam_curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERDATA, &hd_malware);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERFUNCTION, header_cb);
    res = curl_easy_perform(clam_curl);
    if (res) {
        fprintf(stderr, "Error in GET %s: %s\n", urlp , curl_easy_strerror(res));
        exit(1);
    }
    if (wd.str != NULL) {
        sp = strstr(wd.str, "name=\"authenticity_token\"");
        if (sp == NULL) {
            fprintf (stderr, "Authenticity token element not found.\n");
            exit(1);
        }
        sp = strstr(sp, "value=");
        if (sp == NULL) {
            fprintf (stderr, "Authenticity token value not found.\n");
            exit(1);
        }
        sp += 7;
        ep = strchr(sp, '"');
        if (ep == NULL) {
            fprintf (stderr, "Authenticity token malformed.\n");
            exit(1);
        }
        authenticity_token = malloc(ep-sp+1);
        if (authenticity_token == NULL) {
            fprintf (stderr, "no memory for authenticity token.\n");
            exit(1);
        }
        memcpy(authenticity_token, sp, ep-sp);
        authenticity_token[ep-sp] = '\0';
        free (wd.str);
        wd.str = NULL;
    }
    wd.len = 0;
    urlp = NULL;


    /*** The GET presigned ***/
    if (malware == 1)
        curl_easy_setopt(clam_curl, CURLOPT_URL, "http://www.clamav.net/presigned?type=malware");
    else
        curl_easy_setopt(clam_curl, CURLOPT_URL, "http://www.clamav.net/presigned?type=fp");
    curl_easy_setopt(clam_curl, CURLOPT_HTTPGET, 1);
    len = strlen(hd_malware.cfduid) + strlen(hd_malware.session) + 3;
    str = malloc(len);
    if (str == NULL) {
        fprintf(stderr, "No memory for GET presigned cookies\n");
        exit(1);
    }
    if (snprintf(str, len, "%s; %s;", hd_malware.cfduid, hd_malware.session) > len) {
        fprintf(stderr, "snprintf() failed formatting GET presigned cookies\n");
        exit(1);
    }
    curl_easy_setopt(clam_curl, CURLOPT_COOKIE, str);
    free(str);
    len = strlen(authenticity_token) + 15;
    str = malloc(len);
    if (str == NULL) {
        fprintf(stderr, "No memory for GET presigned X-CSRF-Token\n");
        exit(1);
    }
    if (snprintf(str, len, "X-CSRF-Token: %s", authenticity_token) > len) {
        fprintf(stderr, "snprintf() failed for GET presigned X-CSRF-Token\n");
        exit(1);
    }
    slist = curl_slist_append(slist, str);
    free(str);
    curl_easy_setopt(clam_curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERDATA, &hd_presigned);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERFUNCTION, header_cb);
    if (malware ==1)
        curl_easy_setopt(clam_curl, CURLOPT_REFERER, "http://www.clamav.net/reports/malware");
    else
        curl_easy_setopt(clam_curl, CURLOPT_REFERER, "http://www.clamav.net/reports/fp");

    res = curl_easy_perform(clam_curl);
    if (res) {
        fprintf(stderr, "Error in GET presigned: %s\n", curl_easy_strerror(res));
        exit(1);
    }
    curl_slist_free_all(slist);
    slist = NULL;


    /*** The POST to AWS ***/
    ps_json_obj = json_tokener_parse(wd.str);
    if (ps_json_obj == NULL) {
        fprintf(stderr, "Error in json_tokener_parse of %.*s\n", wd.len, wd.str);
        exit(1);
    }
    json_str = presigned_get_string(ps_json_obj, "key");
    sp = strchr(json_str, '/');
    if (sp == NULL) {
        fprintf(stderr, "Error: malformed 'key' string in GET presigned response (missing '/'.\n");
        exit (1);
    }
    sp++;
    ep = strchr(sp, '-');
    if (ep == NULL) {
        fprintf(stderr, "Error: malformed 'key' string in GET presigned response (missing '-'.\n");
        exit (1);
    }
    submissionID = malloc(ep-sp+1);
    if (submissionID == NULL) {
        fprintf(stderr, "Error: malloc submissionID.\n");
        exit (1);
    }
    memcpy(submissionID, sp, ep-sp);
    submissionID[ep-sp] = '\0';
    aws_curl = curl_easy_init();
    if (!(aws_curl)) {
        fprintf(stderr, "ERROR: Could not initialize libcurl POST presigned\n");
        exit(1);
    }
    submissionID[ep-sp] = '\0';
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "key", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);
    json_str = presigned_get_string(ps_json_obj, "acl");
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "acl", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);
    json_str = presigned_get_string(ps_json_obj, "policy");
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "policy", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);
    json_str = presigned_get_string(ps_json_obj, "x-amz-meta-original-filename");
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-meta-original-filename", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);
    json_str = presigned_get_string(ps_json_obj, "x-amz-credential");
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-credential", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);
    json_str = presigned_get_string(ps_json_obj, "x-amz-algorithm");
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-algorithm", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);
    json_str = presigned_get_string(ps_json_obj, "x-amz-date");
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-date", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);
    json_str = presigned_get_string(ps_json_obj, "x-amz-signature");
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-signature", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "file", CURLFORM_FILE, filename, CURLFORM_END);
    slist = curl_slist_append(slist, "Expect:");
    curl_easy_setopt(aws_curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(aws_curl, CURLOPT_URL, "http://clamav-site.s3.amazonaws.com/");
    curl_easy_setopt(aws_curl, CURLOPT_HTTPPOST, post);

    res = curl_easy_perform(aws_curl);
    if (res) {
        fprintf(stderr, "Error in POST AWS: %s\n", curl_easy_strerror(res));
        exit(1);
    }
    curl_slist_free_all(slist);
    slist = NULL;
    curl_formfree(post);
    post = NULL;
    last = NULL;
    curl_easy_cleanup(aws_curl);
    json_object_put(ps_json_obj);
    free(wd.str);
    wd.str = NULL;
    wd.len = 0;


    /*** The POST submit to clamav.net ***/
    slist = curl_slist_append(slist, "Expect:");
    len = strlen(hd_malware.cfduid) + strlen(hd_presigned.session) + 3;
    str = malloc(len);
    if (str == NULL) {
        fprintf(stderr, "No memory for POST submit cookies.\n");
        exit(1);
    }
    if (snprintf(str, len, "%s; %s;", hd_malware.cfduid, hd_presigned.session) > len) {
        fprintf(stderr, "snprintf() failed formatting POST submit cookies\n");
        exit(1);
    }
    curl_easy_setopt(clam_curl, CURLOPT_COOKIE, str);
    free(str);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "utf8", CURLFORM_COPYCONTENTS, "\x27" "\x13", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "authenticity_token", CURLFORM_COPYCONTENTS, authenticity_token, CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "submissionID", CURLFORM_COPYCONTENTS, submissionID, CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "type", CURLFORM_COPYCONTENTS, malware?"malware":"fp", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "sendername", CURLFORM_COPYCONTENTS, name, CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "email", CURLFORM_COPYCONTENTS, email, CURLFORM_END);
    if (malware == 0) {
        curl_formadd(&post, &last, CURLFORM_COPYNAME, "virusname", CURLFORM_COPYCONTENTS, fpvname, CURLFORM_END);
    } else {
    if (malware == 1)
        curl_formadd(&post, &last, CURLFORM_COPYNAME, "shareSample", CURLFORM_COPYCONTENTS, "on", CURLFORM_END);
    }
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "description", CURLFORM_COPYCONTENTS, "clamsubmit", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "notify", CURLFORM_COPYCONTENTS, "on", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "privacy", CURLFORM_COPYCONTENTS, "on", CURLFORM_END);
    curl_easy_setopt(clam_curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(clam_curl, CURLOPT_URL, "http://www.clamav.net/reports/submit");
    curl_easy_setopt(clam_curl, CURLOPT_HTTPPOST, post);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERFUNCTION, NULL);
    res = curl_easy_perform(clam_curl);
    if (res) {
        fprintf(stderr, "Error in POST submit: %s\n", curl_easy_strerror(res));
        exit(1);
    } else {
        long response_code;
        curl_easy_getinfo(clam_curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code/100 == 3) {
            curl_easy_getinfo(clam_curl, CURLINFO_REDIRECT_URL, &urlp);
            if (urlp == NULL) {
                fprintf(stderr, "POST submit Location URL is NULL.\n");
                exit(1);
            }
            sp = strstr(urlp, "/reports/");
            if (sp == NULL) {
                fprintf(stderr, "POST submit Location URL is malformed.\n");
                exit(1);
            }
            if (!strcmp(sp, "/reports/success"))
                fprintf(stdout, "Submission success!\n");
            else if (!strcmp(sp, "/reports/failure"))
                fprintf(stdout, "Submission failed\n");
            else
                fprintf(stdout, "Unknown submission status %s\n", sp);
        }
        else
            fprintf(stderr, "Unexpected POST submit response code: %li\n", response_code);
    }
    curl_slist_free_all(slist);
    curl_formfree(post);
    curl_easy_cleanup(clam_curl);
    if (wd.str != NULL) {
        free(wd.str);
        wd.str = NULL;
        wd.len = 0;
    }
    free(hd_malware.cfduid);
    free(hd_malware.session);
    free(hd_presigned.cfduid);
    free(hd_presigned.session);
    free(submissionID);
    free(authenticity_token);
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
