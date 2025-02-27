/*
 *  ClamAV Malware and False Positive Reporting Tool
 *
 *  Copyright (C) 2014-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Shawn Webb, Steve Morgan
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

#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>

#ifdef _WIN32
#include <Windows.h>
#include <wincrypt.h>
#endif

#include <curl/curl.h>
#include <json.h>

#include "target.h"

// libclamav
#include "clamav.h"
#include "others.h"

// common
#include "misc.h"
#include "getopt.h"
#include "cert_util.h"
#include "output.h"

#define OPTS "e:p:n:N:V:H:h?v?d"

char *read_stream(void);
void usage(char *name);
void version(void);

typedef struct _header_data {
    int len;
    char *session;
} header_data;

typedef struct _write_data {
    int len;
    char *str;
} write_data;

bool g_debug = false;

void usage(char *name)
{
    printf("\n");
    printf("                       Clam AntiVirus: Malware and False Positive Reporting Tool %s\n", get_version());
    printf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    printf("           (C) 2025 Cisco Systems, Inc.\n");
    printf("\n");
    printf("    %s -hHinpVvd?\n", name);
    printf("\n");
    printf("    -h or -?                  Show this help\n");
    printf("    -v                        Show version\n");
    printf("    -e [EMAIL]                Your email address (required)\n");
    printf("    -n [FILE/-]               Submit a false negative (FN)\n");
    printf("    -N [NAME]                 Your name contained in quotation marks (required)\n");
    printf("    -p [FILE/-]               Submit a false positive (FP)\n");
    printf("    -V [VIRUS]                Detected virus name (required with -p)\n");
    printf("    -d                        Enable debug output\n");
    printf("\n");
    printf("You must specify -n or -p. Both are mutually exclusive. Pass in - as the filename for stdin.\n\n");
    exit(0);
}

void version(void)
{
    print_version(NULL);
    exit(0);
}

size_t header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    int len = size * nmemb;
    char *sp, *ep, *mem;
    header_data *hd        = (header_data *)userdata;
    const char *set_cookie = "Set-Cookie:";
    int clen               = strlen(set_cookie);

    if (len > clen) {
        if (strncmp(ptr, set_cookie, clen))
            return len;
        sp = ptr + clen + 1;
        ep = strchr(sp, ';');
        if (ep == NULL) {
            logg(LOGG_ERROR, "header_cb(): malformed cookie\n");
            return 0;
        }
        mem = malloc(ep - sp + 1);
        if (mem == NULL) {
            logg(LOGG_ERROR, "header_cb(): malloc failed\n");
            return 0;
        }
        memcpy(mem, sp, ep - sp);
        mem[ep - sp] = '\0';
        if (!strncmp(mem, "_clamav-net_session", strlen("_clamav-net_session")))
            hd->session = mem;
        else {
            logg(LOGG_ERROR, "header_cb(): unrecognized cookie\n");
            free(mem);
        }
    }
    return len;
}

size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    int len = size * nmemb;
    char *str;
    write_data *wd = (write_data *)userdata;

    if (len) {
        str = realloc(wd->str, wd->len + len + 1);
        if (str == NULL) {
            logg(LOGG_ERROR, "write_cb() realloc failure\n");
            return 0;
        }
        memcpy(str + wd->len, ptr, len);
        str[wd->len + len] = '\0';
        wd->str            = str;
        wd->len += len;
    }
    return len;
}

/**
 * @brief Parse a value from a JSON object, given a key.
 *
 * @param ps_json_obj   The JSON object
 * @param key           The Key
 * @return const char*  The Value on Success, NULL on Failure.
 */
const char *presigned_get_string(json_object *ps_json_obj, char *key)
{
    json_object *json_obj = NULL;
    const char *json_str  = NULL;

    if (json_object_object_get_ex(ps_json_obj, key, &json_obj)) {
        json_str = json_object_get_string(json_obj);
        if (json_str == NULL) {
            logg(LOGG_ERROR, "Error: json_object_get_string() for %s.\n", key);
        }
    } else {
        logg(LOGG_ERROR, "Error: json_object_object_get_ex() for %s.\n", key);
    }
    return json_str;
}

int main(int argc, char *argv[])
{
    int status = 1;
    char userAgent[128];
    CURL *clam_curl = NULL, *aws_curl = NULL;
    CURLcode res;
    int ch;
    struct curl_httppost *post = NULL, *last = NULL;
    struct curl_slist *slist = NULL;
    char *name = NULL, *email = NULL, *filename = NULL;
    int setURL = 0, fromStream = 0;
    const char *json_str;
    write_data wd            = {0, NULL};
    header_data hd_malware   = {0, NULL};
    header_data hd_presigned = {0, NULL};
    json_object *ps_json_obj = NULL;
    bool malware             = false;
    int len                  = 0;
    char *submissionID       = NULL;
    char *fpvname            = NULL;
    char *sp, *ep;

    char *authenticity_token_header = NULL;
    char *authenticity_token        = NULL;
    char *session_cookie            = NULL;

    char *url_for_auth_token;
    char *url_for_presigned_cookie;

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    curl_global_init(CURL_GLOBAL_ALL);

    clam_curl = curl_easy_init();
    if (clam_curl == NULL) {
        logg(LOGG_ERROR, "ERROR: Could not initialize libcurl.\n");
        goto done;
    }

    memset(userAgent, 0, sizeof(userAgent));
    snprintf(userAgent, sizeof(userAgent),
             PACKAGE "/%s (OS: " TARGET_OS_TYPE ", ARCH: " TARGET_ARCH_TYPE ", CPU: " TARGET_CPU_TYPE ")",
             get_version());
    userAgent[sizeof(userAgent) - 1] = 0;

    if (CURLE_OK != curl_easy_setopt(clam_curl, CURLOPT_USERAGENT, userAgent)) {
        logg(LOGG_ERROR, "!create_curl_handle: Failed to set CURLOPT_USERAGENT (%s)!\n", userAgent);
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
                malware  = true;
                filename = optarg;
                break;
            case 'V':
                fpvname = optarg;
                break;
            case 'd':
                g_debug = true;
                break;
            case 'h':
            case '?':
            default:
                usage(argv[0]);
        }
    }

    if (!(name) || !(email) || !(filename))
        usage(argv[0]);

    if (malware == false && fpvname == NULL) {
        logg(LOGG_ERROR, "Detected virus name(-V) required for false positive submissions.\n");
        usage(argv[0]);
    }
    if (strlen(filename) == 1 && filename[0] == '-') {
        filename = read_stream();
        if (!(filename)) {
            logg(LOGG_ERROR, "ERROR: Unable to read stream\n");
            goto done;
        }
        fromStream = 1;
    }

    if (g_debug) {
        /* ask libcurl to show us the verbose output */
        if (CURLE_OK != curl_easy_setopt(clam_curl, CURLOPT_VERBOSE, 1L)) {
            logg(LOGG_ERROR, "!ERROR: Failed to set CURLOPT_VERBOSE!\n");
        }
        if (CURLE_OK != curl_easy_setopt(clam_curl, CURLOPT_STDERR, stdout)) {
            logg(LOGG_ERROR, "!ERROR: Failed to direct curl debug output to stdout!\n");
        }
    }

    if (CURLE_OK != curl_easy_setopt(clam_curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1)) {
        logg(LOGG_ERROR, "ERROR: Failed to set HTTP version to 1.1 (to prevent 2.0 responses which we don't yet parse properly)!\n");
    }

#if defined(C_DARWIN) || defined(_WIN32)
    if (CURLE_OK != curl_easy_setopt(clam_curl, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function)) {
        logg(LOGG_ERROR, "ERROR: Failed to set SSL CTX function!\n");
    }
#else
    /* Use an alternate CA bundle, if specified by the CURL_CA_BUNDLE environment variable. */
    set_tls_ca_bundle(clam_curl);
#endif

    /*
     * GET authenticity token
     */
    if (malware == true) {
        url_for_auth_token = "https://www.clamav.net/reports/malware";
    } else {
        url_for_auth_token = "https://www.clamav.net/reports/fp";
    }
    curl_easy_setopt(clam_curl, CURLOPT_URL, url_for_auth_token);
    curl_easy_setopt(clam_curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(clam_curl, CURLOPT_WRITEDATA, &wd);
    curl_easy_setopt(clam_curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERDATA, &hd_malware);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERFUNCTION, header_cb);
    res = curl_easy_perform(clam_curl);
    if (res != CURLE_OK) {
        logg(LOGG_ERROR, "Error in GET %s: %s\n", url_for_auth_token, curl_easy_strerror(res));
        goto done;
    }
    if (wd.str != NULL) {
        sp = strstr(wd.str, "name=\"authenticity_token\"");
        if (sp == NULL) {
            logg(LOGG_ERROR, "Authenticity token element not found.\n");
            goto done;
        }
        sp = strstr(sp, "value=");
        if (sp == NULL) {
            logg(LOGG_ERROR, "Authenticity token value not found.\n");
            goto done;
        }
        sp += 7;
        ep = strchr(sp, '"');
        if (ep == NULL) {
            logg(LOGG_ERROR, "Authenticity token malformed.\n");
            goto done;
        }
        authenticity_token = malloc(ep - sp + 1);
        if (authenticity_token == NULL) {
            logg(LOGG_ERROR, "no memory for authenticity token.\n");
            goto done;
        }
        memcpy(authenticity_token, sp, ep - sp);
        authenticity_token[ep - sp] = '\0';
        free(wd.str);
        wd.str = NULL;
    }
    wd.len = 0;

    /* record the session cookie for later use, if exists */
    if (NULL == hd_malware.session) {
        logg(LOGG_ERROR, "clamav.net/presigned response missing session ID cookie.\nWill try without the cookie.\n");
        // goto done; // Note: unclear if the session cookie is required. Can't hurt to try w/out it?
    } else {
        len            = strlen(hd_malware.session) + 3;
        session_cookie = malloc(len);
        if (session_cookie == NULL) {
            logg(LOGG_ERROR, "No memory for GET presigned cookies\n");
            goto done;
        }
        if (snprintf(session_cookie, len, "%s;", hd_malware.session) > len) {
            logg(LOGG_ERROR, "snprintf() failed formatting GET presigned cookies\n");
            goto done;
        }
    }

    /*
     * GET presigned cookie
     */
    if (malware == true) {
        url_for_presigned_cookie = "https://www.clamav.net/presigned?type=malware";
    } else {
        url_for_presigned_cookie = "https://www.clamav.net/presigned?type=fp";
    }

    curl_easy_setopt(clam_curl, CURLOPT_URL, url_for_presigned_cookie);
    curl_easy_setopt(clam_curl, CURLOPT_HTTPGET, 1);

    if (NULL != session_cookie) {
        curl_easy_setopt(clam_curl, CURLOPT_COOKIE, session_cookie);
    }

    /* Include an X-CSRF-Token header using the authenticity token retrieved with the presigned GET request */
    len                       = strlen(authenticity_token) + strlen("X-CSRF-Token: ") + 1;
    authenticity_token_header = malloc(len);
    if (authenticity_token_header == NULL) {
        logg(LOGG_ERROR, "No memory for GET presigned X-CSRF-Token\n");
        goto done;
    }
    if (snprintf(authenticity_token_header, len, "X-CSRF-Token: %s", authenticity_token) > len) {
        logg(LOGG_ERROR, "snprintf() failed for GET presigned X-CSRF-Token\n");
        goto done;
    }
    slist = curl_slist_append(slist, authenticity_token_header);
    free(authenticity_token_header);
    authenticity_token_header = NULL;

    curl_easy_setopt(clam_curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERDATA, &hd_presigned);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(clam_curl, CURLOPT_REFERER, url_for_auth_token);

    res = curl_easy_perform(clam_curl);
    if (res != CURLE_OK) {
        logg(LOGG_ERROR, "Error in GET reports: %s\n", curl_easy_strerror(res));
        goto done;
    }
    curl_slist_free_all(slist);
    slist = NULL;

    /*
     * POST the report to AWS
     */
    ps_json_obj = json_tokener_parse(wd.str);
    if (ps_json_obj == NULL) {
        logg(LOGG_ERROR, "Error in json_tokener_parse of %.*s\n", wd.len, wd.str);
        goto done;
    }
    json_str = presigned_get_string(ps_json_obj, "key");
    if (json_str == NULL) {
        logg(LOGG_ERROR, "Error in presigned_get_string parsing key from json object\n");
        goto done;
    }
    sp = strchr(json_str, '/');
    if (sp == NULL) {
        logg(LOGG_ERROR, "Error: malformed 'key' string in GET presigned response (missing '/'.\n");
        goto done;
    }
    sp++;
    ep = strchr(sp, '-');
    if (ep == NULL) {
        logg(LOGG_ERROR, "Error: malformed 'key' string in GET presigned response (missing '-'.\n");
        goto done;
    }

    submissionID = malloc(ep - sp + 1);
    if (submissionID == NULL) {
        logg(LOGG_ERROR, "Error: malloc submissionID.\n");
        goto done;
    }
    memcpy(submissionID, sp, ep - sp);
    submissionID[ep - sp] = '\0';

    aws_curl = curl_easy_init();
    if (!(aws_curl)) {
        logg(LOGG_ERROR, "ERROR: Could not initialize libcurl POST presigned\n");
        goto done;
    }

    if (CURLE_OK != curl_easy_setopt(aws_curl, CURLOPT_USERAGENT, userAgent)) {
        logg(LOGG_ERROR, "!create_curl_handle: Failed to set CURLOPT_USERAGENT (%s)!\n", userAgent);
    }

    if (g_debug) {
        /* ask libcurl to show us the verbose output */
        if (CURLE_OK != curl_easy_setopt(aws_curl, CURLOPT_VERBOSE, 1L)) {
            logg(LOGG_ERROR, "!ERROR: Failed to set CURLOPT_VERBOSE!\n");
        }
        if (CURLE_OK != curl_easy_setopt(aws_curl, CURLOPT_STDERR, stdout)) {
            logg(LOGG_ERROR, "!ERROR: Failed to direct curl debug output to stdout!\n");
        }
    }

    if (CURLE_OK != curl_easy_setopt(aws_curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1)) {
        logg(LOGG_ERROR, "ERROR: Failed to set HTTP version to 1.1 (to prevent 2.0 responses which we don't yet parse properly)!\n");
    }

#if defined(C_DARWIN) || defined(_WIN32)
    if (CURLE_OK != curl_easy_setopt(aws_curl, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function)) {
        logg(LOGG_ERROR, "ERROR: Failed to set SSL CTX function!\n");
    }
#else
    /* Use an alternate CA bundle, if specified by the CURL_CA_BUNDLE environment variable. */
    set_tls_ca_bundle(aws_curl);
#endif

    curl_formadd(&post, &last, CURLFORM_COPYNAME, "key", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);

    json_str = presigned_get_string(ps_json_obj, "acl");
    if (json_str == NULL) {
        logg(LOGG_ERROR, "Error in presigned_get_string parsing acl from json object\n");
        goto done;
    }
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "acl", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);

    json_str = presigned_get_string(ps_json_obj, "policy");
    if (json_str == NULL) {
        logg(LOGG_ERROR, "Error in presigned_get_string parsing policy from json object\n");
        goto done;
    }
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "policy", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);

    json_str = presigned_get_string(ps_json_obj, "x-amz-meta-original-filename");
    if (json_str == NULL) {
        logg(LOGG_ERROR, "Error in presigned_get_string parsing x-amz-meta-original-filename from json object\n");
        goto done;
    }
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-meta-original-filename", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);

    json_str = presigned_get_string(ps_json_obj, "x-amz-credential");
    if (json_str == NULL) {
        logg(LOGG_ERROR, "Error in presigned_get_string parsing x-amz-credential from json object\n");
        goto done;
    }
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-credential", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);

    json_str = presigned_get_string(ps_json_obj, "x-amz-algorithm");
    if (json_str == NULL) {
        logg(LOGG_ERROR, "Error in presigned_get_string parsing x-amz-algorithm from json object\n");
        goto done;
    }
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-algorithm", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);

    json_str = presigned_get_string(ps_json_obj, "x-amz-date");
    if (json_str == NULL) {
        logg(LOGG_ERROR, "Error in presigned_get_string parsing x-amz-date from json object\n");
        goto done;
    }
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-date", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);

    json_str = presigned_get_string(ps_json_obj, "x-amz-signature");
    if (json_str == NULL) {
        logg(LOGG_ERROR, "Error in presigned_get_string parsing x-amz-signature from json object\n");
        goto done;
    }
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "x-amz-signature", CURLFORM_COPYCONTENTS, json_str, CURLFORM_END);

    curl_formadd(&post, &last, CURLFORM_COPYNAME, "file", CURLFORM_FILE, filename, CURLFORM_END);

    slist = curl_slist_append(slist, "Expect:");
    curl_easy_setopt(aws_curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(aws_curl, CURLOPT_URL, "https://clamav-site.s3.amazonaws.com/");
    curl_easy_setopt(aws_curl, CURLOPT_HTTPPOST, post);

    res = curl_easy_perform(aws_curl);
    if (res != CURLE_OK) {
        logg(LOGG_ERROR, "Error in POST AWS: %s\n", curl_easy_strerror(res));
        goto done;
    }
    curl_slist_free_all(slist);
    slist = NULL;
    curl_formfree(post);
    post = NULL;
    last = NULL;
    curl_easy_cleanup(aws_curl);
    aws_curl = NULL;
    json_object_put(ps_json_obj);

    if (wd.str != NULL) {
        free(wd.str);
        wd.str = NULL;
    }
    wd.len = 0;

    /*** The POST submit to clamav.net ***/
    slist = curl_slist_append(slist, "Expect:");

    if (NULL != session_cookie) {
        curl_easy_setopt(clam_curl, CURLOPT_COOKIE, session_cookie);
    }

    curl_formadd(&post, &last, CURLFORM_COPYNAME, "utf8", CURLFORM_COPYCONTENTS, "\x27\x13", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "authenticity_token", CURLFORM_COPYCONTENTS, authenticity_token, CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "submissionID", CURLFORM_COPYCONTENTS, submissionID, CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "type", CURLFORM_COPYCONTENTS, malware ? "malware" : "fp", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "sendername", CURLFORM_COPYCONTENTS, name, CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "email", CURLFORM_COPYCONTENTS, email, CURLFORM_END);
    if (malware == true) {
        curl_formadd(&post, &last, CURLFORM_COPYNAME, "shareSample", CURLFORM_COPYCONTENTS, "on", CURLFORM_END);
    } else {
        curl_formadd(&post, &last, CURLFORM_COPYNAME, "virusname", CURLFORM_COPYCONTENTS, fpvname, CURLFORM_END);
    }
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "description", CURLFORM_COPYCONTENTS, "clamsubmit", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "notify", CURLFORM_COPYCONTENTS, "on", CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "privacy", CURLFORM_COPYCONTENTS, "on", CURLFORM_END);
    curl_easy_setopt(clam_curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(clam_curl, CURLOPT_URL, "https://www.clamav.net/reports/submit");
    curl_easy_setopt(clam_curl, CURLOPT_HTTPPOST, post);
    curl_easy_setopt(clam_curl, CURLOPT_HEADERFUNCTION, NULL);
    res = curl_easy_perform(clam_curl);
    if (res != CURLE_OK) {
        logg(LOGG_ERROR, "Error in POST submit: %s\n", curl_easy_strerror(res));
        goto done;
    } else {
        long response_code;
        curl_easy_getinfo(clam_curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code / 100 == 3) {
            curl_easy_getinfo(clam_curl, CURLINFO_REDIRECT_URL, &url_for_auth_token);
            if (url_for_auth_token == NULL) {
                logg(LOGG_ERROR, "POST submit Location URL is NULL.\n");
                goto done;
            }
            sp = strstr(url_for_auth_token, "/reports/");
            if (sp == NULL) {
                logg(LOGG_ERROR, "POST submit Location URL is malformed.\n");
            } else if (!strcmp(sp, "/reports/success")) {
                logg(LOGG_INFO, "Submission success!\n");
                status = 0;
            } else if (!strcmp(sp, "/reports/failure")) {
                logg(LOGG_INFO, "Submission failed\n");
            } else {
                logg(LOGG_INFO, "Unknown submission status %s\n", sp);
            }
        } else {
            logg(LOGG_ERROR, "Unexpected POST submit response code: %li\n", response_code);
        }
    }

done:
    /*
     * Cleanup
     */
    if (authenticity_token_header != NULL) {
        free(authenticity_token_header);
    }
    if (session_cookie != NULL) {
        free(session_cookie);
    }
    if (slist != NULL) {
        curl_slist_free_all(slist);
    }
    if (post != NULL) {
        curl_formfree(post);
    }
    if (clam_curl != NULL) {
        curl_easy_cleanup(clam_curl);
    }
    if (aws_curl != NULL) {
        curl_easy_cleanup(aws_curl);
    }
    curl_global_cleanup();

    if (wd.str != NULL) {
        free(wd.str);
        wd.str = NULL;
        wd.len = 0;
    }
    if (hd_malware.session != NULL) {
        free(hd_malware.session);
    }
    if (hd_presigned.session != NULL) {
        free(hd_presigned.session);
    }
    if (submissionID != NULL) {
        free(submissionID);
    }
    if (authenticity_token != NULL) {
        free(authenticity_token);
    }
    if ((fromStream != 0) && (filename != NULL)) {
        remove(filename);
        free(filename);
    }

    return status;
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
        nread    = fread(buf, 1, sizeof(buf), stdin);
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
