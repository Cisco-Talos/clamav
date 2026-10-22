/*
 *  ClamAV Malware and False Positive Reporting Tool
 *
 *  Copyright (C) 2014-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#include <wincrypt.h>
#endif

#include <curl/curl.h>
#include <json.h>

#include "target.h"

// libclamav
#include "clamav.h"
#include "others.h"

// common
#include "cert_util.h"
#include "getopt.h"
#include "misc.h"
#include "output.h"

#define OPTS "e:p:n:N:V:h?vd"
#define MAX_RESPONSE_SIZE (1024U * 1024U)
#define URL_BUFFER_SIZE 2048

typedef struct response_buffer {
    size_t len;
    char *data;
    bool too_large;
    bool out_of_memory;
} response_buffer_t;

typedef struct service_urls {
    char report_form[URL_BUFFER_SIZE];
    char presigned[URL_BUFFER_SIZE];
    char upload[URL_BUFFER_SIZE];
    char report_submit[URL_BUFFER_SIZE];
    char report_success[URL_BUFFER_SIZE];
    char report_failure[URL_BUFFER_SIZE];
} service_urls_t;

static bool g_debug = false;

/**
 * @brief Print command-line usage.
 *
 * @param name      Program name.
 * @param stream    Destination stream.
 */
static void usage(const char *name, FILE *stream)
{
    fprintf(stream, "\n");
    fprintf(stream, "                       Clam AntiVirus: Malware and False Positive Reporting Tool %s\n", get_version());
    fprintf(stream, "           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    fprintf(stream, "           (C) 2026 Cisco Systems, Inc.\n");
    fprintf(stream, "\n");
    fprintf(stream, "    %s -e EMAIL -N NAME (-n FILE | -p FILE -V VIRUS) [-d]\n", name);
    fprintf(stream, "\n");
    fprintf(stream, "    -h or -?                  Show this help\n");
    fprintf(stream, "    -v                        Show version\n");
    fprintf(stream, "    -e [EMAIL]                Your email address (required)\n");
    fprintf(stream, "    -n [FILE/-]               Submit a false negative (FN)\n");
    fprintf(stream, "    -N [NAME]                 Your name contained in quotation marks (required)\n");
    fprintf(stream, "    -p [FILE/-]               Submit a false positive (FP)\n");
    fprintf(stream, "    -V [VIRUS]                Detected virus name (required with -p)\n");
    fprintf(stream, "    -d                        Enable debug output\n");
    fprintf(stream, "\n");
    fprintf(stream, "You must specify exactly one of -n or -p. Pass - as the filename to read from stdin.\n\n");
}

/** @brief Free and reset a response buffer. */
static void response_buffer_reset(response_buffer_t *response)
{
    if (response == NULL) {
        return;
    }
    free(response->data);
    response->data          = NULL;
    response->len           = 0;
    response->too_large     = false;
    response->out_of_memory = false;
}

/** @brief Collect an HTTP response body with a fixed size limit. */
static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    response_buffer_t *response = (response_buffer_t *)userdata;
    size_t chunk_size;
    char *new_data;

    if (size != 0 && nmemb > SIZE_MAX / size) {
        response->too_large = true;
        return 0;
    }
    chunk_size = size * nmemb;
    if (chunk_size == 0) {
        return 0;
    }
    if (response->len > MAX_RESPONSE_SIZE || chunk_size > MAX_RESPONSE_SIZE - response->len) {
        response->too_large = true;
        return 0;
    }
    new_data = realloc(response->data, response->len + chunk_size + 1);
    if (new_data == NULL) {
        response->out_of_memory = true;
        return 0;
    }
    memcpy(new_data + response->len, ptr, chunk_size);
    response->len += chunk_size;
    new_data[response->len] = '\0';
    response->data          = new_data;
    return chunk_size;
}

/**
 * @brief Emit connection diagnostics without request headers or bodies.
 *
 * Headers and bodies contain cookies, CSRF tokens, and signed upload fields.
 */
static int debug_cb(CURL *curl, curl_infotype type, char *data, size_t size, void *userdata)
{
    int printable_size;
    (void)curl;
    (void)userdata;

    if (type != CURLINFO_TEXT || size == 0) {
        return 0;
    }
    printable_size = size > INT_MAX ? INT_MAX : (int)size;
    logg(LOGG_DEBUG, "libcurl: %.*s", printable_size, data);
    return 0;
}

/** @brief Report a libcurl option failure. */
static bool curl_option_ok(CURLcode result, const char *description)
{
    if (result == CURLE_OK) {
        return true;
    }
    logg(LOGG_ERROR, "Failed to configure %s: %s\n", description, curl_easy_strerror(result));
    return false;
}

/** @brief Configure options shared by all clamsubmit HTTP handles. */
static bool configure_curl(CURL *curl, const char *user_agent, response_buffer_t *response)
{
#if !defined(C_DARWIN) && !defined(_WIN32)
    const char *ca_bundle;
#endif

    if (!curl_option_ok(curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent), "the HTTP user agent") ||
        !curl_option_ok(curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1), "HTTP/1.1") ||
        !curl_option_ok(curl_easy_setopt(curl, CURLOPT_WRITEDATA, response), "the response destination") ||
        !curl_option_ok(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb), "the response callback")) {
        return false;
    }
    if (g_debug &&
        (!curl_option_ok(curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, debug_cb), "safe HTTP debugging") ||
         !curl_option_ok(curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L), "verbose HTTP output"))) {
        return false;
    }
#if defined(C_DARWIN) || defined(_WIN32)
    if (!curl_option_ok(curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function), "the TLS context callback")) {
        return false;
    }
#else
    /* Use an alternate CA bundle when CURL_CA_BUNDLE is set. */
    ca_bundle = getenv("CURL_CA_BUNDLE");
    if (ca_bundle != NULL &&
        !curl_option_ok(curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle), "the alternate CA bundle")) {
        return false;
    }
#endif
    return true;
}

/** @brief Perform an HTTP request and validate its response status. */
static bool perform_request(CURL *curl, const char *description, long minimum_status, long maximum_status, response_buffer_t *response)
{
    CURLcode result;
    long response_code = 0;

    result = curl_easy_perform(curl);
    if (result != CURLE_OK) {
        if (response->too_large) {
            logg(LOGG_ERROR, "%s response exceeded the %u-byte limit.\n", description, MAX_RESPONSE_SIZE);
        } else if (response->out_of_memory) {
            logg(LOGG_ERROR, "Out of memory while reading the %s response.\n", description);
        } else {
            logg(LOGG_ERROR, "%s request failed: %s\n", description, curl_easy_strerror(result));
        }
        return false;
    }
    result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (result != CURLE_OK) {
        logg(LOGG_ERROR, "Failed to read the %s HTTP status: %s\n", description, curl_easy_strerror(result));
        return false;
    }
    if (response_code < minimum_status || response_code > maximum_status) {
        logg(LOGG_ERROR, "Unexpected %s HTTP status: %ld (expected %ld-%ld).\n",
             description, response_code, minimum_status, maximum_status);
        return false;
    }
    return true;
}

/** @brief Append a header without losing the existing list on failure. */
static bool append_header(struct curl_slist **headers, const char *header)
{
    struct curl_slist *new_headers = curl_slist_append(*headers, header);
    if (new_headers == NULL) {
        logg(LOGG_ERROR, "Out of memory while constructing HTTP headers.\n");
        return false;
    }
    *headers = new_headers;
    return true;
}

/** @brief Add a string field to a legacy libcurl multipart form. */
static bool form_add_string(struct curl_httppost **post, struct curl_httppost **last, const char *name, const char *value)
{
    CURLFORMcode result = curl_formadd(post, last,
                                       CURLFORM_COPYNAME, name,
                                       CURLFORM_COPYCONTENTS, value,
                                       CURLFORM_END);
    if (result != CURL_FORMADD_OK) {
        logg(LOGG_ERROR, "Failed to add multipart field '%s' (libcurl form error %d).\n", name, (int)result);
        return false;
    }
    return true;
}

/** @brief Add the sample file to a legacy libcurl multipart form. */
static bool form_add_file(struct curl_httppost **post, struct curl_httppost **last, const char *filename)
{
    CURLFORMcode result = curl_formadd(post, last,
                                       CURLFORM_COPYNAME, "file",
                                       CURLFORM_FILE, filename,
                                       CURLFORM_END);
    if (result != CURL_FORMADD_OK) {
        logg(LOGG_ERROR, "Failed to attach sample file '%s' (libcurl form error %d).\n", filename, (int)result);
        return false;
    }
    return true;
}

/**
 * @brief Get a non-empty string from a presigned response.
 *
 * @param object    Parsed response object.
 * @param key       Field name.
 * @param required  Whether a missing field is an error.
 * @param value     Receives a borrowed string owned by object.
 */
static bool presigned_get_string(json_object *object, const char *key, bool required, const char **value)
{
    json_object *field = NULL;

    *value = NULL;
    if (!json_object_object_get_ex(object, key, &field)) {
        if (required) {
            logg(LOGG_ERROR, "Presigned response is missing required string field '%s'.\n", key);
            return false;
        }
        return true;
    }
    if (!json_object_is_type(field, json_type_string)) {
        logg(LOGG_ERROR, "Presigned response field '%s' is not a string.\n", key);
        return false;
    }
    *value = json_object_get_string(field);
    if (*value == NULL || **value == '\0') {
        logg(LOGG_ERROR, "Presigned response field '%s' is empty.\n", key);
        return false;
    }
    return true;
}

/** @brief Parse and validate a presigned response as a JSON object. */
static json_object *parse_presigned_response(const response_buffer_t *response)
{
    json_tokener *tokener = NULL;
    json_object *object   = NULL;
    enum json_tokener_error error;
    size_t parse_end;

    if (response->data == NULL || response->len == 0) {
        logg(LOGG_ERROR, "Presigned response body is empty.\n");
        return NULL;
    }
    tokener = json_tokener_new();
    if (tokener == NULL) {
        logg(LOGG_ERROR, "Out of memory while creating the JSON parser.\n");
        return NULL;
    }
    object    = json_tokener_parse_ex(tokener, response->data, (int)response->len);
    error     = json_tokener_get_error(tokener);
    parse_end = (size_t)tokener->char_offset;
    while (parse_end < response->len && isspace((unsigned char)response->data[parse_end])) {
        parse_end++;
    }
    if (error != json_tokener_success || object == NULL) {
        logg(LOGG_ERROR, "Presigned response is not valid JSON: %s.\n", json_tokener_error_desc(error));
        if (object != NULL) {
            json_object_put(object);
            object = NULL;
        }
    } else if (parse_end != response->len) {
        logg(LOGG_ERROR, "Presigned response is not valid JSON: unexpected trailing data.\n");
        json_object_put(object);
        object = NULL;
    } else if (!json_object_is_type(object, json_type_object)) {
        logg(LOGG_ERROR, "Presigned response JSON is not an object.\n");
        json_object_put(object);
        object = NULL;
    }
    json_tokener_free(tokener);
    return object;
}

/** @brief Copy a quoted attribute value from an HTML tag. */
static char *copy_tag_attribute(const char *tag, const char *tag_end, const char *attribute_prefix,
                                const char *attribute_name, const char *tag_description)
{
    const char *value;
    const char *value_end;
    size_t value_len;
    char *copy;

    value = strstr(tag, attribute_prefix);
    if (value == NULL || value >= tag_end) {
        logg(LOGG_ERROR, "%s has no %s attribute.\n", tag_description, attribute_name);
        return NULL;
    }
    value += strlen(attribute_prefix);
    value_end = strchr(value, '"');
    if (value_end == NULL || value_end > tag_end || value_end == value) {
        logg(LOGG_ERROR, "%s has a malformed %s attribute.\n", tag_description, attribute_name);
        return NULL;
    }
    value_len = (size_t)(value_end - value);
    copy      = malloc(value_len + 1);
    if (copy == NULL) {
        logg(LOGG_ERROR, "Out of memory while copying the %s attribute.\n", attribute_name);
        return NULL;
    }
    memcpy(copy, value, value_len);
    copy[value_len] = '\0';
    return copy;
}

/** @brief Extract the Rails authenticity token scoped to the report form. */
static char *extract_form_authenticity_token(const response_buffer_t *response)
{
    const char *input;
    const char *tag_end;
    const char *name;

    if (response->data == NULL || response->len == 0) {
        logg(LOGG_ERROR, "Report form response body is empty.\n");
        return NULL;
    }
    input = response->data;
    while ((input = strstr(input, "<input")) != NULL) {
        tag_end = strchr(input, '>');
        if (tag_end == NULL) {
            break;
        }
        name = strstr(input, "name=\"authenticity_token\"");
        if (name != NULL && name < tag_end) {
            return copy_tag_attribute(input, tag_end, "value=\"", "value", "Authenticity token input");
        }
        input = tag_end + 1;
    }
    logg(LOGG_ERROR, "Report form does not contain an authenticity token.\n");
    return NULL;
}

/** @brief Extract the page-level Rails CSRF token used by AJAX requests. */
static char *extract_csrf_token(const response_buffer_t *response)
{
    const char *meta;
    const char *tag_end;
    const char *name;

    if (response->data == NULL || response->len == 0) {
        logg(LOGG_ERROR, "Report form response body is empty.\n");
        return NULL;
    }
    meta = response->data;
    while ((meta = strstr(meta, "<meta")) != NULL) {
        tag_end = strchr(meta, '>');
        if (tag_end == NULL) {
            break;
        }
        name = strstr(meta, "name=\"csrf-token\"");
        if (name != NULL && name < tag_end) {
            return copy_tag_attribute(meta, tag_end, "content=\"", "content", "CSRF meta tag");
        }
        meta = tag_end + 1;
    }
    logg(LOGG_ERROR, "Report form does not contain a page-level CSRF token.\n");
    return NULL;
}

/** @brief Extract the submission ID from the server-generated object key. */
static char *extract_submission_id(const char *key)
{
    const char *start = strchr(key, '/');
    const char *end;
    size_t length;
    char *submission_id;

    if (start == NULL || *(++start) == '\0') {
        logg(LOGG_ERROR, "Presigned response field 'key' is malformed: missing submission ID.\n");
        return NULL;
    }
    end = strchr(start, '-');
    if (end == NULL || end == start) {
        logg(LOGG_ERROR, "Presigned response field 'key' is malformed: missing submission ID separator.\n");
        return NULL;
    }
    length        = (size_t)(end - start);
    submission_id = malloc(length + 1);
    if (submission_id == NULL) {
        logg(LOGG_ERROR, "Out of memory while copying the submission ID.\n");
        return NULL;
    }
    memcpy(submission_id, start, length);
    submission_id[length] = '\0';
    return submission_id;
}

/** @brief Test whether a redirect URL exactly names an expected report result. */
static bool redirect_is(const char *url, const char *expected_url)
{
    size_t expected_length = strlen(expected_url);

    if (strncmp(url, expected_url, expected_length) != 0) {
        return false;
    }
    return url[expected_length] == '\0' || url[expected_length] == '?' || url[expected_length] == '#';
}

/** @brief Format a test service URL and reject truncation. */
static bool format_url(char *destination, size_t destination_size, const char *format, const char *base)
{
    int length = snprintf(destination, destination_size, format, base);
    if (length < 0 || (size_t)length >= destination_size) {
        logg(LOGG_ERROR, "ClamSubmit service URL is too long.\n");
        return false;
    }
    return true;
}

/** @brief Initialize production URLs or test-only local endpoints. */
static bool initialize_service_urls(service_urls_t *urls, bool malware)
{
#ifdef CLAMSUBMIT_TEST_ENDPOINTS
    const char *base = getenv("CLAMSUBMIT_TEST_BASE_URL");
    if (base == NULL || *base == '\0') {
        logg(LOGG_ERROR, "CLAMSUBMIT_TEST_BASE_URL is required by the test executable.\n");
        return false;
    }
    if (!format_url(urls->report_form, sizeof(urls->report_form),
                    malware ? "%s/reports/malware" : "%s/reports/fp", base) ||
        !format_url(urls->presigned, sizeof(urls->presigned), "%s/presigned", base) ||
        !format_url(urls->upload, sizeof(urls->upload), "%s/upload", base) ||
        !format_url(urls->report_submit, sizeof(urls->report_submit), "%s/reports/submit", base) ||
        !format_url(urls->report_success, sizeof(urls->report_success), "%s/reports/success", base) ||
        !format_url(urls->report_failure, sizeof(urls->report_failure), "%s/reports/failure", base)) {
        return false;
    }
#else
    if (!format_url(urls->report_form, sizeof(urls->report_form), "%s",
                    malware ? "https://www.clamav.net/reports/malware" : "https://www.clamav.net/reports/fp") ||
        !format_url(urls->presigned, sizeof(urls->presigned), "%s", "https://www.clamav.net/presigned") ||
        !format_url(urls->upload, sizeof(urls->upload), "%s", "https://clamav-site.s3.amazonaws.com/") ||
        !format_url(urls->report_submit, sizeof(urls->report_submit), "%s", "https://www.clamav.net/reports/submit") ||
        !format_url(urls->report_success, sizeof(urls->report_success), "%s", "https://www.clamav.net/reports/success") ||
        !format_url(urls->report_failure, sizeof(urls->report_failure), "%s", "https://www.clamav.net/reports/failure")) {
        return false;
    }
#endif
    return true;
}

/** @brief Verify that the selected sample file can be opened for reading. */
static bool validate_sample_file(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        logg(LOGG_ERROR, "Unable to open sample file '%s': %s\n", filename, strerror(errno));
        return false;
    }
    if (fclose(file) != 0) {
        logg(LOGG_ERROR, "Unable to close sample file '%s': %s\n", filename, strerror(errno));
        return false;
    }
    return true;
}

/**
 * @brief Copy stdin to a temporary file for libcurl upload.
 *
 * @return Allocated temporary filename on success, or NULL on failure.
 */
static char *read_stream(void)
{
    char *filename = NULL;
    unsigned char buffer[4096];
    FILE *file = NULL;
    cl_error_t status;
    int file_descriptor = -1;
    size_t bytes_read;
    bool success = false;

#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
        logg(LOGG_ERROR, "Unable to set stdin to binary mode: %s\n", strerror(errno));
        goto done;
    }
#endif

    status = cli_gentempfd(NULL, &filename, &file_descriptor);
    if (status != CL_SUCCESS) {
        logg(LOGG_ERROR, "Unable to create a temporary file for stdin: %s\n", cl_strerror(status));
        goto done;
    }
    file = fdopen(file_descriptor, "wb");
    if (file == NULL) {
        logg(LOGG_ERROR, "Unable to open temporary file '%s' as a stream: %s\n", filename, strerror(errno));
#ifdef _WIN32
        _close(file_descriptor);
#else
        close(file_descriptor);
#endif
        goto done;
    }
    file_descriptor = -1; /* The stream now owns the descriptor. */
    for (;;) {
        size_t bytes_written = 0;
        bytes_read           = fread(buffer, 1, sizeof(buffer), stdin);
        while (bytes_written < bytes_read) {
            size_t result = fwrite(buffer + bytes_written, 1, bytes_read - bytes_written, file);
            if (result == 0) {
                logg(LOGG_ERROR, "Unable to write stdin to temporary file '%s': %s\n", filename, strerror(errno));
                goto done;
            }
            bytes_written += result;
        }
        if (bytes_read < sizeof(buffer)) {
            if (ferror(stdin)) {
                logg(LOGG_ERROR, "Unable to read sample data from stdin.\n");
                goto done;
            }
            break;
        }
    }
    if (fflush(file) != 0) {
        logg(LOGG_ERROR, "Unable to flush temporary file '%s': %s\n", filename, strerror(errno));
        goto done;
    }
    if (fclose(file) != 0) {
        file = NULL;
        logg(LOGG_ERROR, "Unable to close temporary file '%s': %s\n", filename, strerror(errno));
        goto done;
    }
    file    = NULL;
    success = true;

done:
    if (file != NULL) {
        fclose(file);
    }
    if (!success && filename != NULL) {
        remove(filename);
        free(filename);
        filename = NULL;
    }
    return filename;
}

int main(int argc, char *argv[])
{
    int status = 1;
    int option;
    char user_agent[128];
    int user_agent_length;
    CURL *clam_curl = NULL;
    CURL *aws_curl  = NULL;
    CURLcode curl_result;
    struct curl_httppost *post    = NULL;
    struct curl_httppost *last    = NULL;
    struct curl_slist *headers    = NULL;
    char *name                    = NULL;
    char *email                   = NULL;
    char *filename                = NULL;
    char *false_positive_name     = NULL;
    char *form_authenticity_token = NULL;
    char *csrf_token              = NULL;
    char *csrf_header             = NULL;
    char *submission_id           = NULL;
    const char *json_string;
    response_buffer_t response = {0};
    json_object *presigned     = NULL;
    service_urls_t urls;
    bool malware             = false;
    bool submission_selected = false;
    bool from_stream         = false;
    bool curl_initialized    = false;
    const char *presigned_body;
    const char *redirect_url = NULL;
    size_t header_length;

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    while ((option = my_getopt(argc, argv, OPTS)) > 0) {
        switch (option) {
            case 'v':
                print_version(NULL);
                return 0;
            case 'e':
                email = optarg;
                break;
            case 'N':
                name = optarg;
                break;
            case 'p':
            case 'n':
                if (submission_selected) {
                    logg(LOGG_ERROR, "Options -n and -p are mutually exclusive.\n");
                    usage(argv[0], stderr);
                    return 1;
                }
                submission_selected = true;
                malware             = option == 'n';
                filename            = optarg;
                break;
            case 'V':
                false_positive_name = optarg;
                break;
            case 'd':
                g_debug = true;
                break;
            case 'h':
                usage(argv[0], stdout);
                return 0;
            case '?':
                if (optopt == '?') {
                    usage(argv[0], stdout);
                    return 0;
                }
                usage(argv[0], stderr);
                return 1;
            default:
                usage(argv[0], stderr);
                return 1;
        }
    }
    if (optind < argc) {
        logg(LOGG_ERROR, "Unexpected positional argument: %s\n", argv[optind]);
        usage(argv[0], stderr);
        return 1;
    }
    if (name == NULL || email == NULL || filename == NULL) {
        logg(LOGG_ERROR, "Name, email, and exactly one sample file are required.\n");
        usage(argv[0], stderr);
        return 1;
    }
    if (!malware && false_positive_name == NULL) {
        logg(LOGG_ERROR, "A detected virus name (-V) is required for false-positive submissions.\n");
        usage(argv[0], stderr);
        return 1;
    }
    if (strcmp(filename, "-") == 0) {
        filename = read_stream();
        if (filename == NULL) {
            goto done;
        }
        from_stream = true;
    }
    if (!validate_sample_file(filename) || !initialize_service_urls(&urls, malware)) {
        goto done;
    }

    curl_result = curl_global_init(CURL_GLOBAL_ALL);
    if (curl_result != CURLE_OK) {
        logg(LOGG_ERROR, "Failed to initialize libcurl: %s\n", curl_easy_strerror(curl_result));
        goto done;
    }
    curl_initialized = true;
    clam_curl        = curl_easy_init();
    if (clam_curl == NULL) {
        logg(LOGG_ERROR, "Failed to create the ClamAV website HTTP handle.\n");
        goto done;
    }
    user_agent_length = snprintf(user_agent, sizeof(user_agent),
                                 PACKAGE "/%s (OS: " TARGET_OS_TYPE ", ARCH: " TARGET_ARCH_TYPE ", CPU: " TARGET_CPU_TYPE ")",
                                 get_version());
    if (user_agent_length < 0 || (size_t)user_agent_length >= sizeof(user_agent)) {
        logg(LOGG_ERROR, "Failed to construct the HTTP user agent.\n");
        goto done;
    }
    if (!configure_curl(clam_curl, user_agent, &response) ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_COOKIEFILE, ""), "the in-memory cookie engine") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_URL, urls.report_form), "the report form URL") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_HTTPGET, 1L), "the report form GET request")) {
        goto done;
    }
    if (!perform_request(clam_curl, "report form", 200, 299, &response)) {
        goto done;
    }
    form_authenticity_token = extract_form_authenticity_token(&response);
    if (form_authenticity_token == NULL) {
        goto done;
    }
    csrf_token = extract_csrf_token(&response);
    if (csrf_token == NULL) {
        goto done;
    }
    response_buffer_reset(&response);

    if (strlen(csrf_token) > SIZE_MAX - strlen("X-CSRF-Token: ") - 1) {
        logg(LOGG_ERROR, "Page-level CSRF token is too long.\n");
        goto done;
    }
    header_length = strlen("X-CSRF-Token: ") + strlen(csrf_token) + 1;
    csrf_header   = malloc(header_length);
    if (csrf_header == NULL) {
        logg(LOGG_ERROR, "Out of memory while constructing the CSRF header.\n");
        goto done;
    }
    user_agent_length = snprintf(csrf_header, header_length, "X-CSRF-Token: %s", csrf_token);
    if (user_agent_length < 0 || (size_t)user_agent_length >= header_length) {
        logg(LOGG_ERROR, "Failed to construct the CSRF header.\n");
        goto done;
    }
    if (!append_header(&headers, csrf_header)) {
        goto done;
    }

    presigned_body = malware ? "type=malware" : "type=fp";
    if (!curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_URL, urls.presigned), "the presigned POST URL") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_POST, 1L), "the presigned POST request") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_POSTFIELDS, presigned_body), "the presigned POST body") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_POSTFIELDSIZE, (long)strlen(presigned_body)), "the presigned POST body size") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_HTTPHEADER, headers), "the presigned POST headers") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_REFERER, urls.report_form), "the presigned POST referer")) {
        goto done;
    }
    if (!perform_request(clam_curl, "presigned POST", 200, 299, &response)) {
        goto done;
    }
    if (!curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_HTTPHEADER, (struct curl_slist *)NULL), "clearing the presigned POST headers") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_POSTFIELDS, (char *)NULL), "clearing the presigned POST body") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_POSTFIELDSIZE, 0L), "clearing the presigned POST body size")) {
        goto done;
    }
    curl_slist_free_all(headers);
    headers = NULL;

    presigned = parse_presigned_response(&response);
    if (presigned == NULL) {
        goto done;
    }
    if (!presigned_get_string(presigned, "key", true, &json_string) ||
        !form_add_string(&post, &last, "key", json_string)) {
        goto done;
    }
    submission_id = extract_submission_id(json_string);
    if (submission_id == NULL) {
        goto done;
    }
    if (!presigned_get_string(presigned, "acl", false, &json_string)) {
        goto done;
    }
    if (json_string != NULL && !form_add_string(&post, &last, "acl", json_string)) {
        goto done;
    }

#define ADD_REQUIRED_PRESIGNED_FIELD(field_name)                                \
    do {                                                                        \
        if (!presigned_get_string(presigned, field_name, true, &json_string) || \
            !form_add_string(&post, &last, field_name, json_string)) {          \
            goto done;                                                          \
        }                                                                       \
    } while (0)

    ADD_REQUIRED_PRESIGNED_FIELD("policy");
    ADD_REQUIRED_PRESIGNED_FIELD("x-amz-meta-original-filename");
    ADD_REQUIRED_PRESIGNED_FIELD("x-amz-credential");
    ADD_REQUIRED_PRESIGNED_FIELD("x-amz-algorithm");
    ADD_REQUIRED_PRESIGNED_FIELD("x-amz-date");
    ADD_REQUIRED_PRESIGNED_FIELD("x-amz-signature");
#undef ADD_REQUIRED_PRESIGNED_FIELD

    if (!form_add_file(&post, &last, filename)) {
        goto done;
    }
    json_object_put(presigned);
    presigned = NULL;
    response_buffer_reset(&response);

    aws_curl = curl_easy_init();
    if (aws_curl == NULL) {
        logg(LOGG_ERROR, "Failed to create the S3 upload HTTP handle.\n");
        goto done;
    }
    if (!configure_curl(aws_curl, user_agent, &response) ||
        !append_header(&headers, "Expect:") ||
        !curl_option_ok(curl_easy_setopt(aws_curl, CURLOPT_HTTPHEADER, headers), "the S3 upload headers") ||
        !curl_option_ok(curl_easy_setopt(aws_curl, CURLOPT_URL, urls.upload), "the S3 upload URL") ||
        !curl_option_ok(curl_easy_setopt(aws_curl, CURLOPT_HTTPPOST, post), "the S3 upload form")) {
        goto done;
    }
    if (!perform_request(aws_curl, "S3 upload", 200, 299, &response)) {
        goto done;
    }
    curl_easy_cleanup(aws_curl);
    aws_curl = NULL;
    curl_slist_free_all(headers);
    headers = NULL;
    curl_formfree(post);
    post = NULL;
    last = NULL;
    response_buffer_reset(&response);

    if (!form_add_string(&post, &last, "utf8", "\xE2\x9C\x93") ||
        !form_add_string(&post, &last, "authenticity_token", form_authenticity_token) ||
        !form_add_string(&post, &last, "submissionID", submission_id) ||
        !form_add_string(&post, &last, "type", malware ? "malware" : "fp") ||
        !form_add_string(&post, &last, "sendername", name) ||
        !form_add_string(&post, &last, "email", email)) {
        goto done;
    }
    if (malware) {
        if (!form_add_string(&post, &last, "shareSample", "on")) {
            goto done;
        }
    } else if (!form_add_string(&post, &last, "virusname", false_positive_name)) {
        goto done;
    }
    if (!form_add_string(&post, &last, "description", "clamsubmit") ||
        !form_add_string(&post, &last, "notify", "on") ||
        !form_add_string(&post, &last, "privacy", "on") ||
        !append_header(&headers, "Expect:") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_HTTPHEADER, headers), "the report submission headers") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_URL, urls.report_submit), "the report submission URL") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_HTTPPOST, post), "the report submission form") ||
        !curl_option_ok(curl_easy_setopt(clam_curl, CURLOPT_REFERER, urls.report_form), "the report submission referer")) {
        goto done;
    }
    if (!perform_request(clam_curl, "report submission", 300, 399, &response)) {
        goto done;
    }
    curl_result = curl_easy_getinfo(clam_curl, CURLINFO_REDIRECT_URL, &redirect_url);
    if (curl_result != CURLE_OK) {
        logg(LOGG_ERROR, "Failed to read the report submission redirect: %s\n", curl_easy_strerror(curl_result));
        goto done;
    }
    if (redirect_url == NULL) {
        logg(LOGG_ERROR, "Report submission response has no redirect destination.\n");
        goto done;
    }
    if (redirect_is(redirect_url, urls.report_success)) {
        logg(LOGG_INFO, "Submission success!\n");
        status = 0;
    } else if (redirect_is(redirect_url, urls.report_failure)) {
        logg(LOGG_ERROR, "The ClamAV website rejected the submission.\n");
    } else {
        logg(LOGG_ERROR, "Unknown report submission redirect destination.\n");
    }

done:
    if (clam_curl != NULL) {
        curl_easy_cleanup(clam_curl);
    }
    if (aws_curl != NULL) {
        curl_easy_cleanup(aws_curl);
    }
    if (headers != NULL) {
        curl_slist_free_all(headers);
    }
    if (post != NULL) {
        curl_formfree(post);
    }
    if (curl_initialized) {
        curl_global_cleanup();
    }
    if (presigned != NULL) {
        json_object_put(presigned);
    }
    response_buffer_reset(&response);
    free(csrf_header);
    free(csrf_token);
    free(form_authenticity_token);
    free(submission_id);
    if (from_stream && filename != NULL) {
        if (remove(filename) != 0) {
            logg(LOGG_WARNING, "Unable to remove temporary file '%s': %s\n", filename, strerror(errno));
        }
        free(filename);
    }
    return status;
}
