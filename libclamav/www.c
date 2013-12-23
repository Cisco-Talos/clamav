#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>

#include <sys/types.h>
#include <fcntl.h>
#include <sys/select.h>

#include <errno.h>

#if !defined(_WIN32)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "libclamav/others.h"
#include "libclamav/clamav.h"
#include "libclamav/www.h"

int connect_host(const char *host, const char *port, int useAsync)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int flags;
    fd_set write_fds;
    struct timeval tv;

    memset(&hints, 0x00, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &servinfo))
        return -1;

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0)
            continue;

        if (useAsync) {
            flags = fcntl(sockfd, F_GETFL, 0);
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen)) {
            if (useAsync) {
                if (errno != EINPROGRESS) {
                    close(sockfd);
                    continue;
                }

                FD_ZERO(&write_fds);
                FD_SET(sockfd, &write_fds);

                tv.tv_sec = 10;
                tv.tv_usec = 0;

                if (select(sockfd + 1, NULL, &write_fds, NULL, &tv) <= 0) {
                    close(sockfd);
                    continue;
                }
            } else {
                close(sockfd);
                continue;
            }
        }

        /* Connected to host */
        break;
    }

    if (!(p)) {
        freeaddrinfo(servinfo);
        close(sockfd);
        return -1;
    }

    freeaddrinfo(servinfo);

    return sockfd;
}

size_t encoded_size(const char *postdata)
{
    const char *p;
    size_t len=0;

    for (p = postdata; *p != '\0'; p++)
        len += isalnum(*p) ? 1 : 3;

    return len;
}

char *encode_data(const char *postdata)
{
    char *buf;
    size_t bufsz, i, j;

    bufsz = encoded_size(postdata);
    if (bufsz == 0)
        return NULL;

    buf = cli_calloc(1, bufsz+1);
    if (!(buf))
        return NULL;

    for (i=0, j=0; postdata[i] != '\0'; i++) {
        if (isalnum(postdata[i])) {
            buf[j++] = postdata[i];
        } else {
            sprintf(buf+j, "%%%02x", postdata[i]);
            j += 3;
        }
    }

    return buf;
}

void submit_post(const char *host, const char *port, const char *method, const char *url, const char *postdata)
{
    int sockfd;
    unsigned int i;
    char *buf, *encoded=NULL;
    size_t bufsz ;
    char chunkedlen[21];
    char *acceptable_methods[] = {
        "GET",
        "PUT",
        "POST",
        NULL
    };

    for (i=0; acceptable_methods[i] != NULL; i++)
        if (!strcmp(method, acceptable_methods[i]))
            break;

    if (acceptable_methods[i] == NULL)
        return;

    bufsz = strlen(method);
    bufsz += sizeof("   HTTP/1.1") + 2; /* Yes. Three blank spaces. +1 for the \n */
    bufsz += strlen(url);
    bufsz += sizeof("Host: \r\n");
    bufsz += strlen(host);
    bufsz += sizeof("Connection: Close\r\n");
    bufsz += 4; /* +4 for \r\n\r\n */

    if (!strcmp(method, "POST") || !strcmp(method, "PUT")) {
        encoded = encode_data(postdata);
        if (!(encoded))
            return;

        snprintf(chunkedlen, sizeof(chunkedlen), "%zu", strlen(encoded));
        bufsz += sizeof("Content-Type: application/x-www-form-urlencoded\r\n");
        bufsz += sizeof("Content-Length: \r\n");
        bufsz += strlen(chunkedlen);
        bufsz += strlen(encoded);
    }

    buf = cli_calloc(1, bufsz);
    if (!(buf)) {
        if ((encoded))
            free(encoded);

        return;
    }

    snprintf(buf, bufsz, "%s %s HTTP/1.1\r\n", method, url);
    snprintf(buf+strlen(buf), bufsz-strlen(buf), "Host: %s\r\n", host);
    snprintf(buf+strlen(buf), bufsz-strlen(buf), "Connection: Close\r\n");

    if (!strcmp(method, "POST") || !strcmp(method, "PUT")) {
        snprintf(buf+strlen(buf), bufsz-strlen(buf), "Content-Type: appplication/x-www-form-urlencoded\r\n");
        snprintf(buf+strlen(buf), bufsz-strlen(buf), "Content-Length: %s\r\n", chunkedlen);
        snprintf(buf+strlen(buf), bufsz-strlen(buf), "\r\n");
        snprintf(buf+strlen(buf), bufsz-strlen(buf), "%s", encoded);
        free(encoded);
    }

    sockfd = connect_host(host, port, 1);
    if (sockfd < 0) {
        cli_warnmsg("Could not connect to stats server\n");
        free(buf);
        return;
    }

    if (send(sockfd, buf, strlen(buf), 0) != strlen(buf)) {
        cli_warnmsg("Could not send stats\n");
        perror("send");
    }

    while (1) {
        /*
         * Check to make sure the stats submitted okay (so that we don't kill the HTTP request
         * while it's being processed).
         *
         * TODO: Add a time limit based on a call to select() to prevent lock-ups or major
         * slow downs.
         */
        memset(buf, 0x00, bufsz);
        if (recv(sockfd, buf, bufsz, 0) <= 0) {
            if (errno == EAGAIN)
                continue;

            cli_warnmsg("Could not receive data back from stats server. Errno: %d\n", errno);
            perror("recv");
            break;
        }

        if (strstr(buf, "STATOK"))
            break;
    }

    close(sockfd);
    free(buf);
}
