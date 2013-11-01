#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>

#include <sys/types.h>

#if !defined(_WIN32)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "libclamav/others.h"
#include "libclamav/clamav.h"
#include "libclamav/www.h"

int connect_host(const char *host, const char *port)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0x00, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &servinfo))
        return -1;

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0)
            continue;

        if (connect(sockfd, p->ai_addr, p->ai_addrlen)) {
            close(sockfd);
            continue;
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

    cli_warnmsg("Connected to %s\n", host);

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

void submit_post(const char *host, const char *port, const char *url, const char *postdata)
{
    int sockfd;
    unsigned int i;
    char *buf, *encoded;
    size_t bufsz;

    encoded = encode_data(postdata);
    if (!(encoded))
        return;

    bufsz = sizeof("POST   HTTP/1.1") + 1; /* Yes. Three blank spaces. +1 for the \n */
    bufsz += strlen(url);
    bufsz += sizeof("Host: ");
    bufsz += strlen(host) + 1; /* +1 for the \n */
    bufsz += sizeof("Content-Type: application/x-www-form-urlencoded\n");
    bufsz += sizeof("Content-Length: \n") + 10;
    bufsz += 2; /* +2 for \n\n */
    bufsz += sizeof("postdata=");
    bufsz += strlen(encoded) + 1;

    buf = cli_calloc(1, bufsz);
    if (!(buf)) {
        free(encoded);
        return;
    }

    snprintf(buf, bufsz, "POST %s HTTP/1.1\n", url);
    snprintf(buf+strlen(buf), bufsz-strlen(buf), "Host: %s\n", host);
    snprintf(buf+strlen(buf), bufsz-strlen(buf), "Content-Type: application/x-www-form-urlencoded\n");
    snprintf(buf+strlen(buf), bufsz-strlen(buf), "Content-Length: %u\n\n", (unsigned int)(strlen(encoded) + sizeof("postdata=") - 1));
    snprintf(buf+strlen(buf), bufsz-strlen(buf), "postdata=%s", encoded);
    free(encoded);

    sockfd = connect_host(host, port);
    if (sockfd < 0) {
        free(buf);
        return;
    }

    cli_warnmsg("---- Sending ----\n");
    cli_warnmsg("%s\n", buf);
    cli_warnmsg("---- End sent data ----\n");

    send(sockfd, buf, strlen(buf), 0);

    close(sockfd);
    free(buf);
}
