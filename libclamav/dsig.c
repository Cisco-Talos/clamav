/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 *
 *  Acknowledgements: The idea of number encoding comes from yyyRSA by
 *                    Erik Thiele.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "clamav.h"
#include "others.h"
#include "dsig.h"
#include "str.h"
#include "bignum.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#else
#include "w32_stat.h"
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define CLI_NSTR "118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037"

#define CLI_ESTR "100001027"

#define MP_GET(a) ((a)->used > 0 ? (a)->dp[0] : 0)

static char cli_ndecode(unsigned char value)
{
    unsigned int i;
    char ncodec[] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
        'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        '+', '/'};

    for (i = 0; i < 64; i++)
        if (ncodec[i] == value)
            return i;

    cli_errmsg("cli_ndecode: value out of range\n");
    return -1;
}

static unsigned char *cli_decodesig(const char *sig, unsigned int plen, fp_int e, fp_int n)
{
    int i, slen = strlen(sig), dec;
    unsigned char *plain;
    fp_int r, p, c;

    fp_init(&r);
    fp_init(&c);
    for (i = 0; i < slen; i++) {
        if ((dec = cli_ndecode(sig[i])) < 0) {
            return NULL;
        }
        fp_set(&r, dec);
        fp_mul_2d(&r, 6 * i, &r);
        fp_add(&r, &c, &c);
    }

    plain = (unsigned char *)cli_calloc(plen + 1, sizeof(unsigned char));
    if (!plain) {
        cli_errmsg("cli_decodesig: Can't allocate memory for 'plain'\n");
        return NULL;
    }
    fp_init(&p);
    fp_exptmod(&c, &e, &n, &p); /* plain = cipher^e mod n */
    fp_set(&c, 256);
    for (i = plen - 1; i >= 0; i--) { /* reverse */
        fp_div(&p, &c, &p, &r);
        plain[i] = MP_GET(&r);
    }

    return plain;
}

char *cli_getdsig(const char *host, const char *user, const unsigned char *data, unsigned int datalen, unsigned short mode)
{
    char buff[512], cmd[128], pass[31], *pt;
    struct sockaddr_in server;
    int sockd, bread, len;
#ifdef HAVE_TERMIOS_H
    struct termios old, new;
#endif

    memset(&server, 0x00, sizeof(struct sockaddr_in));

    if ((pt = getenv("SIGNDPASS"))) {
        strncpy(pass, pt, sizeof(pass));
        pass[sizeof(pass) - 1] = '\0';
    } else {
        cli_infomsg(NULL, "Password: ");

#ifdef HAVE_TERMIOS_H
        if (tcgetattr(0, &old)) {
            cli_errmsg("getdsig: tcgetattr() failed\n");
            return NULL;
        }
        new = old;
        new.c_lflag &= ~ECHO;
        if (tcsetattr(0, TCSAFLUSH, &new)) {
            cli_errmsg("getdsig: tcsetattr() failed\n");
            return NULL;
        }
#endif
        if (scanf("%30s", pass) == EOF) {
            cli_errmsg("getdsig: Can't get password\n");
#ifdef HAVE_TERMIOS_H
            tcsetattr(0, TCSAFLUSH, &old);
#endif
            return NULL;
        }

#ifdef HAVE_TERMIOS_H
        if (tcsetattr(0, TCSAFLUSH, &old)) {
            cli_errmsg("getdsig: tcsetattr() failed\n");
            memset(pass, 0, sizeof(pass));
            return NULL;
        }
#endif
        cli_infomsg(NULL, "\n");
    }

    if ((sockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        cli_errmsg("getdsig: Can't create socket\n");
        memset(pass, 0, sizeof(pass));
        return NULL;
    }

    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = inet_addr(host);
    server.sin_port        = htons(33101);

    if (connect(sockd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
        perror("connect()");
        closesocket(sockd);
        cli_errmsg("getdsig: Can't connect to ClamAV Signing Service at %s\n", host);
        memset(pass, 0, sizeof(pass));
        return NULL;
    }
    memset(cmd, 0, sizeof(cmd));

    if (mode == 1)
        snprintf(cmd, sizeof(cmd) - datalen, "ClamSign:%s:%s:", user, pass);
    else if (mode == 2)
        snprintf(cmd, sizeof(cmd) - datalen, "ClamSignPSS:%s:%s:", user, pass);
    else
        snprintf(cmd, sizeof(cmd) - datalen, "ClamSignPSS2:%s:%s:", user, pass);

    len = strlen(cmd);
    pt  = cmd + len;
    memcpy(pt, data, datalen);
    len += datalen;

    if (send(sockd, cmd, len, 0) < 0) {
        cli_errmsg("getdsig: Can't write to socket\n");
        closesocket(sockd);
        memset(cmd, 0, sizeof(cmd));
        memset(pass, 0, sizeof(pass));
        return NULL;
    }

    memset(cmd, 0, sizeof(cmd));
    memset(pass, 0, sizeof(pass));
    memset(buff, 0, sizeof(buff));

    if ((bread = recv(sockd, buff, sizeof(buff) - 1, 0)) > 0) {
        buff[bread] = '\0';
        if (!strstr(buff, "Signature:")) {
            cli_errmsg("getdsig: Error generating digital signature\n");
            cli_errmsg("getdsig: Answer from remote server: %s\n", buff);
            closesocket(sockd);
            return NULL;
        } else {
            cli_infomsg(NULL, "Signature received (length = %lu)\n", (unsigned long)strlen(buff) - 10);
        }
    } else {
        cli_errmsg("getdsig: Communication error with remote server\n");
        closesocket(sockd);
        return NULL;
    }

    closesocket(sockd);

    pt = buff;
    pt += 10;
    return strdup(pt);
}

int cli_versig(const char *md5, const char *dsig)
{
    fp_int n, e;
    char *pt, *pt2;

    if (strlen(md5) != 32 || !isalnum(md5[0])) {
        /* someone is trying to fool us with empty/malformed MD5 ? */
        cli_errmsg("SECURITY WARNING: MD5 basic test failure.\n");
        return CL_EVERIFY;
    }

    fp_init(&n);
    fp_read_radix(&n, CLI_NSTR, 10);
    fp_init(&e);
    fp_read_radix(&e, CLI_ESTR, 10);

    if (!(pt = (char *)cli_decodesig(dsig, 16, e, n))) {
        return CL_EVERIFY;
    }

    pt2 = cli_str2hex(pt, 16);
    free(pt);

    cli_dbgmsg("cli_versig: Decoded signature: %s\n", pt2);

    if (strncmp(md5, pt2, 32)) {
        cli_dbgmsg("cli_versig: Signature doesn't match.\n");
        free(pt2);
        return CL_EVERIFY;
    }

    free(pt2);

    cli_dbgmsg("cli_versig: Digital signature is correct.\n");
    return CL_SUCCESS;
}

#define HASH_LEN 32
#define SALT_LEN 32
#define PAD_LEN (2048 / 8)
#define BLK_LEN (PAD_LEN - HASH_LEN - 1)
int cli_versig2(const unsigned char *sha256, const char *dsig_str, const char *n_str, const char *e_str)
{
    unsigned char *decoded, digest1[HASH_LEN], digest2[HASH_LEN], digest3[HASH_LEN], *salt;
    unsigned char mask[BLK_LEN], data[BLK_LEN], final[8 + 2 * HASH_LEN], c[4];
    unsigned int i, rounds;
    void *ctx;
    fp_int n, e;

    fp_init(&e);
    fp_read_radix(&e, e_str, 10);
    fp_init(&n);
    fp_read_radix(&n, n_str, 10);

    decoded = cli_decodesig(dsig_str, PAD_LEN, e, n);
    if (!decoded)
        return CL_EVERIFY;

    if (decoded[PAD_LEN - 1] != 0xbc) {
        free(decoded);
        return CL_EVERIFY;
    }

    memcpy(mask, decoded, BLK_LEN);
    memcpy(digest2, &decoded[BLK_LEN], HASH_LEN);
    free(decoded);

    c[0] = c[1] = 0;
    rounds      = (BLK_LEN + HASH_LEN - 1) / HASH_LEN;
    for (i = 0; i < rounds; i++) {
        c[2] = (unsigned char)(i / 256);
        c[3] = (unsigned char)i;

        ctx = cl_hash_init("sha256");
        if (!(ctx))
            return CL_EMEM;

        cl_update_hash(ctx, digest2, HASH_LEN);
        cl_update_hash(ctx, c, 4);
        cl_finish_hash(ctx, digest3);
        if (i + 1 == rounds)
            memcpy(&data[i * 32], digest3, BLK_LEN - i * HASH_LEN);
        else
            memcpy(&data[i * 32], digest3, HASH_LEN);
    }

    for (i = 0; i < BLK_LEN; i++)
        data[i] ^= mask[i];
    data[0] &= (0xff >> 1);

    if (!(salt = memchr(data, 0x01, BLK_LEN)))
        return CL_EVERIFY;
    salt++;

    if (data + BLK_LEN - salt != SALT_LEN)
        return CL_EVERIFY;

    memset(final, 0, 8);
    memcpy(&final[8], sha256, HASH_LEN);
    memcpy(&final[8 + HASH_LEN], salt, SALT_LEN);

    ctx = cl_hash_init("sha256");
    if (!(ctx))
        return CL_EMEM;

    cl_update_hash(ctx, final, sizeof(final));
    cl_finish_hash(ctx, digest1);

    return memcmp(digest1, digest2, HASH_LEN) ? CL_EVERIFY : CL_SUCCESS;
}
