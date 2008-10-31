/*
 *  Copyright (C) 2007 Nigel Horne <njh@bandsman.co.uk>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
 *
 * Compare the results of scanning files on a set of machines
 *	This is useful for regression testing versions, and for testing
 *	across different operating systems and architectures
 * The file is always copied which is slow, and could be removed for regression
 *	testing, if we have some mechanism to sync the data
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <memory.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>

#define	PORT	3310
#define	LEN	128

/*
 * Ensure you don't have StreamMaxLength on any of the servers, or that it's
 *	big enough for all your samples
 * Uses SESSIONS, which isn't good
 * If localhost is one of them, it's probably best to put it last so that it
 *	can be scanning while waiting for the remote machines to respond
 */
static struct machine {
	const	char	*name;
	in_addr_t	ip;
	int	sock;
} machines[] = {
	{	"eric",		0,	-1	},
	/*{	"motorola",	0,	-1	},*/
	/*{	"ultra60",	0,	-1	},*/
	{	"mac",		0,	-1	},
	{	"localhost",	0,	-1	},
	{	NULL,		0,	-1	}
};

struct args {
	const	char	*filename;
	const	struct	machine	*m;
	char	*ret;
};

static	void	dir(const char *dirname);
static	in_addr_t	resolve(const char *machine);
static	int	start(in_addr_t ip);
static	void	*scan(void *v);

int
main(int argc, char **argv)
{
	struct machine *m;

	if(argc <= 1) {
		fputs("Arg count\n", stderr);
		return 1;
	}

	for(m = machines; m->name; m++) {
		m->ip = resolve(m->name);

		if(m->ip == INADDR_NONE) {
			fprintf(stderr, "Can't resolve %s\n", m->name);
			return 1;
		}
		m->sock = start(m->ip);
		if(m->sock < 0)
			fprintf(stderr, "%s is down\n", m->name);
	}

	signal(SIGPIPE, SIG_IGN);

	while(*++argv)
		dir(*argv);

	return 0;
}

static void
dir(const char *dirname)
{
	int i, nmachines;
	const struct dirent *dirent;
	struct machine *m;
	DIR *d = opendir(dirname);
	char **results;

	if(d == NULL) {
		perror(dirname);
		return;
	}
	for(nmachines = 0, m = machines; m->name; m++)
		if(m->sock >= 0)
			nmachines++;

	if(nmachines < 2) {
		fputs("Needs at least 2 machines up to run\n", stderr);
		closedir(d);
		return;
	}

	results = (char **)malloc(nmachines * sizeof(char *));
	if(results == NULL)
		return;
	for(i = 0, m = machines; m->name; m++)
		if(m->sock >= 0) {
			results[i] = malloc(LEN);
			if(results[i++] == NULL) {
				free(results);
				closedir(d);
				return;
			}
		}

	if(i != nmachines) {
		fputs("Failed sanity check\n", stderr);
		closedir(d);
		return;
	}

	while((dirent = readdir(d)) != NULL) {
		int nthreads, founddiffs;
		pthread_t *tids;
		struct args *args;
		char name[PATH_MAX];

		if(dirent->d_ino == (ino_t)0)
			continue;
		if(dirent->d_name[0] == '.')
			continue;

		tids = malloc(nmachines * sizeof(pthread_t));
		if(tids == NULL) {
			free(results);
			closedir(d);
			return;
		}
		args = malloc(nmachines * sizeof(struct args));
		if(args == NULL) {
			free(tids);
			free(results);
			closedir(d);
			return;
		}

		snprintf(name, sizeof(name) -1, "%s/%s", dirname, dirent->d_name);
		for(nthreads = 0, m = machines; m->name; m++) {
			if(m->sock < 0)
				continue;

			args[nthreads].filename = name;
			args[nthreads].m = m;
			args[nthreads].ret = results[nthreads];
			pthread_create(&tids[nthreads], NULL, scan, &args[nthreads]);
			nthreads++;
		}
		/*printf("Scanning %s\n", name);*/
		founddiffs = 0;
		while(--nthreads >= 0)
			/* TODO: timeout */
			pthread_join(tids[nthreads], NULL);

		free(args);
		free(tids);
		for(i = 0; i <= nmachines - 2; i++) {
			int j;

			for(j = i + 1; j <= nmachines - 1; j++) {
				const char *s, *t;

				s = strchr(results[i], ' ');
				t = strchr(results[j], ' ');
				if((s == NULL) || (t == NULL) || (strcmp(s, t) != 0)) {
					printf("%s:\n", name);
					printf("\t%s: %s\n", machines[i].name, s ? s : "null");
					printf("\t%s: %s\n", machines[j].name, t ? t : "null");
					founddiffs = 1;
				}
			}
		}

		/*if(!founddiffs)
			printf("%s passed\n", name);*/
	}
	closedir(d);
}

static in_addr_t
resolve(const char *machine)
{
	in_addr_t ret = inet_addr(machine);

	if(ret == INADDR_NONE) {
		const struct hostent *h = gethostbyname(machine);

		if(h == NULL) {
			fprintf(stderr, "Unknown host %s\n", machine);
			return INADDR_NONE;
		}

		memcpy((char *)&ret, h->h_addr, sizeof(in_addr_t));
	}
	return ret;
}

static int
start(in_addr_t ip)
{
	int sock;
	const struct protoent *proto;
	struct sockaddr_in server;

	memset((char *)&server, 0, sizeof(struct sockaddr_in));
	server.sin_family = AF_INET;
	server.sin_port = (in_port_t)htons(PORT);
	server.sin_addr.s_addr = ip;

	proto = getprotobyname("tcp");
	if(proto == NULL) {
		fputs("Unknown prototol tcp, check /etc/protocols\n", stderr);
		return -1;
	} else if((sock = socket(AF_INET, SOCK_STREAM, proto->p_proto)) < 0) {
		perror("socket");
		return -1;
	} else if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) < 0) {
		perror("connect");
		close(sock);
		return -1;
	} else if(send(sock, "SESSION\n", 8, 0) < 8) {
		perror("send");
		close(sock);
		return -1;
	}
	return sock;
}

static void *
scan(void *v)
{
	struct args *args;
	FILE *fin;
	int sock;
	ssize_t nbytes;
	size_t buflen;
	in_port_t port;
	struct sockaddr_in data;
	const struct machine *m;
	char buf[1024];	/* must be less than MTU */

	args = (struct args *)v;
	m = args->m;
	if(m->sock < 0)
		return NULL;
	if(m->ip == htonl(INADDR_LOOPBACK)) {
		char cmd[NAME_MAX + 7];

		snprintf(cmd, sizeof(cmd) - 1, "SCAN %s\n", args->filename);
		buflen = strlen(cmd);

		if(send(m->sock, cmd, buflen, 0) != (ssize_t)buflen) {
			perror(m->name);
			return NULL;
		}
		nbytes = recv(m->sock, args->ret, LEN, 0);
		if(nbytes < 0) {
			perror(m->name);
			return NULL;
		}
		args->ret[nbytes - 1] = '\0';	/* remove the trailing \n */

		return NULL;
	}
	fin = fopen(args->filename, "r");
	if(fin == NULL) {
		perror(args->filename);
		return NULL;
	}
	if(send(m->sock, "STREAM\n", 7, 0) != 7) {
		perror(m->name);
		fclose(fin);
		return NULL;
	}

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		fputs("Failed to create TCPSocket to talk to clamd\n", stderr);
		fclose(fin);
		return NULL;
	}

	nbytes = recv(m->sock, buf, sizeof(buf), 0);
	if(nbytes <= 0) {
		perror(m->name);
		close(sock);
		fclose(fin);
		return NULL;
	}
	buf[nbytes] = '\0';

	if(sscanf(buf, "PORT %hu\n", &port) != 1) {
		fprintf(stderr, "Expected port information from clamd, got '%s'",
			buf);
		close(sock);
		fclose(fin);
		return NULL;
	}

	memset((char *)&data, 0, sizeof(struct sockaddr_in));
	data.sin_family = AF_INET;
	data.sin_port = (in_port_t)htons(port);
	data.sin_addr.s_addr = m->ip;

	if(connect(sock, (struct sockaddr *)&data, sizeof(struct sockaddr_in)) < 0) {
		perror(m->name);
		fprintf(stderr, "Couldn't connect to port %d\n", port);
		close(sock);
		fclose(fin);
		return NULL;
	}

	shutdown(sock, SHUT_RD);

	while((buflen = fread(buf, 1, sizeof(buf), fin)) > 0) {
		ssize_t sent = send(sock, buf, buflen, 0);

		if(sent != (ssize_t)buflen) {
			/* Probably hit scanstream len */
			if(sent < 0)
				perror(m->name);
			else
				fprintf(stderr, "%s: only sent %d bytes of %d to %s\n",
					args->filename, sent, buflen, m->name);
			break;
		}
	}

	close(sock);
	fclose(fin);

	/* TODO: timeout */
	nbytes = recv(m->sock, args->ret, LEN, 0);
	if(nbytes < 0) {
		perror(m->name);
		return NULL;
	}
	args->ret[(nbytes) ? (nbytes - 1) : 0] = '\0';	/* remove the trailing \n */

	return NULL;
}
