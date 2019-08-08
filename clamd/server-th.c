/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Trog, Török Edvin
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
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#ifndef	_WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#endif
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <fcntl.h>
#ifdef C_SOLARIS
#include <stdio_ext.h>
#endif
#include "libclamav/clamav.h"

#include "shared/output.h"
#include "shared/optparser.h"
#include "shared/misc.h"

#include "shared/idmef_logging.h"

#include "onaccess_fan.h"
#include "server.h"
#include "thrmgr.h"
#include "session.h"
#include "others.h"
#include "shared.h"
#include "libclamav/others.h"
#include "libclamav/readdb.h"

#define BUFFSIZE 1024

int progexit = 0;
pthread_mutex_t exit_mutex = PTHREAD_MUTEX_INITIALIZER;
int reload = 0;
time_t reloaded_time = 0;
pthread_mutex_t reload_mutex = PTHREAD_MUTEX_INITIALIZER;
int sighup = 0;
extern pthread_mutex_t logg_mutex;
static struct cl_stat dbstat;

void *event_wake_recv = NULL;
void *event_wake_accept = NULL;

static void scanner_thread(void *arg)
{
	client_conn_t *conn = (client_conn_t *) arg;
#ifndef	_WIN32
	sigset_t sigset;
#endif
	int ret;
	int virus=0, errors = 0;

#ifndef	_WIN32
    /* ignore all signals */
    sigfillset(&sigset);
    /* The behavior of a process is undefined after it ignores a
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    sigdelset(&sigset, SIGTSTP);
    sigdelset(&sigset, SIGCONT);
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
#endif

    ret = command(conn, &virus);
    if (ret == -1) {
	pthread_mutex_lock(&exit_mutex);
	progexit = 1;
	pthread_mutex_unlock(&exit_mutex);
	errors = 1;
    } else
	errors = ret;

    thrmgr_setactiveengine(NULL);

    if (conn->filename)
	free(conn->filename);
    logg("$Finished scanthread\n");
    if (thrmgr_group_finished(conn->group, virus ? EXIT_OTHER :
			      errors ? EXIT_ERROR : EXIT_OK)) {
	logg("$Scanthread: connection shut down (FD %d)\n", conn->sd);
	/* close connection if we were last in group */
	shutdown(conn->sd, 2);
	closesocket(conn->sd);
    }
    cl_engine_free(conn->engine);
    free(conn);
    return;
}

static int syncpipe_wake_recv_w = -1;

void sighandler_th(int sig)
{
    int action = 0;
    switch(sig) {
	case SIGINT:
	case SIGTERM:
	    progexit = 1;
	    action = 1;
	    break;

#ifdef	SIGHUP
	case SIGHUP:
	    sighup = 1;
	    action = 1;
	    break;
#endif

#ifdef	SIGUSR2
	case SIGUSR2:
	    reload = 1;
	    action = 1;
	    break;
#endif

	default:
	    break; /* Take no action on other signals - e.g. SIGPIPE */
    }
    /* a signal doesn't always wake poll(), for example on FreeBSD */
    if (action && syncpipe_wake_recv_w != -1)
	if (write(syncpipe_wake_recv_w, "", 1) != 1)
	    logg("$Failed to write to syncpipe\n");
}

static struct cl_engine *reload_db(struct cl_engine *engine, unsigned int dboptions, const struct optstruct *opts, int do_check, int *ret)
{
	const char *dbdir;
	int retval;
	unsigned int sigs = 0;
	struct cl_settings *settings = NULL;

    *ret = 0;
    if(do_check) {
	if(!dbstat.entries) {
	    logg("No stats for Database check - forcing reload\n");
	    return engine;
	}

	if(cl_statchkdir(&dbstat) == 1) {
	    logg("SelfCheck: Database modification detected. Forcing reload.\n");
	    return engine;
	} else {
	    logg("SelfCheck: Database status OK.\n");
	    return NULL;
	}
    }

    /* release old structure */
    if(engine) {
	/* copy current settings */
	settings = cl_engine_settings_copy(engine);
	if(!settings)
	    logg("^Can't make a copy of the current engine settings\n");

	thrmgr_setactiveengine(NULL);
	cl_engine_free(engine);
    }

    dbdir = optget(opts, "DatabaseDirectory")->strarg;
    logg("Reading databases from %s\n", dbdir);

    if(dbstat.entries)
	cl_statfree(&dbstat);

    memset(&dbstat, 0, sizeof(struct cl_stat));
    if((retval = cl_statinidir(dbdir, &dbstat))) {
	logg("!cl_statinidir() failed: %s\n", cl_strerror(retval));
	*ret = 1;
	if(settings)
	    cl_engine_settings_free(settings);
	return NULL;
    }

    if(!(engine = cl_engine_new())) {
	logg("!Can't initialize antivirus engine\n");
	*ret = 1;
	if(settings)
	    cl_engine_settings_free(settings);
	return NULL;
    }

    if(settings) {
	retval = cl_engine_settings_apply(engine, settings);
	if(retval != CL_SUCCESS) {
	    logg("^Can't apply previous engine settings: %s\n", cl_strerror(retval));
	    logg("^Using default engine settings\n");
	}
	cl_engine_settings_free(settings);
    }

    if((retval = cl_load(dbdir, engine, &sigs, dboptions))) {
	logg("!reload db failed: %s\n", cl_strerror(retval));
	cl_engine_free(engine);
	*ret = 1;
	return NULL;
    }

    if((retval = cl_engine_compile(engine)) != 0) {
	logg("!Database initialization error: can't compile engine: %s\n", cl_strerror(retval));
	cl_engine_free(engine);
	*ret = 1;
	return NULL;
    }
    logg("Database correctly reloaded (%u signatures)\n", sigs);

    thrmgr_setactiveengine(engine);
    return engine;
}

/*
 * zCOMMANDS are delimited by \0
 * nCOMMANDS are delimited by \n
 * Old-style non-prefixed commands are one packet, optionally delimited by \n,
 * with trailing \r|\n ignored
 */
static const char *get_cmd(struct fd_buf *buf, size_t off, size_t *len, char *term, int *oldstyle)
{
    char *pos;
    if (!buf->off || off >= buf->off) {
	*len = 0;
	return NULL;
    }

    *term = '\n';
    switch (buf->buffer[off]) {
	/* commands terminated by delimiters */
	case 'z':
	    *term = '\0';
	case 'n':
	    pos = memchr(buf->buffer + off, *term, buf->off - off);
	    if (!pos) {
		/* we don't have another full command yet */
		*len = 0;
		return NULL;
	    }
	    *pos = '\0';
	    if (*term) {
		*len = cli_chomp(buf->buffer + off);
	    } else {
		*len = pos - buf->buffer - off;
	    }
	    *oldstyle = 0;
	    return buf->buffer + off + 1;
	default:
	    /* one packet = one command */
	    if (off)
		return NULL;
	    pos = memchr(buf->buffer, '\n', buf->off);
	    if (pos) {
		*len = pos - buf->buffer;
		*pos = '\0';
	    } else {
		*len = buf->off;
		buf->buffer[buf->off] = '\0';
	    }
	    cli_chomp(buf->buffer);
	    *oldstyle = 1;
	    return buf->buffer;
    }
}

int statinidir_th(const char* dirname)
{
   if (!dbstat.entries) {
      memset(&dbstat, 0, sizeof(dbstat));
   }

   return cl_statinidir(dirname, &dbstat);
}

struct acceptdata {
    struct fd_data fds;
    struct fd_data recv_fds;
    pthread_cond_t cond_nfds;
    int max_queue;
    int commandtimeout;
    int syncpipe_wake_recv[2];
    int syncpipe_wake_accept[2];
};

#define ACCEPTDATA_INIT(mutex1, mutex2) { FDS_INIT(mutex1), FDS_INIT(mutex2), PTHREAD_COND_INITIALIZER, 0, 0, {-1, -1}, {-1, -1}}

static void *acceptloop_th(void *arg)
{
    char buff[BUFFSIZE + 1];
    size_t i;
    struct acceptdata *data = (struct acceptdata*)arg;
    struct fd_data *fds = &data->fds;
    struct fd_data *recv_fds = &data->recv_fds;
    int max_queue = data->max_queue;
    int commandtimeout = data->commandtimeout;

    pthread_mutex_lock(fds->buf_mutex);
    for (;;) {
	/* Block waiting for data to become available for reading */
	int new_sd = fds_poll_recv(fds, -1, 0, event_wake_accept);
#ifdef _WIN32
	ResetEvent(event_wake_accept);
#endif
	/* TODO: what about sockets that get rm-ed? */
	if (!fds->nfds) {
	    /* no more sockets to poll, all gave an error */
	    logg("!Main socket gone: fatal\n");
	    break;
	}

	if (new_sd == -1 && errno != EINTR) {
	    logg("!Failed to poll sockets, fatal\n");
	    pthread_mutex_lock(&exit_mutex);
	    progexit = 1;
	    pthread_mutex_unlock(&exit_mutex);
	    break;
	}

	/* accept() loop */
	for (i=0;i < fds->nfds && new_sd >= 0; i++) {
	    struct fd_buf *buf = &fds->buf[i];
	    if (!buf->got_newdata)
		continue;
#ifndef _WIN32
	    if (buf->fd == data->syncpipe_wake_accept[0]) {
		/* dummy sync pipe, just to wake us */
		if (read(buf->fd, buff, sizeof(buff)) < 0) {
		    logg("^Syncpipe read failed\n");
		}
		continue;
	    }
#endif
	    if (buf->got_newdata == -1) {
		logg("$Acceptloop closed FD: %d\n", buf->fd);
		shutdown(buf->fd, 2);
		closesocket(buf->fd);
		buf->fd = -1;
		continue;
	    }

	    /* don't accept unlimited number of connections, or
	     * we'll run out of file descriptors */
	    pthread_mutex_lock(recv_fds->buf_mutex);
	    while (recv_fds->nfds > (unsigned)max_queue) {
		pthread_mutex_lock(&exit_mutex);
		if(progexit) {
		    pthread_mutex_unlock(&exit_mutex);
		    break;
		}
		pthread_mutex_unlock(&exit_mutex);
		pthread_cond_wait(&data->cond_nfds, recv_fds->buf_mutex);
	    }
	    pthread_mutex_unlock(recv_fds->buf_mutex);

	    pthread_mutex_lock(&exit_mutex);
	    if(progexit) {
		pthread_mutex_unlock(&exit_mutex);
		break;
	    }
	    pthread_mutex_unlock(&exit_mutex);

	    /* listen only socket */
	    new_sd = accept(fds->buf[i].fd, NULL, NULL);

	    if (new_sd >= 0) {
		int ret, flags;
#ifdef F_GETFL
		flags = fcntl(new_sd, F_GETFL, 0);
		if (flags != -1) {
		    if (fcntl(new_sd, F_SETFL, flags | O_NONBLOCK) == -1) {
			logg("^Can't set socket to nonblocking mode, errno %d\n",
			     errno);
		    }
		} else {
			logg("^Can't get socket flags, errno %d\n", errno);
		}
#else
		logg("^Nonblocking sockets not available!\n");
#endif
		logg("$Got new connection, FD %d\n", new_sd);
		pthread_mutex_lock(recv_fds->buf_mutex);
		ret = fds_add(recv_fds, new_sd, 0, commandtimeout);
		pthread_mutex_unlock(recv_fds->buf_mutex);

		if (ret == -1) {
		    logg("!fds_add failed\n");
		    closesocket(new_sd);
		    continue;
		}

		/* notify recvloop */
#ifdef _WIN32
		SetEvent(event_wake_recv);
#else
		if (write(data->syncpipe_wake_recv[1], "", 1) == -1) {
		    logg("!write syncpipe failed\n");
		    continue;
		}
#endif
	    } else if (errno != EINTR) {
		/* very bad - need to exit or restart */
#ifdef HAVE_STRERROR_R
		(void)strerror_r(errno, buff, BUFFSIZE);
		logg("!accept() failed: %s\n", buff);
#else
		logg("!accept() failed\n");
#endif
		/* give the poll loop a chance to close disconnected FDs */
		break;
	    }

	}

	/* handle progexit */
	pthread_mutex_lock(&exit_mutex);
	if (progexit) {
	    pthread_mutex_unlock(&exit_mutex);
	    break;
	}
	pthread_mutex_unlock(&exit_mutex);
    }
    pthread_mutex_unlock(fds->buf_mutex);

    if (sd_listen_fds(0) == 0)
    {
        /* only close the sockets, when not using systemd socket activation */
        for (i=0;i < fds->nfds; i++)
        {
            if (fds->buf[i].fd == -1)
                continue;
            logg("$Shutdown: closed fd %d\n", fds->buf[i].fd);
            shutdown(fds->buf[i].fd, 2);
            closesocket(fds->buf[i].fd);
        }
    }

    fds_free(fds);
    pthread_mutex_destroy(fds->buf_mutex);
    pthread_mutex_lock(&exit_mutex);
    progexit = 1;
    pthread_mutex_unlock(&exit_mutex);
#ifdef _WIN32
    SetEvent(event_wake_recv);
#else
    if (write(data->syncpipe_wake_recv[1], "", 1) < 0) {
	logg("$Syncpipe write failed\n");
    }
#endif
    return NULL;
}

static const char* parse_dispatch_cmd(client_conn_t *conn, struct fd_buf *buf, size_t *ppos, int *error, const struct optstruct *opts, int readtimeout)
{
    const char *cmd = NULL;
    int rc;
    size_t cmdlen;
    char term;
    int oldstyle;
    size_t pos = *ppos;
    /* Parse & dispatch commands */
    while ((conn->mode == MODE_COMMAND) &&
	   (cmd = get_cmd(buf, pos, &cmdlen, &term, &oldstyle)) != NULL) {
	const char *argument;
	enum commands cmdtype;
	if (conn->group && oldstyle) {
	    logg("$Received oldstyle command inside IDSESSION: %s\n", cmd);
	    conn_reply_error(conn, "Only nCMDS\\n and zCMDS\\0 are accepted inside IDSESSION.");
	    *error = 1;
	    break;
	}
	cmdtype = parse_command(cmd, &argument, oldstyle);
	logg("$got command %s (%u, %u), argument: %s\n",
	     cmd, (unsigned)cmdlen, (unsigned)cmdtype, argument ? argument : "");
	if (cmdtype == COMMAND_FILDES) {
	    if (buf->buffer + buf->off <= cmd + strlen("FILDES\n")) {
		/* we need the extra byte from recvmsg */
		conn->mode = MODE_WAITANCILL;
		buf->mode = MODE_WAITANCILL;
		/* put term back */
		buf->buffer[pos + cmdlen] = term;
		cmdlen = 0;
		logg("$RECVTH: mode -> MODE_WAITANCILL\n");
		break;
	    }
	    /* eat extra \0 for controlmsg */
	    cmdlen++;
	    logg("$RECVTH: FILDES command complete\n");
	}
	conn->term = term;
	buf->term = term;

	if ((rc = execute_or_dispatch_command(conn, cmdtype, argument)) < 0) {
	    logg("!Command dispatch failed\n");
	    if(rc == -1 && optget(opts, "ExitOnOOM")->enabled) {
		pthread_mutex_lock(&exit_mutex);
		progexit = 1;
		pthread_mutex_unlock(&exit_mutex);
	    }
	    *error = 1;
	}
	if (thrmgr_group_need_terminate(conn->group)) {
	    logg("$Receive thread: have to terminate group\n");
	    *error = CL_ETIMEOUT;
	    break;
	}
	if (*error || !conn->group || rc) {
	    if (rc && thrmgr_group_finished(conn->group, EXIT_OK)) {
		logg("$Receive thread: closing conn (FD %d), group finished\n", conn->sd);
		/* if there are no more active jobs */
		shutdown(conn->sd, 2);
		closesocket(conn->sd);
		buf->fd = -1;
		conn->group = NULL;
	    } else if (conn->mode != MODE_STREAM) {
		logg("$mode -> MODE_WAITREPLY\n");
		/* no more commands are accepted */
		conn->mode = MODE_WAITREPLY;
		/* Stop monitoring this FD, it will be closed either
		 * by us, or by the scanner thread.
		 * Never close a file descriptor that is being
		 * monitored by poll()/select() from another thread,
		 * because this can lead to subtle bugs such as:
		 * Other thread closes file descriptor -> POLLHUP is
		 * set, but the poller thread doesn't wake up yet.
		 * Another client opens a connection and sends some
		 * data. If the socket reuses the previous file descriptor,
		 * then POLLIN is set on the file descriptor too.
		 * When poll() wakes up it sees POLLIN | POLLHUP
		 * and thinks that the client has sent some data,
		 * and closed the connection, so clamd closes the
		 * connection in turn resulting in a bug.
		 *
		 * If we wouldn't have poll()-ed the file descriptor
		 * we closed in another thread, but rather made sure
		 * that we don't put a FD that we're about to close
		 * into poll()'s list of watched fds; then POLLHUP
		 * would be set, but the file descriptor would stay
		 * open, until we wake up from poll() and close it.
		 * Thus a new connection won't be able to reuse the
		 * same FD, and there is no bug.
		 * */
		buf->fd = -1;
	    }
	}
	/* we received a command, set readtimeout */
	time(&buf->timeout_at);
	buf->timeout_at += readtimeout;
	pos += cmdlen+1;
	if (conn->mode == MODE_STREAM) {
	    /* TODO: this doesn't belong here */
	    buf->dumpname = conn->filename;
	    buf->dumpfd = conn->scanfd;
	    logg("$Receive thread: INSTREAM: %s fd %u\n", buf->dumpname, buf->dumpfd);
	}
	if (conn->mode != MODE_COMMAND) {
	    logg("$Breaking command loop, mode is no longer MODE_COMMAND\n");
	    break;
	}
	conn->id++;
    }
    *ppos = pos;
    buf->mode = conn->mode;
    buf->id = conn->id;
    buf->group = conn->group;
    buf->quota = conn->quota;
    if (conn->scanfd != -1 && conn->scanfd != buf->dumpfd) {
	logg("$Unclaimed file descriptor received, closing: %d\n", conn->scanfd);
	close(conn->scanfd);
	/* protocol error */
	conn_reply_error(conn, "PROTOCOL ERROR: ancillary data sent without FILDES.");
	*error = 1;
	return NULL;
    }
    if (!*error) {
	/* move partial command to beginning of buffer */
	if (pos < buf->off) {
	    memmove (buf->buffer, &buf->buffer[pos], buf->off - pos);
	    buf->off -= pos;
	} else
	    buf->off = 0;
	if (buf->off)
	    logg("$Moved partial command: %lu\n", (unsigned long)buf->off);
	else
	    logg("$Consumed entire command\n");
	/* adjust pos to account for the buffer shuffle */
	pos = 0;
    }
    *ppos = pos;
    return cmd;
}

/* static const unsigned char* parse_dispatch_cmd(client_conn_t *conn, struct fd_buf *buf, size_t *ppos, int *error, const struct optstruct *opts, int readtimeout) */
static int handle_stream(client_conn_t *conn, struct fd_buf *buf, const struct optstruct *opts, int *error, size_t *ppos, int readtimeout)
{
    int rc;
    size_t pos = *ppos;
    size_t cmdlen;

    logg("$mode == MODE_STREAM\n");
    /* we received some data, set readtimeout */
    time(&buf->timeout_at);
    buf->timeout_at += readtimeout;
    while (pos <= buf->off) {
	if (!buf->chunksize) {
	    /* read chunksize */
	    if (buf->off-pos >= 4) {
		uint32_t cs;
		memmove(&cs, buf->buffer + pos, 4);
		pos += 4;
		buf->chunksize = ntohl(cs);
		logg("$Got chunksize: %u\n", buf->chunksize);
		if (!buf->chunksize) {
		    /* chunksize 0 marks end of stream */
		    conn->scanfd = buf->dumpfd;
		    conn->term = buf->term;
		    buf->dumpfd = -1;
		    buf->mode = buf->group ? MODE_COMMAND : MODE_WAITREPLY;
		    if (buf->mode == MODE_WAITREPLY)
			buf->fd = -1;
		    logg("$Chunks complete\n");
		    buf->dumpname = NULL;
		    if ((rc = execute_or_dispatch_command(conn, COMMAND_INSTREAMSCAN, NULL)) < 0) {
			logg("!Command dispatch failed\n");
			if(rc == -1 && optget(opts, "ExitOnOOM")->enabled) {
			    pthread_mutex_lock(&exit_mutex);
			    progexit = 1;
			    pthread_mutex_unlock(&exit_mutex);
			}
			*error = 1;
		    } else {
			memmove (buf->buffer, &buf->buffer[pos], buf->off - pos);
			buf->off -= pos;
			*ppos = 0;
			buf->id++;
			return 0;
                    }
		}
		if (buf->chunksize > buf->quota) {
		    logg("^INSTREAM: Size limit reached, (requested: %lu, max: %lu)\n",
			 (unsigned long)buf->chunksize, (unsigned long)buf->quota);
		    conn_reply_error(conn, "INSTREAM size limit exceeded.");
                    *error = 1;
		    *ppos = pos;
		    return -1;
                } else {
		    buf->quota -= buf->chunksize;
                }
		logg("$Quota Remaining: %lu\n", buf->quota);
	    } else {
		/* need more data, so return and wait for some */
		memmove (buf->buffer, &buf->buffer[pos], buf->off - pos);
		buf->off -= pos;
		*ppos = 0;
                return -1;
            }
	}
	if (pos + buf->chunksize < buf->off)
	    cmdlen = buf->chunksize;
	else
	    cmdlen = buf->off - pos;
	buf->chunksize -= cmdlen;
	if (cli_writen(buf->dumpfd, buf->buffer + pos, cmdlen) < 0) {
	    conn_reply_error(conn, "Error writing to temporary file");
	    logg("!INSTREAM: Can't write to temporary file.\n");
	    *error = 1;
	}
	logg("$Processed %llu bytes of chunkdata, pos %llu\n", (long long unsigned)cmdlen, (long long unsigned)pos);
	pos += cmdlen;
	if (pos == buf->off) {
	    buf->off = 0;
	    pos = 0;
	    /* need more data, so return and wait for some */
	    *ppos = pos;
            return -1;
	}
    }
    *ppos = pos;
    return 0;
}

int recvloop_th(int *socketds, unsigned nsockets, struct cl_engine *engine, unsigned int dboptions, const struct optstruct *opts)
{
	int max_threads, max_queue, readtimeout, ret = 0;
	struct cl_scan_options options;
	char timestr[32];
#ifndef	_WIN32
	struct sigaction sigact;
	sigset_t sigset;
	struct rlimit rlim;
#endif
	mode_t old_umask;
	const struct optstruct *opt;
	char buff[BUFFSIZE + 1];
	pid_t mainpid;
	int idletimeout;
	unsigned long long val;
	size_t i, j, rr_last = 0;
	pthread_t accept_th;
	pthread_mutex_t fds_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t recvfds_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct acceptdata acceptdata = ACCEPTDATA_INIT(&fds_mutex, &recvfds_mutex);
	struct fd_data *fds = &acceptdata.recv_fds;
	time_t start_time, current_time;
	unsigned int selfchk;
	threadpool_t *thr_pool;

#if defined(FANOTIFY) || defined(CLAMAUTH)
	pthread_t fan_pid = 0;
	pthread_attr_t fan_attr;
	struct thrarg *tharg = NULL; /* shut up gcc */
#endif

#ifndef	_WIN32
	memset(&sigact, 0, sizeof(struct sigaction));
#endif

	/* Initalize scan options struct */
	memset(&options, 0, sizeof(struct cl_scan_options));

    /* set up limits */
    if ((opt = optget(opts, "MaxScanTime"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, opt->numarg))) {
            logg("!cl_engine_set_num(CL_ENGINE_MAX_SCANTIME) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_SCANTIME, NULL);
    if (val)
        logg("Limits: Global time limit set to %llu milliseconds.\n", val);
    else
        logg("^Limits: Global time limit protection disabled.\n");

    if ((opt = optget(opts, "MaxScanSize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, opt->numarg))) {
            logg("!cl_engine_set_num(CL_ENGINE_MAX_SCANSIZE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_SCANSIZE, NULL);
    if(val)
    	logg("Limits: Global size limit set to %llu bytes.\n", val);
    else
    	logg("^Limits: Global size limit protection disabled.\n");

    if((opt = optget(opts, "MaxFileSize"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, opt->numarg))) {
	    logg("!cl_engine_set_num(CL_ENGINE_MAX_FILESIZE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 1;
	}
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL);
    if(val)
    	logg("Limits: File size limit set to %llu bytes.\n", val);
    else
    	logg("^Limits: File size limit protection disabled.\n");

#ifndef _WIN32
    if(getrlimit(RLIMIT_FSIZE, &rlim) == 0) {
	if(rlim.rlim_cur < (rlim_t) cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL))
	    logg("^System limit for file size is lower than engine->maxfilesize\n");
	if(rlim.rlim_cur < (rlim_t) cl_engine_get_num(engine, CL_ENGINE_MAX_SCANSIZE, NULL))
	    logg("^System limit for file size is lower than engine->maxscansize\n");
    } else {
	logg("^Cannot obtain resource limits for file size\n");
    }
#endif

    if((opt = optget(opts, "MaxRecursion"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_RECURSION, opt->numarg))) {
	    logg("!cl_engine_set_num(CL_ENGINE_MAX_RECURSION) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 1;
	}
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_RECURSION, NULL);
    if(val)
    	logg("Limits: Recursion level limit set to %u.\n", (unsigned int) val);
    else
    	logg("^Limits: Recursion level limit protection disabled.\n");

    if((opt = optget(opts, "MaxFiles"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, opt->numarg))) {
	    logg("!cl_engine_set_num(CL_ENGINE_MAX_FILES) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 1;
	}
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_FILES, NULL);
    if(val)
    	logg("Limits: Files limit set to %u.\n", (unsigned int) val);
    else
    	logg("^Limits: Files limit protection disabled.\n");

#ifndef _WIN32
    if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
	logg("*Limits: Core-dump limit is %lu.\n", (unsigned long)rlim.rlim_cur);
    }
#endif

    /* Engine max sizes */

    if((opt = optget(opts, "MaxEmbeddedPE"))->active) {
        if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_EMBEDDEDPE, opt->numarg))) {
            logg("!cli_engine_set_num(CL_ENGINE_MAX_EMBEDDEDPE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_EMBEDDEDPE, NULL);
    logg("Limits: MaxEmbeddedPE limit set to %llu bytes.\n", val);

    if((opt = optget(opts, "MaxHTMLNormalize"))->active) {
        if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, opt->numarg))) {
            logg("!cli_engine_set_num(CL_ENGINE_MAX_HTMLNORMALIZE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, NULL);
    logg("Limits: MaxHTMLNormalize limit set to %llu bytes.\n", val);

    if((opt = optget(opts, "MaxHTMLNoTags"))->active) {
        if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNOTAGS, opt->numarg))) {
            logg("!cli_engine_set_num(CL_ENGINE_MAX_HTMLNOTAGS) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_HTMLNOTAGS, NULL);
    logg("Limits: MaxHTMLNoTags limit set to %llu bytes.\n", val);

    if((opt = optget(opts, "MaxScriptNormalize"))->active) {
        if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCRIPTNORMALIZE, opt->numarg))) {
            logg("!cli_engine_set_num(CL_ENGINE_MAX_SCRIPTNORMALIZE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_SCRIPTNORMALIZE, NULL);
    logg("Limits: MaxScriptNormalize limit set to %llu bytes.\n", val);

    if((opt = optget(opts, "MaxZipTypeRcg"))->active) {
        if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_ZIPTYPERCG, opt->numarg))) {
            logg("!cli_engine_set_num(CL_ENGINE_MAX_ZIPTYPERCG) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_ZIPTYPERCG, NULL);
    logg("Limits: MaxZipTypeRcg limit set to %llu bytes.\n", val);

    if((opt = optget(opts, "MaxPartitions"))->active) {
        if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_PARTITIONS, opt->numarg))) {
            logg("!cli_engine_set_num(MaxPartitions) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_PARTITIONS, NULL);
    logg("Limits: MaxPartitions limit set to %llu.\n", val);

    if((opt = optget(opts, "MaxIconsPE"))->active) {
        if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_ICONSPE, opt->numarg))) {
            logg("!cli_engine_set_num(MaxIconsPE) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_ICONSPE, NULL);
    logg("Limits: MaxIconsPE limit set to %llu.\n", val);

    if((opt = optget(opts, "MaxRecHWP3"))->active) {
        if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_RECHWP3, opt->numarg))) {
            logg("!cli_engine_set_num(MaxRecHWP3) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_MAX_RECHWP3, NULL);
    logg("Limits: MaxRecHWP3 limit set to %llu.\n", val);

    /* options are handled in main (clamd.c) */
    val = cl_engine_get_num(engine, CL_ENGINE_PCRE_MATCH_LIMIT, NULL);
    logg("Limits: PCREMatchLimit limit set to %llu.\n", val);

    val = cl_engine_get_num(engine, CL_ENGINE_PCRE_RECMATCH_LIMIT, NULL);
    logg("Limits: PCRERecMatchLimit limit set to %llu.\n", val);

    if((opt = optget(opts, "PCREMaxFileSize"))->active) {
        if((ret = cl_engine_set_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, opt->numarg))) {
            logg("!cli_engine_set_num(PCREMaxFileSize) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return 1;
        }
    }
    val = cl_engine_get_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, NULL);
    logg("Limits: PCREMaxFileSize limit set to %llu.\n", val);

    if (optget(opts, "ScanArchive")->enabled) {
        logg("Archive support enabled.\n");
        options.parse |= CL_SCAN_PARSE_ARCHIVE;
    } else {
        logg("Archive support disabled.\n");
    }

    /* TODO: Remove deprecated option in a future feature release. */
    if (optget(opts, "ArchiveBlockEncrypted")->enabled) {
        if (options.parse & CL_SCAN_PARSE_ARCHIVE) {
            logg(
              "^Using deprecated option \"ArchiveBlockEncrypted\" to alert on "
              "encrypted archives _and_ documents. Please update your "
              "configuration to use replacement options \"AlertEncrypted\", or "
              "\"AlertEncryptedArchive\" and/or \"AlertEncryptedDoc\".\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
        } else {
            logg(
              "^Using deprecated option \"ArchiveBlockEncrypted\" to alert on "
              "encrypted documents. Please update your configuration to use "
              "replacement options \"AlertEncrypted\", or "
              "\"AlertEncryptedArchive\" and/or \"AlertEncryptedDoc\".\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
        }
    }

    if (optget(opts, "AlertEncrypted")->enabled) {
        if (options.parse & CL_SCAN_PARSE_ARCHIVE) {
            logg("Alerting of encrypted archives _and_ documents enabled.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
        } else {
            logg("Alerting of encrypted documents enabled.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
        }
    }

    if (optget(opts, "AlertEncryptedArchive")->enabled) {
        if (options.parse & CL_SCAN_PARSE_ARCHIVE) {
            logg("Alerting of encrypted archives _and_ documents enabled.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
        } else {
            logg("^Encrypted archive alerting requested, but archive support "
                 "is disabled!\n");
        }
    }

    if (optget(opts, "AlertEncryptedDoc")->enabled) {
        logg("Alerting of encrypted documents enabled.\n");
        options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
    }

    /* TODO: Remove deprecated option in a future feature release. */
    if (optget(opts, "BlockMax")->enabled) {
        logg("^Using deprecated option \"BlockMax\" to enable heuristic alerts "
             "when scans exceed set maximums. Please update your configuration "
             "to use replacement option \"AlertExceedsMax\".\n");
        options.heuristic |= CL_SCAN_HEURISTIC_EXCEEDS_MAX;
    } else if (optget(opts, "AlertExceedsMax")->enabled) {
        logg("Heuristic alerting enabled for scans that exceed set maximums.\n");
        options.heuristic |= CL_SCAN_HEURISTIC_EXCEEDS_MAX;
    } else {
        logg("AlertExceedsMax heuristic detection disabled.\n");
    }

    /* TODO: Remove deprecated option in a future feature release. */
    if (!optget(opts, "AlgorithmicDetection")->enabled) {
        logg("^Using deprecated option \"AlgorithmicDetection\" to disable "
             "heuristic alerts. Please update your configuration to use "
             "replacement option \"HeuristicAlerts\".\n");
    } else if (!optget(opts, "HeuristicAlerts")->enabled) {
        logg("Heuristic alerts disabled.\n");
	} else {
		logg("Heuristic alerts enabled.\n");
		options.general |= CL_SCAN_GENERAL_HEURISTICS;
    }

    if(optget(opts, "ScanPE")->enabled) {
	logg("Portable Executable support enabled.\n");
	options.parse |= CL_SCAN_PARSE_PE;
    } else {
	logg("Portable Executable support disabled.\n");
    }

    if(optget(opts, "ScanELF")->enabled) {
	logg("ELF support enabled.\n");
	options.parse |= CL_SCAN_PARSE_ELF;
    } else {
	logg("ELF support disabled.\n");
    }

	/* TODO: Remove deprecated option in a future feature release */
    if (optget(opts, "ScanPE")->enabled || optget(opts, "ScanELF")->enabled) {
        if ((optget(opts, "DetectBrokenExecutables")->enabled) ||
			(optget(opts, "AlertBrokenExecutables")->enabled)) {
            logg("Alerting on broken executables enabled.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_BROKEN;
        }
    }

    if(optget(opts, "ScanMail")->enabled) {
	logg("Mail files support enabled.\n");
	options.parse |= CL_SCAN_PARSE_MAIL;

	if(optget(opts, "ScanPartialMessages")->enabled) {
	    logg("Mail: RFC1341 handling enabled.\n");
	    options.mail |= CL_SCAN_MAIL_PARTIAL_MESSAGE;
	}

    } else {
	logg("Mail files support disabled.\n");
    }

    if (optget(opts, "ScanOLE2")->enabled) {
        logg("OLE2 support enabled.\n");
        options.parse |= CL_SCAN_PARSE_OLE2;

		/* TODO: Remove deprecated option in a future feature release */
        if ((optget(opts, "OLE2BlockMacros")->enabled) ||
        	(optget(opts, "AlertOLE2Macros")->enabled)) {
            logg("OLE2: Alerting on all VBA macros.\n");
            options.heuristic |= CL_SCAN_HEURISTIC_MACROS;
        }
    } else {
        logg("OLE2 support disabled.\n");
    }

    if(optget(opts, "ScanPDF")->enabled) {
	logg("PDF support enabled.\n");
	options.parse |= CL_SCAN_PARSE_PDF;
    } else {
	logg("PDF support disabled.\n");
    }

    if(optget(opts, "ScanSWF")->enabled) {
	logg("SWF support enabled.\n");
	options.parse |= CL_SCAN_PARSE_SWF;
    } else {
	logg("SWF support disabled.\n");
    }

    if(optget(opts, "ScanHTML")->enabled) {
	logg("HTML support enabled.\n");
	options.parse |= CL_SCAN_PARSE_HTML;
    } else {
	logg("HTML support disabled.\n");
    }

    if(optget(opts, "ScanXMLDOCS")->enabled) {
	logg("XMLDOCS support enabled.\n");
	options.parse |= CL_SCAN_PARSE_XMLDOCS;
    } else {
	logg("XMLDOCS support disabled.\n");
    }

    if(optget(opts, "ScanHWP3")->enabled) {
	logg("HWP3 support enabled.\n");
	options.parse |= CL_SCAN_PARSE_HWP3;
    } else {
	logg("HWP3 support disabled.\n");
    }

    if (optget(opts, "PhishingScanURLs")->enabled) {
		/* TODO: Remove deprecated option in a future feature release */
        if ((optget(opts, "PhishingAlwaysBlockCloak")->enabled) ||
            (optget(opts, "AlertPhishingCloak")->enabled)) {
            options.heuristic |= CL_SCAN_HEURISTIC_PHISHING_CLOAK;
            logg("Phishing: Always checking for cloaked urls\n");
        }
		/* TODO: Remove deprecated option in a future feature release */
        if ((optget(opts, "PhishingAlwaysBlockSSLMismatch")->enabled) ||
            (optget(opts, "AlertPhishingSSLMismatch")->enabled)) {
            options.heuristic |= CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH;
            logg("Phishing: Always checking for ssl mismatches\n");
        }
    }

	/* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts,"PartitionIntersection")->enabled) ||
		(optget(opts,"AlertPartitionIntersection")->enabled)) {
        options.heuristic |= CL_SCAN_HEURISTIC_PARTITION_INTXN;
        logg("Raw DMG: Alert on partitions intersections\n");
    }

    if(optget(opts,"HeuristicScanPrecedence")->enabled) {
	    options.general |= CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;
	    logg("Heuristic: precedence enabled\n");
    }

    if(optget(opts, "StructuredDataDetection")->enabled) {
        options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED;

	if((opt = optget(opts, "StructuredMinCreditCardCount"))->enabled) {
	    if((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_CC_COUNT, opt->numarg))) {
		logg("!cl_engine_set_num(CL_ENGINE_MIN_CC_COUNT) failed: %s\n", cl_strerror(ret));
		cl_engine_free(engine);
		return 1;
	    }
	}
	val = cl_engine_get_num(engine, CL_ENGINE_MIN_CC_COUNT, NULL);
	logg("Structured: Minimum Credit Card Number Count set to %u\n", (unsigned int) val);

	if((opt = optget(opts, "StructuredMinSSNCount"))->enabled) {
	    if((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_SSN_COUNT, opt->numarg))) {
		logg("!cl_engine_set_num(CL_ENGINE_MIN_SSN_COUNT) failed: %s\n", cl_strerror(ret));
		cl_engine_free(engine);
		return 1;
	    }
	}
	val = cl_engine_get_num(engine, CL_ENGINE_MIN_SSN_COUNT, NULL);
        logg("Structured: Minimum Social Security Number Count set to %u\n", (unsigned int) val);

        if(optget(opts, "StructuredSSNFormatNormal")->enabled)
            options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL;

        if(optget(opts, "StructuredSSNFormatStripped")->enabled)
	    options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED;
    }

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if(optget(opts, "DevCollectHashes")->enabled)
	options.dev |= CL_SCAN_DEV_COLLECT_SHA;
#endif

    selfchk = optget(opts, "SelfCheck")->numarg;
    if(!selfchk) {
	logg("Self checking disabled.\n");
    } else {
	logg("Self checking every %u seconds.\n", selfchk);
    }

    /* save the PID */
    mainpid = getpid();
    if((opt = optget(opts, "PidFile"))->enabled) {
	    FILE *fd;
	old_umask = umask(0002);
	if((fd = fopen(opt->strarg, "w")) == NULL) {
	    logg("!Can't save PID in file %s\n", opt->strarg);
	} else {
	    if (fprintf(fd, "%u\n", (unsigned int) mainpid)<0) {
	    	logg("!Can't save PID in file %s\n", opt->strarg);
	    }
	    fclose(fd);
	}
	umask(old_umask);
    }

    logg("*Listening daemon: PID: %u\n", (unsigned int) mainpid);
    max_threads = optget(opts, "MaxThreads")->numarg;
    max_queue = optget(opts, "MaxQueue")->numarg;
    acceptdata.commandtimeout = optget(opts, "CommandReadTimeout")->numarg;
    readtimeout = optget(opts, "ReadTimeout")->numarg;

#if !defined(_WIN32) && defined(RLIMIT_NOFILE)
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
	/* don't warn if default value is too high, silently fix it */
	unsigned maxrec;
	int max_max_queue;
	unsigned warn = optget(opts, "MaxQueue")->active;
	const unsigned clamdfiles = 6;
#ifdef C_SOLARIS
	int solaris_has_extended_stdio = 0;
#endif
	/* Condition to not run out of file descriptors:
	 * MaxThreads * MaxRecursion + (MaxQueue - MaxThreads) + CLAMDFILES < RLIMIT_NOFILE
	 * CLAMDFILES is 6: 3 standard FD + logfile + 2 FD for reloading the DB
	 * */
#ifdef C_SOLARIS

	/*
	**  If compiling 64bit, then set the solaris_has_extended_stdio
	**  flag
	*/

#if defined(_LP64)
	solaris_has_extended_stdio++;
#endif

#ifdef HAVE_ENABLE_EXTENDED_FILE_STDIO
	if (enable_extended_FILE_stdio(-1, -1) == -1) {
	    logg("^Unable to set extended FILE stdio, clamd will be limited to max 256 open files\n");
	    rlim.rlim_cur = rlim.rlim_cur > 255 ? 255 : rlim.rlim_cur;
	}
	else
	{
	   solaris_has_extended_stdio++;
	}

#elif !defined(_LP64)
	if (solaris_has_extended_stdio && rlim.rlim_cur > 255) {
	    rlim.rlim_cur = 255;
	    logg("^Solaris only supports 256 open files for 32-bit processes, you need at least Solaris 10u4, or compile as 64-bit to support more!\n");
	}
#endif

	/*
	**  If compiling in 64bit or the file stdio has been extended,
	**  then increase the soft limit for the number of open files
	**  as the default is usually 256
	*/

	if (solaris_has_extended_stdio)
	{
	   rlim_t saved_soft_limit = rlim.rlim_cur;

	   rlim.rlim_cur = rlim.rlim_max;
	   if (setrlimit (RLIMIT_NOFILE, &rlim) < 0)
	   {
	      logg("!setrlimit() for RLIMIT_NOFILE to %lu failed: %s\n",
		   (unsigned long) rlim.rlim_cur, strerror (errno));
	      rlim.rlim_cur = saved_soft_limit;
	   }
	} /*  If 64bit or has extended stdio  */

#endif
	opt = optget(opts,"MaxRecursion");
	maxrec = opt->numarg;
	max_max_queue = rlim.rlim_cur - maxrec * max_threads - clamdfiles + max_threads;
	if (max_queue < max_threads) {
	    max_queue = max_threads;
	    if (warn)
		logg("^MaxQueue value too low, increasing to: %d\n", max_queue);
	}
	if (max_max_queue < max_threads) {
	    logg("^MaxThreads * MaxRecursion is too high: %d, open file descriptor limit is: %lu\n",
		 maxrec*max_threads, (unsigned long)rlim.rlim_cur);
	    max_max_queue = max_threads;
	}
	if (max_queue > max_max_queue) {
	    max_queue = max_max_queue;
	    if (warn)
		logg("^MaxQueue value too high, lowering to: %d\n", max_queue);
	} else if (max_queue < 2*max_threads && max_queue < max_max_queue) {
	    max_queue = 2*max_threads;
	    if (max_queue > max_max_queue)
		max_queue = max_max_queue;
	    /* always warn here */
	    logg("^MaxQueue is lower than twice MaxThreads, increasing to: %d\n", max_queue);
	}
    }
#endif
    logg("*MaxQueue set to: %d\n", max_queue);
    acceptdata.max_queue = max_queue;

    if(optget(opts, "ScanOnAccess")->enabled)

#if defined(FANOTIFY) || defined(CLAMAUTH)
    {
		int thread_started = 1;
        do {
			if(pthread_attr_init(&fan_attr)) break;
			pthread_attr_setdetachstate(&fan_attr, PTHREAD_CREATE_JOINABLE);

			/* Allocate memory for arguments. Thread is responsible for freeing it. */
			if (!(tharg = (struct thrarg *) calloc(sizeof(struct thrarg), 1))) break;
			if (!(tharg->options = (struct cl_scan_options *) calloc(sizeof(struct cl_scan_options), 1))) break;

			(void) memcpy(tharg->options, &options, sizeof(struct cl_scan_options));
			tharg->opts = opts;
			tharg->engine = engine;

			thread_started = pthread_create(&fan_pid, &fan_attr, onas_fan_th, tharg);
		} while(0);

		if (0 != thread_started) {
			/* Failed to create thread. Free anything we may have allocated. */
			logg("!Unable to start on-access scan.\n");
			if (NULL != tharg) {
				if (NULL != tharg->options) {
					free(tharg->options);
					tharg->options = NULL;
				}
				free(tharg);
				tharg = NULL;
			}
		}
    }
#else
	logg("!On-access scan is not available\n");
#endif


#ifndef	_WIN32
    /* set up signal handling */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGTERM);
    sigdelset(&sigset, SIGSEGV);
    sigdelset(&sigset, SIGHUP);
    sigdelset(&sigset, SIGPIPE);
    sigdelset(&sigset, SIGUSR2);
    /* The behavior of a process is undefined after it ignores a
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    sigdelset(&sigset, SIGTSTP);
    sigdelset(&sigset, SIGCONT);
    sigprocmask(SIG_SETMASK, &sigset, NULL);

    /* SIGINT, SIGTERM, SIGSEGV */
    sigact.sa_handler = sighandler_th;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGINT);
    sigaddset(&sigact.sa_mask, SIGTERM);
    sigaddset(&sigact.sa_mask, SIGHUP);
    sigaddset(&sigact.sa_mask, SIGPIPE);
    sigaddset(&sigact.sa_mask, SIGUSR2);
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL);
#endif

    idletimeout = optget(opts, "IdleTimeout")->numarg;

    for (i=0;i < nsockets;i++)
	if (fds_add(&acceptdata.fds, socketds[i], 1, 0) == -1) {
	    logg("!fds_add failed\n");
	    cl_engine_free(engine);
	    return 1;
	}
#ifdef _WIN32
	event_wake_accept = CreateEvent(NULL, TRUE, FALSE, NULL);
	event_wake_recv = CreateEvent(NULL, TRUE, FALSE, NULL);
#else
    if (pipe(acceptdata.syncpipe_wake_recv) == -1 ||
	(pipe(acceptdata.syncpipe_wake_accept) == -1)) {

	logg("!pipe failed\n");
	exit(-1);
    }
    syncpipe_wake_recv_w = acceptdata.syncpipe_wake_recv[1];

    if (fds_add(fds, acceptdata.syncpipe_wake_recv[0], 1, 0) == -1 ||
	fds_add(&acceptdata.fds, acceptdata.syncpipe_wake_accept[0], 1, 0)) {
	logg("!failed to add pipe fd\n");
	exit(-1);
    }
#endif

    if ((thr_pool = thrmgr_new(max_threads, idletimeout, max_queue, scanner_thread)) == NULL) {
	logg("!thrmgr_new failed\n");
	exit(-1);
    }

    if (pthread_create(&accept_th, NULL, acceptloop_th, &acceptdata)) {
	logg("!pthread_create failed\n");
	exit(-1);
    }

    time(&start_time);
    for(;;) {
	int new_sd;

	/* Block waiting for connection on any of the sockets */
	pthread_mutex_lock(fds->buf_mutex);
	fds_cleanup(fds);
	/* signal that we can accept more connections */
	if (fds->nfds <= (unsigned)max_queue)
	    pthread_cond_signal(&acceptdata.cond_nfds);
	new_sd = fds_poll_recv(fds, selfchk ? (int)selfchk : -1, 1, event_wake_recv);
#ifdef _WIN32
	ResetEvent(event_wake_recv);
#else
	if (!fds->nfds) {
	    /* at least the dummy/sync pipe should have remained */
	    logg("!All recv() descriptors gone: fatal\n");
	    pthread_mutex_lock(&exit_mutex);
	    progexit = 1;
	    pthread_mutex_unlock(&exit_mutex);
	    pthread_mutex_unlock(fds->buf_mutex);
	    break;
	}
#endif
	if (new_sd == -1 && errno != EINTR) {
	    logg("!Failed to poll sockets, fatal\n");
	    pthread_mutex_lock(&exit_mutex);
	    progexit = 1;
	    pthread_mutex_unlock(&exit_mutex);
	}


	if(fds->nfds) i = (rr_last + 1) % fds->nfds;
	for (j = 0;  j < fds->nfds && new_sd >= 0; j++, i = (i+1) % fds->nfds) {
	    size_t pos = 0;
	    int error = 0;
	    struct fd_buf *buf = &fds->buf[i];
	    if (!buf->got_newdata)
		continue;

#ifndef _WIN32
	    if (buf->fd == acceptdata.syncpipe_wake_recv[0]) {
		/* dummy sync pipe, just to wake us */
		if (read(buf->fd, buff, sizeof(buff)) < 0) {
		    logg("^Syncpipe read failed\n");
		}
		continue;
	    }
#endif
	    if (buf->got_newdata == -1) {
		if (buf->mode == MODE_WAITREPLY) {
		    logg("$mode WAIT_REPLY -> closed\n");
		    buf->fd = -1;
		    thrmgr_group_terminate(buf->group);
		    thrmgr_group_finished(buf->group, EXIT_ERROR);
		    continue;
		} else {
		    logg("$client read error or EOF on read\n");
		    error = 1;
		}
	    }

	    if (buf->fd != -1 && buf->got_newdata == -2) {
		logg("$Client read timed out\n");
		mdprintf(buf->fd, "COMMAND READ TIMED OUT\n");
		error = 1;
	    }

	    rr_last = i;
	    if (buf->mode == MODE_WAITANCILL) {
		buf->mode = MODE_COMMAND;
		logg("$mode -> MODE_COMMAND\n");
	    }
	    while (!error && buf->fd != -1 && buf->buffer && pos < buf->off &&
		   buf->mode != MODE_WAITANCILL) {
		client_conn_t conn;
		const char *cmd = NULL;
		int rc;
		/* New data available to read on socket. */

		memset(&conn, 0, sizeof(conn));
		conn.scanfd = buf->recvfd;
		buf->recvfd = -1;
		conn.sd = buf->fd;
		conn.options = &options;
		conn.opts = opts;
		conn.thrpool = thr_pool;
		conn.engine = engine;
		conn.group = buf->group;
		conn.id = buf->id;
		conn.quota = buf->quota;
		conn.filename = buf->dumpname;
		conn.mode = buf->mode;
		conn.term = buf->term;

		/* Parse & dispatch command */
		cmd = parse_dispatch_cmd(&conn, buf, &pos, &error, opts, readtimeout);

		if (conn.mode == MODE_COMMAND && !cmd)
		    break;
		if (!error) {
		    if (buf->mode == MODE_WAITREPLY && buf->off) {
			/* Client is not supposed to send anything more */
			logg("^Client sent garbage after last command: %lu bytes\n", (unsigned long)buf->off);
			buf->buffer[buf->off] = '\0';
			logg("$Garbage: %s\n", buf->buffer);
			error = 1;
		    } else if (buf->mode == MODE_STREAM) {
			rc = handle_stream(&conn, buf, opts, &error, &pos, readtimeout);
			if (rc == -1)
			    break;
			else
			    continue;
		    }
		}
		if (error && error != CL_ETIMEOUT) {
		    conn_reply_error(&conn, "Error processing command.");
		}
	    }
	    if (error) {
		if (buf->dumpfd != -1) {
		    close(buf->dumpfd);
		    if (buf->dumpname) {
			cli_unlink(buf->dumpname);
			free(buf->dumpname);
		    }
		    buf->dumpfd = -1;
		}
		thrmgr_group_terminate(buf->group);
		if (thrmgr_group_finished(buf->group, EXIT_ERROR)) {
		    if (buf->fd < 0) {
			logg("$Skipping shutdown of bad socket after error (FD %d)\n", buf->fd);
		    }
		    else {
			logg("$Shutting down socket after error (FD %d)\n", buf->fd);
			shutdown(buf->fd, 2);
			closesocket(buf->fd);
		    }
		} else
		    logg("$Socket not shut down due to active tasks\n");
		buf->fd = -1;
	    }
	}
	pthread_mutex_unlock(fds->buf_mutex);

	/* handle progexit */
	pthread_mutex_lock(&exit_mutex);
	if (progexit) {
	    pthread_mutex_unlock(&exit_mutex);
	    pthread_mutex_lock(fds->buf_mutex);
        if (sd_listen_fds(0) == 0)
        {
            /* only close the sockets, when not using systemd socket activation */
            for (i=0;i < fds->nfds; i++)
            {
                if (fds->buf[i].fd == -1)
                    continue;
                thrmgr_group_terminate(fds->buf[i].group);
                if (thrmgr_group_finished(fds->buf[i].group, EXIT_ERROR))
                {
                    logg("$Shutdown closed fd %d\n", fds->buf[i].fd);
                    shutdown(fds->buf[i].fd, 2);
                    closesocket(fds->buf[i].fd);
                    fds->buf[i].fd = -1;
                }
            }
	    }
	    pthread_mutex_unlock(fds->buf_mutex);
	    break;
	}
	pthread_mutex_unlock(&exit_mutex);

	/* SIGHUP */
	if (sighup) {
	    logg("SIGHUP caught: re-opening log file.\n");
	    logg_close();
	    sighup = 0;
	    if(!logg_file && (opt = optget(opts, "LogFile"))->enabled)
		logg_file = opt->strarg;
	}

	/* SelfCheck */
	if(selfchk) {
	    time(&current_time);
	    if((current_time - start_time) >= (time_t)selfchk) {
		if(reload_db(engine, dboptions, opts, TRUE, &ret)) {
		    pthread_mutex_lock(&reload_mutex);
		    reload = 1;
		    pthread_mutex_unlock(&reload_mutex);
		}
		time(&start_time);
	    }
	}

	/* DB reload */
	pthread_mutex_lock(&reload_mutex);
	if(reload) {
	    pthread_mutex_unlock(&reload_mutex);

	    engine = reload_db(engine, dboptions, opts, FALSE, &ret);
	    if(ret) {
		logg("Terminating because of a fatal error.\n");
		if(new_sd >= 0)
		    closesocket(new_sd);
		break;
	    }

	    pthread_mutex_lock(&reload_mutex);
	    reload = 0;
	    time(&reloaded_time);
	    pthread_mutex_unlock(&reload_mutex);

#if defined(FANOTIFY) || defined(CLAMAUTH)
	    if(optget(opts, "ScanOnAccess")->enabled && tharg) {
		tharg->engine = engine;
	    }
#endif
	    time(&start_time);
	} else {
	    pthread_mutex_unlock(&reload_mutex);
	}
    }

    pthread_mutex_lock(&exit_mutex);
    progexit = 1;
    pthread_mutex_unlock(&exit_mutex);
#ifdef _WIN32
    SetEvent(event_wake_accept);
#else
    if (write(acceptdata.syncpipe_wake_accept[1], "", 1) < 0) {
	logg("^Write to syncpipe failed\n");
    }
#endif
    /* Destroy the thread manager.
     * This waits for all current tasks to end
     */
    logg("*Waiting for all threads to finish\n");
    thrmgr_destroy(thr_pool);
#if defined(FANOTIFY) || defined(CLAMAUTH)
    if(optget(opts, "ScanOnAccess")->enabled && tharg) {
	logg("Stopping on-access scan\n");
	pthread_mutex_lock(&logg_mutex);
	pthread_kill(fan_pid, SIGUSR1);
	pthread_mutex_unlock(&logg_mutex);
	pthread_join(fan_pid, NULL);
    free(tharg);
    }
#endif
    if(engine) {
	thrmgr_setactiveengine(NULL);
	cl_engine_free(engine);
    }

    pthread_join(accept_th, NULL);
    fds_free(fds);
    pthread_mutex_destroy(fds->buf_mutex);
    pthread_cond_destroy(&acceptdata.cond_nfds);
#ifdef _WIN32
    CloseHandle(event_wake_accept);
    CloseHandle(event_wake_recv);
#else
    close(acceptdata.syncpipe_wake_accept[1]);
    close(acceptdata.syncpipe_wake_recv[1]);
#endif
    if(dbstat.entries)
	cl_statfree(&dbstat);
    if (sd_listen_fds(0) == 0)
    {
        /* only close the sockets, when not using systemd socket activation */
        logg("*Shutting down the main socket%s.\n", (nsockets > 1) ? "s" : "");
        for (i = 0; i < nsockets; i++)
            shutdown(socketds[i], 2);
    }

    if((opt = optget(opts, "PidFile"))->enabled) {
	if(unlink(opt->strarg) == -1)
	    logg("!Can't unlink the pid file %s\n", opt->strarg);
	else
	    logg("Pid file removed.\n");
    }

    time(&current_time);
    logg("--- Stopped at %s", cli_ctime(&current_time, timestr, sizeof(timestr)));

    return ret;
}
