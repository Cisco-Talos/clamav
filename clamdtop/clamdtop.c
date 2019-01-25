/*
 *  ClamdTOP
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#define _GNU_SOURCE
#define __EXTENSIONS
#define GCC_PRINTF
#define GCC_SCANF

#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include CURSES_INCLUDE
#include <time.h>
#include <ctype.h>
#include <signal.h>
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
/* this is not correct, perhaps winsock errors are not mapped on errno */
#define herror perror
#else
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <sys/time.h>
#include <assert.h>
#include <errno.h>

#include "libclamav/clamav.h"
#include "shared/optparser.h"
#include "shared/misc.h"

/* Types, prototypes and globals*/
typedef struct connection {
	int sd;
	char *remote;
	int tcp;
	struct timeval tv_conn;
	char *version;
	int line;
} conn_t;

struct global_stats {
	struct task *tasks;
	ssize_t n;
	struct stats *all_stats;
	size_t num_clamd;
	conn_t *conn;
};

struct stats {
	const char *remote;
	char *engine_version;
	char *db_version;
	struct tm db_time;
	const char *version;
	int stats_unsupp;
	uint8_t conn_hr, conn_min, conn_sec;
	/* threads - primary */
	unsigned prim_live, prim_idle, prim_max;
	/* threads - sum */
	unsigned live, idle, max;
	/* queue */
	unsigned biggest_queue, current_q;
	double mem;/* in megabytes */
	unsigned long lheapu, lmmapu, ltotalu, ltotalf, lreleasable, lpoolu, lpoolt;
	unsigned pools_cnt;
};

static void cleanup(void);
static int send_string_noreconn(conn_t *conn, const char *cmd);
static void send_string(conn_t *conn, const char *cmd);
static int read_version(conn_t *conn);
char *get_ip(const char *ip);
char *get_port(const char *ip);
char *make_ip(const char *host, const char *port);

enum exit_reason {
        FAIL_CMDLINE=1,
	FAIL_INITIAL_CONN,
	OUT_OF_MEMORY,
	RECONNECT_FAIL,
	SIGINT_REASON
};

static void exit_program(enum exit_reason reason, const char *func, unsigned line);
#if __GNUC__ >= 3
#define EXIT_PROGRAM(r) exit_program(r, __PRETTY_FUNCTION__, __LINE__);
#else
#define EXIT_PROGRAM(r) exit_program(r, "<unknown>", __LINE__);
#endif
#define OOM_CHECK(p) do { if (!p) EXIT_PROGRAM(OUT_OF_MEMORY); } while (0)


static struct global_stats global;
static int curses_inited = 1;
static int maxystats=0;
static int detail_selected = -1;

static int detail_exists(void)
{
	return global.num_clamd != 1;
}

static int detail_is_selected(int idx)
{
	if (!detail_exists()) {
		assert(idx == 0);
		return 1;
	}
	return idx == detail_selected;
}


/* ---------------------- NCurses routines -----------------*/
enum colors {
	header_color=1,
	version_color,
	error_color,
	value_color,
	descr_color,
	selected_color,
	queue_header_color,
	activ_color,
	dim_color,
	red_color,
};

#define UPDATE_INTERVAL 2
#define MIN_INTERVAL 1

/* the default color of the terminal in ncurses */
#define DEFAULT_COLOR -1

#define VALUE_ATTR A_BOLD | COLOR_PAIR(value_color)
#define DESCR_ATTR COLOR_PAIR(descr_color)
#define ERROR_ATTR A_BOLD | COLOR_PAIR(error_color)

static WINDOW *header_window = NULL;
static WINDOW *stats_head_window = NULL;
static WINDOW *stats_window = NULL;
static WINDOW *status_bar_window = NULL;
static WINDOW *mem_window = NULL;

static const char *status_bar_keys[10];
static unsigned maxy=0, maxx=0;
static char *queue_header = NULL;
static char *clamd_header = NULL;

#define CMDHEAD " COMMAND        QUEUEDSINCE   FILE"
#define CMDHEAD2 " # COMMAND     QUEUEDSINCE   FILE"

/*
 * CLAMD - which local/remote clamd this is
 * CONNTIM - since when we are connected (TODO: zeroed at reconnect)
 * QUEUE   - no of items in queue (total)
 * MAXQUEUE - max no of items in queue observed
 * LIVETHR - sum of live threads
 * IDLETHR - sum of idle threads
 */
#define SUMHEAD "NO CONNTIME LIV IDL QUEUE  MAXQ   MEM HOST           ENGINE DBVER DBTIME"

static void resize(void)
{
	char *p;
	unsigned new_maxy, new_maxx;
	getmaxyx(stdscr, new_maxy, new_maxx);
	if(new_maxy == maxy && new_maxx == maxx)
		return;
	maxx = new_maxx;
	maxy = new_maxy;
	free(queue_header);
	free(clamd_header);
	queue_header = malloc(maxx + 1);
	OOM_CHECK(queue_header);
	clamd_header = malloc(maxx + 1);
	OOM_CHECK(clamd_header);
	assert(clamd_header && queue_header);
	strncpy(queue_header, global.num_clamd>1 ? CMDHEAD2 : CMDHEAD, maxx);
	strncpy(clamd_header, SUMHEAD, maxx);
	queue_header[maxx] = '\0';
	clamd_header[maxx] = '\0';
	p = queue_header + strlen(queue_header);
	while(p < queue_header+maxx)
		*p++ = ' ';
	p = clamd_header + strlen(clamd_header);
	while(p < clamd_header+maxx)
		*p++ = ' ';
}

static void rm_windows(void)
{
	if(header_window) {
		delwin(header_window);
		header_window = NULL;
	}
	if(mem_window) {
		delwin(mem_window);
		mem_window = NULL;
	}
	if(stats_window) {
		delwin(stats_window);
		stats_window = NULL;
	}
	if(stats_head_window) {
		delwin(stats_head_window);
		stats_head_window = NULL;
	}
	if(status_bar_window) {
		delwin(status_bar_window);
		status_bar_window = NULL;
	}
}


static void init_windows(int num_clamd)
{
	resize();

	rm_windows();
	/* non-overlapping windows */
	header_window = subwin(stdscr, 1, maxx, 0, 0);
	stats_head_window = subwin(stdscr, num_clamd+1, maxx, 1, 0);
	maxystats = maxy-num_clamd-3;
	stats_window = subwin(stdscr, maxystats, maxx, num_clamd+2, 0);
	status_bar_window = subwin(stdscr, 1, maxx, maxy-1, 0);
	/* memwindow overlaps, used only in details mode */
	mem_window = derwin(stats_window, 6, 41, 1, maxx-41);
	touchwin(stdscr);
	werase(stdscr);
	refresh();
	memset(status_bar_keys, 0, sizeof(status_bar_keys));
	status_bar_keys[0] = "H - help";
	status_bar_keys[1] = "Q - quit";
	status_bar_keys[2] = "R - reset maximums";
	if (num_clamd > 1) {
		status_bar_keys[3] = "^ - previous clamd";
		status_bar_keys[4] = "v - next clamd";
	}
}

static void init_ncurses(int num_clamd, int use_default)
{
	int default_bg = use_default ? DEFAULT_COLOR : COLOR_BLACK;
	int default_fg = use_default ? DEFAULT_COLOR : COLOR_WHITE;
	initscr();
	curses_inited = 1;

	start_color();
	keypad(stdscr, TRUE);	/* enable keyboard mapping */
	nonl();			/* tell curses not to do NL->CR/NL on output */
	halfdelay(UPDATE_INTERVAL*10); /* timeout of 2s when waiting for input*/
	noecho();		/* dont echo input */
	curs_set(0);		/* turn off cursor */
	if (use_default)
	    use_default_colors();

	init_pair(header_color, COLOR_BLACK, COLOR_WHITE);
	init_pair(version_color, default_fg, default_bg);
	init_pair(error_color, COLOR_WHITE, COLOR_RED);
	init_pair(value_color, COLOR_GREEN, default_bg);
	init_pair(descr_color, COLOR_CYAN, default_bg);
	init_pair(selected_color, COLOR_BLACK, COLOR_CYAN);
	init_pair(queue_header_color, COLOR_BLACK, COLOR_GREEN);
	init_pair(activ_color, COLOR_MAGENTA, default_bg);
	init_pair(dim_color, COLOR_GREEN, default_bg);
	init_pair(red_color, COLOR_RED, default_bg);

	init_windows(num_clamd);
}

static void win_start(WINDOW *win, enum colors col)
{
	wattrset(win, COLOR_PAIR(col));
	wbkgd(win, COLOR_PAIR(col));
	werase(win);
}


static void  print_colored(WINDOW *win, const char *p)
{
	while(*p) {
		wattron(win, DESCR_ATTR);
		while(*p && !isdigit(*p))
			waddch(win, *p++);
		wattroff(win, DESCR_ATTR);
		wattron(win, VALUE_ATTR);
		while(*p && isdigit(*p))
			waddch(win, *p++);
		wattroff(win, VALUE_ATTR);
	}
}

static void header(void)
{
	size_t i, x=0;
	time_t t;


	win_start(header_window, header_color);
	mvwprintw(header_window, 0, 0, "  ClamdTOP version %s   ", get_version());
	time(&t);
	wprintw(header_window, "%s", ctime(&t));
	wrefresh(header_window);

/*	win_start(version_window, version_color);
	mvwprintw(version_window, 0, 0, "Connected to: ");
	print_colored(version_window, clamd_version ? clamd_version : "Unknown");
	wrefresh(version_window);*/

	werase(status_bar_window);
	for(i=0;i<sizeof(status_bar_keys)/sizeof(status_bar_keys[0]);i++) {
		const char *s = status_bar_keys[i];
		if(!s)
			continue;
		wattron(status_bar_window, A_REVERSE);
		if (s[0] == '^') {
			mvwaddch(status_bar_window, 0, x, ACS_UARROW);
			s++;
			x++;
		} else if (s[0] == 'v') {
			mvwaddch(status_bar_window, 0, x, ACS_DARROW);
			s++;
			x++;
		}
		mvwprintw(status_bar_window, 0, x,  "%s",s);
		wattroff(status_bar_window, A_REVERSE);
		x += strlen(status_bar_keys[i]) + 1;
	}
	wrefresh(status_bar_window);
}

static void show_bar(WINDOW *win, size_t i, unsigned live, unsigned idle,
		unsigned max, int blink)
{
	int y,x,z = 0;
	unsigned len  = 39;
	unsigned start = 1;
	unsigned activ = max ? ((live-idle)*(len - start - 2) + (max/2)) / max : 0;
	unsigned dim   = max ? idle*(len - start - 2) / max : 0;
	unsigned rem = len - activ - dim - start-2;
        
	assert(activ + 2 < len && activ+dim + 2 < len && activ+dim+rem + 2 < len && "Invalid values");
	mvwaddch(win, i, start, '[' | A_BOLD);
	wattron(win, A_BOLD | COLOR_PAIR(activ_color));
	for(i=0;i<activ;i++)
		waddch(win, '|');
	wattroff(win, A_BOLD | COLOR_PAIR(activ_color));
	wattron(win, A_DIM | COLOR_PAIR(dim_color));
	for(i=0;i<dim;i++)
		waddch(win, '|');
	wattroff(win, A_DIM | COLOR_PAIR(dim_color));
	for(i=0;i<rem;i++)
		waddch(win, ' ');
	waddch(win, ']' | A_BOLD);
	if(blink) {
		getyx(win, y, x);
		if ((x < 0) || (y < 0)) {
			return; /* if getyx() failed, nevermind the blinking */
		}
		if (x >= 2) {
			z = x - 2;
		}
		mvwaddch(win, y, z, '>' | A_BLINK | COLOR_PAIR(red_color));
		move(y, z);
	}
}

/* --------------------- Error handling ---------------------*/
static int normal_exit = 0;
static const char *exit_reason = NULL;
static const char *exit_func = NULL;
static unsigned exit_line = 0;

static void cleanup(void)
{
	unsigned i;
	if (curses_inited) {
		if (status_bar_window) {
			werase(status_bar_window);
			wrefresh(status_bar_window);
		}
		rm_windows();
		endwin();
	}
	curses_inited = 0;
	for (i=0;i<global.num_clamd;i++) {
		if (global.conn[i].sd && global.conn[i].sd != -1) {
			send_string_noreconn(&global.conn[i], "nEND\n");
			close(global.conn[i].sd);
		}
		free(global.conn[i].version);
		free(global.conn[i].remote);
	}
	free(global.all_stats);
	free(global.conn);
	free(queue_header);
	free(clamd_header);
	if(!normal_exit) {
		fprintf(stderr, "Abnormal program termination");
	        if (exit_reason) fprintf(stderr, ": %s",exit_reason);
		if (exit_func) fprintf(stderr, " in %s", exit_func);
		if (exit_line) fprintf(stderr, " at line %u", exit_line);
		fputc('\n',stderr);
	}
}

#ifdef __GNUC__
#define __noreturn __attribute__((noreturn))
#else
#define __noreturn
#endif

static void __noreturn exit_program(enum exit_reason reason, const char *func, unsigned line)
{
	switch(reason) {
		case FAIL_CMDLINE:
			exit_reason = "Invalid command-line arguments";
			break;
		case FAIL_INITIAL_CONN:
			exit_reason = "Unable to connect to all clamds";
			break;
		case OUT_OF_MEMORY:
			exit_reason = "Out of memory";
			break;
		case RECONNECT_FAIL:
			exit_reason = "Failed to reconnect to clamd after connection was lost";
			break;
		case SIGINT_REASON:
			exit_reason = "User interrupt";
			break;
		default:
			exit_reason = "Unknown";
			break;
	}
	exit_func = func;
	exit_line = line;
	exit(reason);
}

struct task {
	char *line;
	double tim;
	int clamd_no;
};

static int tasks_compare(const void *a, const void *b)
{
	const struct task *ta = a;
	const struct task *tb = b;
	if(ta->tim < tb->tim)
		return 1;
	if(ta->tim > tb->tim)
		return -1;
	return 0;
}

/* ----------- Socket routines ----------------------- */
#ifdef __GNUC__
static void print_con_info(conn_t *conn, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#endif
static void print_con_info(conn_t *conn, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (stats_head_window) {
		char *buf = malloc(maxx);
		OOM_CHECK(buf);
		memset(buf, ' ', maxx);
		vsnprintf(buf, maxx-1, fmt, ap);
		buf[strlen(buf)] = ' ';
		buf[maxx-1] = '\0';
		wattron(stats_head_window, ERROR_ATTR);
		mvwprintw(stats_head_window, conn->line, 0, "%s", buf);
		wattroff(stats_head_window, ERROR_ATTR);
		wrefresh(stats_head_window);
		free(buf);
	} else
		vfprintf(stdout, fmt, ap);
	va_end(ap);
}

char *get_ip(const char *ip)
{
    char *dupip, *p1;
    unsigned int i;

    /*
     * Expected format of ip:
     *     1) IPv4
     *     2) IPv4:Port
     *     3) IPv6
     *     4) [IPv6]:Port
     * 
     * Use of IPv6:Port is incorrect. An IPv6 address must be enclosed in brackets.
     */

    dupip = strdup(ip);
    if (!(dupip))
        return NULL;

    if (dupip[0] == '[') {
        /* IPv6 */
        p1 = strchr(dupip, ']');
        if (!(p1)) {
            free(dupip);
            return NULL;
        }

        *p1 = '\0';

        p1 = strdup(dupip+1);
        free(dupip);
        return p1;
    }

    p1 = dupip;
    i=0;
    while ((p1 = strchr(p1, ':'))) {
        i++;
        p1++;
    }

    if (i == 0 || i > 1)
        return dupip;

    if (i == 1) {
        p1 = strchr(dupip, ':');
        *p1 = '\0';
        return dupip;
    }

    return dupip;
}

char *get_port(const char *ip)
{
    char *dupip, *p;
    unsigned int offset=0;

    dupip = get_ip(ip);
    if (!(dupip))
        return NULL;

    if (ip[0] == '[')
        offset += 2;

    p = (char *)ip + strlen(dupip) + offset;
    if (*p == ':') {
        p = strdup(p+1);
        free(dupip);
        return p;
    }

    return NULL;
}

char *make_ip(const char *host, const char *port)
{
    char *ip;
    size_t len;
    int ipv6;

    len = strlen(host) + strlen(port);

    ipv6 = (strchr(host, ':') != NULL);

    len += (ipv6 ? 4 : 3);

    ip = calloc(1, len);
    if (!(ip))
        return NULL;

    snprintf(ip, len, "%s%s%s:%s", ipv6 ? "[" : "", host, ipv6 ? "]" : "", port);

    return ip;
}

static int make_connection_real(const char *soname, conn_t *conn)
{
    int s = -1;
    struct timeval tv;
    char *port=NULL;
    char *pt = strdup(soname);
    const char *host = pt;
    struct addrinfo hints, *res=NULL, *p;
    int err;

    OOM_CHECK(pt);
    conn->tcp = 0;

#ifndef _WIN32
    if(cli_is_abspath(soname) || (access(soname, F_OK) == 0)) {
        struct sockaddr_un addr;

        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if(s < 0) {
            perror("socket");
            return -1;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, soname, sizeof(addr.sun_path));
        addr.sun_path[sizeof(addr.sun_path) - 1] = 0x0;

        print_con_info(conn, "Connecting to: %s\n", soname);
        if (connect(s, (struct sockaddr *)&addr, sizeof(addr))) {
            perror("connect");
            close(s);
            return -1;
        }

        goto end;
    }
#endif

    memset(&hints, 0x00, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    host = get_ip(soname);
    if (!(host))
        return -1;

    port = get_port(soname);

    conn->tcp=1;

    print_con_info(conn, "Looking up: %s:%s\n", host, port ? port : "3310");
    if ((err = getaddrinfo(host, (port != NULL) ? port : "3310", &hints, &res))) {
        print_con_info(conn, "Could not look up %s:%s, getaddrinfo returned: %s\n", host, port ? port : "3310", gai_strerror(err));
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        if ((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
            perror("socket");
            continue;
        }

        print_con_info(conn, "Connecting to: %s\n", soname);
        if (connect(s, p->ai_addr, p->ai_addrlen)) {
            perror("connect");
            close(s);
            continue;
        }

        break;
    }

    free(pt);

    if (res)
        freeaddrinfo(res);

    if (p == NULL)
        return -1;

end:
    if (conn->remote != soname) {
        /* when we reconnect, they are the same */
        if (conn->remote)
            free(conn->remote);

        conn->remote = make_ip(host, (port != NULL) ? port : "3310");
    }
    if (port)
        free(port);
    conn->sd = s;
    gettimeofday(&conn->tv_conn, NULL);
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(conn->sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 0;
}

static int make_connection(const char *soname, conn_t *conn)
{
    int rc;

    if ((rc = make_connection_real(soname, conn)))
        return rc;

    send_string(conn, "nIDSESSION\nnVERSION\n");
    free(conn->version);
    conn->version = NULL;
    if (!read_version(conn))
        return 0;

    /* clamd < 0.95 */
    if ((rc = make_connection_real(soname, conn)))
        return rc;

    send_string(conn, "nSESSION\nnVERSION\n");
    conn->version = NULL;
    if (!read_version(conn))
        return 0;

    return -1;
}

static void reconnect(conn_t *conn);

static int send_string_noreconn(conn_t *conn, const char *cmd)
{
	assert(cmd);
	assert(conn && conn->sd > 0);
	return send(conn->sd, cmd, strlen(cmd), 0);
}

static void send_string(conn_t *conn, const char *cmd)
{
	while(send_string_noreconn(conn, cmd) == -1) {
		reconnect(conn);
	}
}

static int tries = 0;
static void reconnect(conn_t *conn)
{
	if(++tries > 3) {
		EXIT_PROGRAM(RECONNECT_FAIL);
	}
	if (conn->sd != -1)
	    close(conn->sd);
	if (make_connection(conn->remote, conn) < 0) {
		print_con_info(conn, "Unable to reconnect to %s: %s", conn->remote, strerror(errno));
		EXIT_PROGRAM(RECONNECT_FAIL);
	}
	tries = 0;
}

static int recv_line(conn_t *conn, char *buf, size_t len)
{
	assert(len > 0);
	assert(conn);
	assert(buf);

	len--;
	if (!len || conn->sd == -1)
		return 0;
	assert(conn->sd > 0);
	while (len > 0) {
		ssize_t nread = recv(conn->sd, buf, len, MSG_PEEK);
		if (nread  <= 0) {
			print_con_info(conn, "%s: %s", conn->remote, strerror(errno));
			/* it could be a timeout, be nice and send an END */
			send_string_noreconn(conn, "nEND\n");
			close(conn->sd);
			conn->sd = -1;
			return 0;
		} else {
			char *p = memchr(buf, '\n', nread);
			if (p) {
				len = p - buf + 1;
			} else
				len = nread;
			assert(len > 0);
			assert(len <= (size_t)nread);
			nread = recv(conn->sd, buf, len, 0);
			if (nread == -1)
				reconnect(conn);
			else {
				assert(nread >0 && (size_t)nread == len);
				buf += nread;
			}
			if (p)
				break;
		}
	}
	*buf = '\0';
	return 1;
}

static void output_queue(size_t line, ssize_t max)
{
	ssize_t i, j;
	struct task *tasks = global.tasks;
	struct task *filtered_tasks = calloc(global.n, sizeof(*filtered_tasks));
	OOM_CHECK(filtered_tasks);
	for (i=0,j=0;i<global.n;i++) {
		if (detail_selected == -1 || detail_is_selected(tasks[i].clamd_no-1)) {
			filtered_tasks[j++] = tasks[i];
		}
	}

	wattron(stats_window, COLOR_PAIR(queue_header_color));
	mvwprintw(stats_window, line++, 0, "%s", queue_header);
	wattroff(stats_window, COLOR_PAIR(queue_header_color));
	if (max >= j)
		max = j;
	else
		--max;
	if (max < 0) max = 0;
	for(i=0;i<max;i++) {
		char *cmde;
		assert(tasks);
		cmde = strchr(filtered_tasks[i].line, ' ');
		if(cmde) {
			char cmd[16];
			const char *filstart = strchr(cmde + 1, ' ');
			strncpy(cmd, filtered_tasks[i].line, sizeof(cmd)-1);
			cmd[15]='\0';
			if (filtered_tasks[i].line+15 > cmde)
				cmd[cmde - filtered_tasks[i].line] = '\0';
			if(filstart) {
				++filstart;
				if (detail_selected == -1 && global.num_clamd > 1)
					mvwprintw(stats_window, line + i, 0, "%2u %s", filtered_tasks[i].clamd_no, cmd + 1);
				else
					mvwprintw(stats_window, line + i, 0, " %s", cmd + 1);
				mvwprintw(stats_window, line + i, 15, "%10.03fs", filtered_tasks[i].tim);
				mvwprintw(stats_window, line + i, 30, "%s",filstart);
			}
		}
	}
	if (max < j) {
		/* in summary mode we can only show a max amount of tasks */
		wattron(stats_window, A_DIM | COLOR_PAIR(header_color));
		mvwprintw(stats_window, line+i, 0, "*** %u more task(s) not shown ***", (unsigned)(j - max));
		wattroff(stats_window, A_DIM | COLOR_PAIR(header_color));
	}
	free(filtered_tasks);
}

/* ---------------------- stats parsing routines ------------------- */


static void parse_queue(conn_t *conn, char* buf, size_t len, unsigned idx)
{
	do {
		double tim;
		const char *t = strchr(buf, ' ');
		if(!t)
			continue;
		if(sscanf(t,"%lf", &tim) != 1)
			continue;
		++global.n;
		global.tasks = realloc(global.tasks, sizeof(*global.tasks)*global.n);
		OOM_CHECK(global.tasks);
		global.tasks[global.n-1].line = strdup(buf);
		OOM_CHECK(global.tasks[global.n-1].line);
		global.tasks[global.n-1].tim  = tim;
		global.tasks[global.n-1].clamd_no = idx + 1;
	} while (recv_line(conn, buf, len) && buf[0] == '\t' && strcmp("END\n", buf) != 0);
}

static unsigned biggest_mem = 0;

static void output_memstats(struct stats *stats)
{
	char buf[128];
	unsigned long totalmem;
	int blink = 0;

	werase(mem_window);
	if (stats->mem > 0 || (stats->mem >=0 && (stats->lpoolt > 0))) {
		box(mem_window, 0, 0);

		if (stats->mem > 0)
		    snprintf(buf, sizeof(buf),"heap %4luM mmap %4luM unused %3luM",
			     stats->lheapu/1000, stats->lmmapu/1000, stats->lreleasable/1000);
		else
		    snprintf(buf, sizeof(buf), "heap   N/A mmap   N/A unused  N/A");
		mvwprintw(mem_window, 1, 1, "Mem:  ");
		print_colored(mem_window, buf);

		mvwprintw(mem_window, 2, 1, "Libc: ");
		if (stats->mem > 0)
		    snprintf(buf, sizeof(buf),"used %4luM free %4luM total %4luM",
			     stats->ltotalu/1000, stats->ltotalf/1000, (stats->ltotalu+stats->ltotalf)/1000);
		else
		    snprintf(buf, sizeof(buf), "used   N/A free   N/A total   N/A");
		print_colored(mem_window, buf);

		mvwprintw(mem_window, 3, 1, "Pool: ");
		snprintf(buf, sizeof(buf), "count %4u used %4luM total %4luM",
			stats->pools_cnt, stats->lpoolu/1000, stats->lpoolt/1000);
		print_colored(mem_window, buf);

		totalmem = stats->lheapu + stats->lmmapu + stats->lpoolt;
		if(totalmem > biggest_mem) {
			biggest_mem = totalmem;
			blink = 1;
		}
		show_bar(mem_window, 4, totalmem, stats->lmmapu + stats->lreleasable + stats->lpoolt - stats->lpoolu,
				biggest_mem, blink);
	}
	wrefresh(mem_window);
}

static void parse_memstats(const char *line, struct stats *stats)
{
	double heapu, mmapu, totalu, totalf, releasable, pools_used, pools_total;

	if(sscanf(line, " heap %lfM mmap %lfM used %lfM free %lfM releasable %lfM pools %u pools_used %lfM pools_total %lfM",
			&heapu, &mmapu, &totalu, &totalf, &releasable, &stats->pools_cnt, &pools_used, &pools_total) != 8) {
	    if (sscanf(line , " heap N/A mmap N/A used N/A free N/A releasable N/A pools %u pools_used %lfM pools_total %lfM",
		       &stats->pools_cnt, &pools_used, &pools_total) != 3) {
		stats->mem = -1;
		return;
	    }
	    stats->lpoolu = pools_used*1000;
	    stats->lpoolt = pools_total*1000;
	    stats->mem = 0;
	    return;
	}
	stats->lheapu = heapu*1000;
	stats->lmmapu = mmapu*1000;
	stats->ltotalu = totalu*1000;
	stats->ltotalf = totalf*1000;
	stats->lreleasable = releasable*1000;
	stats->lpoolu = pools_used*1000;
	stats->lpoolt = pools_total*1000;
	stats->mem = heapu + mmapu + pools_total;
}

static int output_stats(struct stats *stats, unsigned idx)
{
	char buf[128];
	char timbuf[15];
	int blink = 0;
	size_t i= 0;
	char mem[6];
	WINDOW *win = stats_head_window;
	int sel = detail_is_selected(idx);
	char *line = malloc(maxx+1);

	OOM_CHECK(line);

	if (stats->mem <= 0 || stats->stats_unsupp) {
		strncpy(mem, "N/A", sizeof(mem));
		mem[sizeof(mem)-1]='\0';
	}
	else {
		char c;
		double s;
		if (stats->mem > 999.0)  {
			c = 'G';
			s = stats->mem / 1024.0;
		} else {
			c = 'M';
			s = stats->mem;
		}
		snprintf(mem, sizeof(mem), "%7.3f", s);
		i = 4;
		if (mem[i-1] == '.') i--;
		mem[i++] = c;
		mem[i] = '\0';
	}
	i = idx+1;

	if (!stats->db_time.tm_year) {
		strncpy(timbuf,"N/A",sizeof(timbuf));
		timbuf[sizeof(timbuf)-1]='\0';
	}
	else
		snprintf(timbuf, sizeof(timbuf), "%04u-%02u-%02u %02uh",
				1900 + stats->db_time.tm_year,
				stats->db_time.tm_mon+1,
				stats->db_time.tm_mday,
				stats->db_time.tm_hour);

	memset(line, ' ', maxx+1);
	if (!stats->stats_unsupp) {
		snprintf(line, maxx-1, "%2u %02u:%02u:%02u %3u %3u %5u %5u %5s %-14s %-6s %5s %s", idx+1,  stats->conn_hr, stats->conn_min, stats->conn_sec,
			stats->live, stats->idle,
			stats->current_q, stats->biggest_queue,
			mem,
			stats->remote, stats->engine_version, stats->db_version, timbuf);
	} else {
		snprintf(line, maxx-1, "%2u %02u:%02u:%02u N/A N/A   N/A   N/A   N/A %-14s %-6s %5s %s", idx+1,  stats->conn_hr, stats->conn_min, stats->conn_sec,
			stats->remote, stats->engine_version, stats->db_version, timbuf);
	}
	line[maxx] = '\0';
	line[strlen(line)] = ' ';
	if (sel) {
		wattron(win,  COLOR_PAIR(selected_color));
	}
	mvwprintw(win, i, 0, "%s", line);
	if (sel) {
		wattroff(win, COLOR_PAIR(selected_color));
	}
	win = stats_window;
	i = 0;
	if (sel && !stats->stats_unsupp) {
		memset(line, ' ', maxx+1);
		snprintf(line, maxx-1, "Details for Clamd version: %s", stats->version);
		line[maxx] = '\0';
		line[strlen(line)]= ' ';
		wattron(win,  COLOR_PAIR(queue_header_color));
		mvwprintw(win, i++, 0, "%s", line);
		wattroff(win, COLOR_PAIR(queue_header_color));
		mvwprintw(win, i++, 0, "Primary threads: ");
		snprintf(buf, sizeof(buf), "live %3u idle %3u max %3u", stats->prim_live, stats->prim_idle, stats->prim_max);
		print_colored(win, buf);
		show_bar(win, i++, stats->prim_live, stats->prim_idle, stats->prim_max, 0);
/*		mvwprintw(win, i++, 0, "Multiscan pool : ");
		snprintf(buf, sizeof(buf), "live %3u idle %3u max %3u", stats->live, stats->idle, stats->max);
		print_colored(win, buf);
		show_bar(win, i++, stats->live, stats->idle, stats->max, 0);*/

		blink = 0;
		if(stats->current_q > stats->biggest_queue) {
			stats->biggest_queue = stats->current_q;
			blink = 1;
		}
		mvwprintw(win, i++, 0, "Queue:");
		snprintf(buf, sizeof(buf), "%6u items %6u max", stats->current_q, stats->biggest_queue);
		print_colored(win, buf);
		show_bar(win, i++, stats->current_q, 0, stats->biggest_queue, blink);
		i += 2;
		werase(mem_window);
		output_memstats(stats);
	}
	free(line);
	return i;
}

static void output_all(void)
{
	unsigned i, stats_line=0;
	werase(stats_head_window);
	werase(stats_window);
	wattron(stats_head_window, COLOR_PAIR(queue_header_color));
	mvwprintw(stats_head_window, 0, 0, "%s", clamd_header);
	wattroff(stats_head_window, COLOR_PAIR(queue_header_color));
	for (i=0;i<global.num_clamd;i++) {
		unsigned  j = output_stats(&global.all_stats[i], i);
		if (j > stats_line)
			stats_line = j;
	}
	output_queue(stats_line, maxystats - stats_line-1);
	wrefresh(stats_head_window);
	wrefresh(stats_window);
	if (detail_exists()) {
		/* overlaps, must be done at the end */
		wrefresh(mem_window);
	}
}

static void parse_stats(conn_t *conn, struct stats *stats, unsigned idx)
{
	char buf[1025];
	size_t j;
	struct timeval tv;
	unsigned conn_dt;
	int primary = 0;
	const char *pstart, *p, *vstart;

	if (conn->tcp)
		stats->remote = conn->remote;
	else
		stats->remote = "local";

	if (!conn->version) {
		stats->engine_version = strdup("???");
		OOM_CHECK(stats->engine_version);
		return;
	}
	p = pstart = vstart = strchr(conn->version, ' ');
	if (!vstart) {
	    stats->engine_version = strdup("???");
	    OOM_CHECK(stats->engine_version);
	    return;
	}
	/* find digit in version */
	while (*p && !isdigit(*p))
		p++;
	/* rewind to first space or dash */
	while (p > pstart && *p && *p != ' ' && *p != '-')
		p--;
	if (*p) p++;
	/* keep only base version, and cut -exp, and -gittags */
	pstart = p;
	while (*p && *p != '-' && *p != '/')
		p++;

	stats->engine_version = malloc(p - pstart+1);
	OOM_CHECK(stats->engine_version);

	memcpy(stats->engine_version, pstart, p-pstart);
	stats->engine_version[p-pstart] = '\0';

	pstart = strchr(p, '/');
	if (!pstart) {
		stats->db_version = strdup("????");
		OOM_CHECK(stats->db_version);
	} else {
		pstart++;
		p = strchr(pstart, '/');
		if (!p)
			p = pstart + strlen(pstart);
		stats->db_version = malloc(p - pstart + 1);
		OOM_CHECK(stats->db_version);
		memcpy(stats->db_version, pstart, p-pstart);
		stats->db_version[p-pstart] = '\0';
		if(*p) p++;
		if (!*p || !strptime(p,"%a %b  %d %H:%M:%S %Y", &stats->db_time)) {
			memset(&stats->db_time, 0, sizeof(stats->db_time));
		}
	}
	if (maxx > 61 && strlen(stats->db_version) > (maxx-61)) {
		stats->db_version[maxx-61] = '\0';
	}

	stats->version = vstart; /* for details view */
	gettimeofday(&tv, NULL);
	tv.tv_sec -= conn->tv_conn.tv_sec;
	tv.tv_usec -= conn->tv_conn.tv_usec;
	conn_dt = tv.tv_sec + tv.tv_usec/1e6;

	stats->live = stats->idle = stats->max = 0;
	stats->conn_hr = conn_dt/3600;
	stats->conn_min = (conn_dt/60)%60;
	stats->conn_sec = conn_dt%60;
	stats->current_q = 0;
	buf[sizeof(buf) - 1] = 0x0;
	while(recv_line(conn, buf, sizeof(buf)-1) && strcmp("END\n",buf) != 0) {
		char *val = strchr(buf, ':');

		if(buf[0] == '\t') {
			parse_queue(conn, buf, sizeof(buf)-1, idx);
			continue;
		} else if(val)
			*val++ = '\0';
		if(!strcmp("MEMSTATS", buf)) {
			parse_memstats(val, stats);
			continue;
		}
		if(!strncmp("UNKNOWN COMMAND", buf, 15)) {
			stats->stats_unsupp = 1;
			break;
		}
		for(j=1;j<strlen(buf);j++)
			buf[j] = tolower(buf[j]);
	/*	mvwprintw(win, i, 0, "%s", buf);
		if(!val) {
			i++;
			continue;
		}
		waddch(win, ':');
		print_colored(win, val);
		i++;*/
		if(!strncmp("State",buf,5)) {
			if(strstr(val, "PRIMARY")) {
				/* primary thread pool */
				primary = 1;
			} else {
				/* multiscan pool */
				primary = 0;
			}
		}
		if(!strcmp("Threads",buf)) {
			unsigned live, idle, max;
			if(sscanf(val, " live %u idle %u max %u", &live, &idle, &max) != 3)
				continue;
			if (primary) {
				stats->prim_live = live;
				stats->prim_idle = idle;
				assert(!stats->prim_max && "There can be only one primary pool!");
				stats->prim_max = max;
			}
			stats->live += live;
			stats->idle += idle;
			stats->max += max;
		} else if (!strcmp("Queue",buf)) {
			unsigned len;
			if(sscanf(val, "%u", &len) != 1)
				continue;
			stats->current_q += len;
		}
	}
}

static int read_version(conn_t *conn)
{
	char buf[1024];
	unsigned i;
	if(!recv_line(conn, buf, sizeof(buf)))
	    return -1;
	if (!strcmp(buf, "UNKNOWN COMMAND\n"))
	    return -2;

	conn->version = strdup(buf);
	OOM_CHECK(conn->version);
	for (i=0;i<strlen(conn->version);i++)
		    if (conn->version[i] == '\n')
			conn->version[i] = ' ';
	return 0;
}

static void sigint(int a)
{
    UNUSEDPARAM(a);
	EXIT_PROGRAM(SIGINT_REASON);
}

static void help(void)
{
    printf("\n");
    printf("                       Clam AntiVirus: Monitoring Tool %s\n", get_version());
    printf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    printf("           (C) 2019 Cisco Systems, Inc.\n");
    printf("\n");
    printf("    clamdtop [-hVc] [host[:port] /path/to/clamd.socket ...]\n");
    printf("\n");
    printf("    --help                 -h         Show this help\n");
    printf("    --version              -V         Show version\n");
    printf("    --config-file=FILE     -c FILE    Read clamd's configuration files from FILE\n");
    printf("    --defaultcolors	       -d         Use default terminal colors\n");
    printf("    host[:port]                       Connect to clamd on host at port (default 3310)\n");
    printf("    /path/to/clamd.socket             Connect to clamd over a local socket\n");
    printf("\n");
    return;
}
static int default_colors=0;
/* -------------------------- Initialization ---------------- */
static void setup_connections(int argc, char *argv[])
{
    struct optstruct *opts;
    struct optstruct *clamd_opts;
    unsigned i;
    char *conn = NULL;

    opts = optparse(NULL, argc, argv, 1, OPT_CLAMDTOP, 0, NULL);
    if (!opts) {
        fprintf(stderr, "ERROR: Can't parse command line options\n");
        EXIT_PROGRAM(FAIL_CMDLINE);
    }

    if(optget(opts, "help")->enabled) {
        optfree(opts);
        help();
        normal_exit = 1;
        exit(0);
    }

    if(optget(opts, "version")->enabled) {
        printf("Clam AntiVirus Monitoring Tool %s\n", get_version());
        optfree(opts);
        normal_exit = 1;
        exit(0);
    }

    if(optget(opts, "defaultcolors")->enabled)
        default_colors = 1;

    memset(&global, 0, sizeof(global));
    if (!opts->filename || !opts->filename[0]) {
        const struct optstruct *opt;
        const char *clamd_conf = optget(opts, "config-file")->strarg;

        if ((clamd_opts = optparse(clamd_conf, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
            fprintf(stderr, "Can't parse clamd configuration file %s\n", clamd_conf);
            EXIT_PROGRAM(FAIL_CMDLINE);
        }

        if((opt = optget(clamd_opts, "LocalSocket"))->enabled) {
            conn = strdup(opt->strarg);
            if (!conn) {
                fprintf(stderr, "Can't strdup LocalSocket value\n");
                EXIT_PROGRAM(FAIL_INITIAL_CONN);
            }
        } else if ((opt = optget(clamd_opts, "TCPSocket"))->enabled) {
            char buf[512];
            const struct optstruct *opt_addr;
            const char *host = "localhost";
            if ((opt_addr = optget(clamd_opts, "TCPAddr"))->enabled) {
                host = opt_addr->strarg;
            }
            snprintf(buf, sizeof(buf), "%lld", opt->numarg);
            conn = make_ip(host, buf);
        } else {
            fprintf(stderr, "Can't find how to connect to clamd\n");
            EXIT_PROGRAM(FAIL_INITIAL_CONN);
        }

        optfree(clamd_opts);
        global.num_clamd = 1;
    } else {
        unsigned i = 0;
        while (opts->filename[i]) { i++; }
        global.num_clamd = i;
    }

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR) {
        fprintf(stderr, "Error at WSAStartup(): %d\n", WSAGetLastError());
        EXIT_PROGRAM(FAIL_INITIAL_CONN);
    }
#endif
    /* clamdtop */
    puts( "        __                    ____");
    puts("  _____/ /___ _____ ___  ____/ / /_____  ____");
    puts(" / ___/ / __ `/ __ `__ \\/ __  / __/ __ \\/ __ \\");
    puts("/ /__/ / /_/ / / / / / / /_/ / /_/ /_/ / /_/ /");
    puts("\\___/_/\\__,_/_/ /_/ /_/\\__,_/\\__/\\____/ .___/");
    puts("                                     /_/");

    global.all_stats = calloc(global.num_clamd, sizeof(*global.all_stats));
    OOM_CHECK(global.all_stats);
    global.conn = calloc(global.num_clamd, sizeof(*global.conn));
    OOM_CHECK(global.conn);

    for (i=0;i < global.num_clamd;i++) {
        const char *soname = conn ? conn : opts->filename[i];
        global.conn[i].line = i+1;
        if (make_connection(soname, &global.conn[i]) < 0) {
            EXIT_PROGRAM(FAIL_INITIAL_CONN);
        }
    }

    optfree(opts);
    free(conn);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sigint);
#endif
}

static void free_global_stats(void)
{
	unsigned i;
	for (i=0;i<(unsigned)global.n;i++) {
		free(global.tasks[i].line);
	}
	for (i=0;i<global.num_clamd;i++) {
		free(global.all_stats[i].engine_version);
		free(global.all_stats[i].db_version);
	}
	free(global.tasks);
	global.tasks = NULL;
	global.n=0;
}

static int help_line;
static void explain(const char *abbrev, const char *msg)
{
	wattron(stdscr, A_BOLD);
	mvwprintw(stdscr, help_line++, 0, "%-15s", abbrev);
	wattroff(stdscr, A_BOLD);
	wprintw(stdscr,"  %s", msg);
}

static int show_help(void)
{
	int ch;
	werase(stdscr);
	help_line = 0;

	explain("NO","Unique clamd number");
	explain("CONNTIME", "How long it is connected");
	explain("LIV", "Total number of live threads");
	explain("IDL", "Total number of idle threads");
	explain("QUEUE", "Number of items in queue");
	explain("MAXQ","Maximum number of items observed in queue");
	explain("MEM", "Total memory usage (if available)");
	explain("HOST", "Which clamd, local means unix socket");
	explain("ENGINE", "Engine version");
	explain("DBVER", "Database version");
	explain("DBTIME", "Database publish time");
	explain("Primary threads", "Threadpool used to receive commands");
	explain("Multiscan pool","Threadpool used for multiscan");
	explain("live","Executing commands, or scanning");
	explain("idle","Waiting for commands, will exit after idle_timeout");
	explain("max", "Maximum number of threads configured for this pool");
	explain("Queue","Tasks queued for processing, but not yet picked up by a thread");
	explain("COMMAND","Command this thread is executing");
	explain("QUEUEDSINCE","How long this task is executing");
	explain("FILE","Which file it is processing (if applicable)");
	explain("Mem","Memory usage reported by libc");
	explain("Libc","Used/free memory reported by libc");
	explain("Pool","Memory usage reported by libclamav's pool");

	wrefresh(stdscr);
	werase(status_bar_window);
	wattron(status_bar_window, A_REVERSE);
	mvwprintw(status_bar_window, 0, 0, "Press any key to exit help");
	wattroff(status_bar_window, A_REVERSE);
	wrefresh(status_bar_window);
	/* getch() times out after a few seconds */
	do {
		ch = getch();
		/* we do need to exit on resize, because the text scroll out of
		 * view */
	} while (ch == -1 /*|| ch == KEY_RESIZE*/);
	return ch == KEY_RESIZE ? KEY_RESIZE : -1;
}

int main(int argc, char *argv[])
{
	int ch = 0;
	struct timeval tv_last, tv;
	unsigned i;

	atexit(cleanup);
	setup_connections(argc, argv);
	init_ncurses(global.num_clamd, default_colors);

	memset(&tv_last, 0, sizeof(tv_last));
	do {
		if (toupper(ch) == 'H') {
			ch = show_help();
		}
		switch(ch) {
			case KEY_RESIZE:
				resize();
				endwin();
				refresh();
				init_windows(global.num_clamd);
				break;
			case 'R':
			case 'r':
				for (i=0;i<global.num_clamd;i++)
					global.all_stats[i].biggest_queue = 1;
				biggest_mem = 0;
				break;
			case KEY_UP:
				if (global.num_clamd > 1) {
					if (detail_selected == -1)
						detail_selected = global.num_clamd-1;
					else
						--detail_selected;
				}
				break;
			case KEY_DOWN:
				if (global.num_clamd > 1) {
					if (detail_selected == -1)
						detail_selected = 0;
					else {
						if((unsigned)++detail_selected >= global.num_clamd)
							detail_selected = -1;
					}
				}
				break;
		}
		gettimeofday(&tv, NULL);
		header();
		if(tv.tv_sec - tv_last.tv_sec >= MIN_INTERVAL) {
			free_global_stats();
			for(i=0;i<global.num_clamd;i++) {
				unsigned biggest_q;
				struct stats *stats = &global.all_stats[i];
				if (global.conn[i].sd != -1)
					send_string(&global.conn[i], "nSTATS\n");
				biggest_q = stats->biggest_queue;
				memset(stats, 0, sizeof(*stats));
				stats->biggest_queue = biggest_q;
				parse_stats(&global.conn[i], stats, i);
			}
			if (global.tasks)
				qsort(global.tasks, global.n, sizeof(*global.tasks), tasks_compare);
			tv_last = tv;
		}
		/* always show, so that screen resizes take effect instantly*/
		output_all();
		for(i=0;i<global.num_clamd;i++) {
			if (global.conn[i].sd == -1)
				reconnect(&global.conn[i]);
		}
	} while(toupper(ch = getch()) != 'Q');
	free_global_stats();
	normal_exit = 1;
	return 0;
}
