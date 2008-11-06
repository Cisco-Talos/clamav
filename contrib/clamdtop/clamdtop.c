/*
 *  ClamdTOP version 0.1
 *
 *  Copyright (C) 2008 Sourcefire, Inc.
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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <ncurses.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>

/* ---------------------- NCurses routines -----------------*/
enum colors {
	header_color=1,
	version_color,
	value_color,
	descr_color,
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

static WINDOW *header_window = NULL;
static WINDOW *version_window = NULL;
static WINDOW *stats_head_window = NULL;
static WINDOW *stats_window = NULL;
static WINDOW *status_bar_window = NULL;
static WINDOW *mem_window = NULL;

static const char *status_bar_keys[10];
static unsigned maxy=0, maxx=0;
static char *queue_header = NULL;
static const char *exit_reason = NULL;
#define CMDHEAD "COMMAND        TIME QUEUED   FILE"

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
	queue_header = malloc(maxx + 1);
	if(!queue_header)
		exit(1);
	queue_header[maxx] = '\0';
	strncpy(queue_header, CMDHEAD, maxx);
	p = queue_header + strlen(queue_header);
	while(p < queue_header+maxx)
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
	if(version_window) {
		delwin(version_window);
		version_window = NULL;
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

static int normal_exit = 0;

static void cleanup_ncurses(void)
{
	werase(status_bar_window);
	wrefresh(status_bar_window);
	rm_windows();
	endwin();
	if(!normal_exit)
		printf("Abnormal program termination %s\n",
				exit_reason ? exit_reason : "");
}

static void init_windows(void)
{
	resize();

	rm_windows();
	header_window = subwin(stdscr, 1, maxx, 0, 0);
	version_window = subwin(stdscr, 1, maxx, 1, 0);
	stats_head_window = subwin(stdscr, 5, maxx-48, 3, 0);
	stats_window = subwin(stdscr, maxy-9, maxx, 7, 0);
	mem_window = subwin(stdscr, 6, 48, 3, maxx-48);
	status_bar_window = subwin(stdscr, 1i, maxx, maxy-1, 0);
	touchwin(stdscr);
	werase(stdscr);
	refresh();
	memset(status_bar_keys, 0, sizeof(status_bar_keys));
	status_bar_keys[0] = "Q - quit";
	status_bar_keys[1] = "R - reset bar maximums";
}

static void init_ncurses(void)
{
	initscr();
	start_color();
	keypad(stdscr, TRUE);	/* enable keyboard mapping */
	nonl();			/* tell curses not to do NL->CR/NL on output */
	halfdelay(UPDATE_INTERVAL*10); /* timeout of 2s when waiting for input*/
	noecho();		/* dont echo input */
	curs_set(0);		/* turn off cursor */
	use_default_colors();

	init_pair(header_color, COLOR_BLACK, COLOR_WHITE);
	init_pair(version_color, DEFAULT_COLOR, DEFAULT_COLOR);
	init_pair(value_color, COLOR_GREEN, DEFAULT_COLOR);
	init_pair(descr_color, COLOR_CYAN, DEFAULT_COLOR);
	init_pair(queue_header_color, COLOR_BLACK, COLOR_GREEN);
	init_pair(activ_color, COLOR_MAGENTA, DEFAULT_COLOR);
	init_pair(dim_color, COLOR_GREEN, DEFAULT_COLOR);
	init_pair(red_color, COLOR_RED, DEFAULT_COLOR);

	atexit(cleanup_ncurses);

	init_windows();
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

static char *clamd_version = NULL;

static void header(void)
{
	size_t i, x=0;
	time_t t;

	win_start(header_window, header_color);
	mvwprintw(header_window, 0, 0, "  ClamdTOP version 0.1   ");
	time(&t);
	wprintw(header_window, "%s", ctime(&t));
	wrefresh(header_window);

	win_start(version_window, version_color);
	mvwprintw(version_window, 0, 0, "Connected to: ");
	print_colored(version_window, clamd_version ? clamd_version : "Unknown");
	wrefresh(version_window);

	werase(status_bar_window);
	for(i=0;i<sizeof(status_bar_keys)/sizeof(status_bar_keys[0]);i++) {
		if(!status_bar_keys[i])
			continue;
		wattron(status_bar_window, A_REVERSE);
		mvwprintw(status_bar_window, 0, x,  "%s",status_bar_keys[i]);
		wattroff(status_bar_window, A_REVERSE);
		x += strlen(status_bar_keys[i]) + 1;
	}
	wrefresh(status_bar_window);
}

static void show_bar(WINDOW *win, size_t i, unsigned live, unsigned idle,
		unsigned max, int blink)
{
	int y,x;
	unsigned len  = 47;
	unsigned start = 1;
	unsigned activ = ((live-idle)*(len - start - 2) + (max/2)) / max;
	unsigned dim   = idle*(len - start - 2) / max;
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
		mvwaddch(win, y, x-2, '>' | A_BLINK | COLOR_PAIR(red_color));
		move(y, x);
	}
}

struct task {
	char *line;
	double tim;
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
typedef struct connection {
	int sd;
	const char *remote;
} conn_t;

static void print_con_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (version_window) {
		werase(version_window);
		wmove(version_window, 0, 0);
		vwprintw(version_window, fmt, ap);
		wrefresh(version_window);
	} else
		vfprintf(stderr, fmt, ap);
	va_end(ap);
}


static int make_connection(const char *soname, conn_t *conn)
{
	int s;
	if(access(soname, F_OK) == 0) {
		struct sockaddr_un addr;
		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if(s < 0) {
			perror("socket");
			return -1;
		}
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strncpy(addr.sun_path, soname, sizeof(addr.sun_path));
		printf("Connecting to: %s\n", soname);
		if (connect(s, (struct sockaddr *)&addr, sizeof(addr))) {
			perror("connect");
			return -1;
		}
	} else {
		struct sockaddr_in server;
		struct hostent *hp;
		unsigned port = 0;
		char *name = strdup(soname);
		const char *host = name;
		name = strchr(name, ':');
		if(name) {
			*name++ = '\0';
			port = atoi(name);
		}
		if(!port)
			port = 3310;
		printf("Looking up: %s\n", host);
		if((hp = gethostbyname(host)) == NULL) {
			herror("Cannot find host");
			return -1;
		}
		free(name);
		s = socket(AF_INET, SOCK_STREAM, 0);
		if(s < 0) {
			perror("socket");
			return -1;
		}
		server.sin_family = AF_INET;
		server.sin_port = htons(port);
		server.sin_addr.s_addr = ((struct in_addr*)(hp->h_addr))->s_addr;
		printf("Connecting to: %s:%u\n", inet_ntoa(server.sin_addr), port);
		if (connect(s, (struct sockaddr *)&server, sizeof(server))) {
			perror("connect");
			return -1;
		}
	}
	conn->remote = soname;
	conn->sd = s;
	return 0;
}

static void reconnect(conn_t *conn)
{
	print_con_error("%s: %s", conn->remote, strerror(errno));
	if (make_connection(conn->remote, conn) < 0) {
		print_con_error("Unable to reconnect to %s: %s", conn->remote, strerror(errno));
		exit(3);
	}
}

static void send_string(conn_t *conn, const char *cmd)
{
	assert(cmd);
	assert(conn && conn->sd > 0);

	while(send(conn->sd, cmd, strlen(cmd), 0) == -1) {
		reconnect(conn);
	}
}

static int recv_line(conn_t *conn, char *buf, size_t len)
{
	assert(len > 0);
	assert(conn && conn->sd > 0);
	assert(buf);

	len--;
	if (!len)
		return 0;
	while (len > 0) {
		ssize_t nread = recv(conn->sd, buf, len, MSG_PEEK);
		if (nread == -1)
			reconnect(conn);
		else {
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

/* ---------------------- stats parsing routines ------------------- */
static size_t parse_queue(conn_t *conn, size_t line, char* buf, size_t len)
{
	struct task *tasks = NULL;
	size_t n = 0, i;
	do {
		double tim;
		const char *t = strchr(buf, ' ');
		if(!t)
			continue;
		if(sscanf(t,"%lf", &tim) != 1)
			continue;
		++n;
		tasks = realloc(tasks, sizeof(*tasks)*n);
		if(!tasks) {
			/* OOM */
			exit(1);
		}
		tasks[n-1].line = strdup(buf);
		if(!tasks[n-1].line)
			exit(1);
		tasks[n-1].tim  = tim;
	} while (recv_line(conn, buf, len) && buf[0] == '\t' && strcmp("END\n", buf) != 0);
	qsort(tasks, n, sizeof(*tasks), tasks_compare);
	wattron(stats_window, COLOR_PAIR(queue_header_color));
	mvwprintw(stats_window, line++, 0, queue_header);
	wattroff(stats_window, COLOR_PAIR(queue_header_color));
	for(i=0;i<n;i++) {
		char *cmde = strchr(tasks[i].line, ' ');
		if(cmde) {
			const char *filstart = strchr(cmde + 1, ' ');
			*cmde = '\0';
			if(filstart) {
				++filstart;
				mvwprintw(stats_window, line + i, 0, " %s", tasks[i].line + 1);
				mvwprintw(stats_window, line + i, 15, "%10.03fs", tasks[i].tim);
				mvwprintw(stats_window, line + i, 30, "%s",filstart);
			}
		}
		free(tasks[i].line);
	}
	free(tasks);
	return line + i + 1;
}

static unsigned biggest_queue = 1, biggest_mem = 0;

static void output_memstats(const char* line)
{
	char buf[128];
	int blink = 0;
	double heapu, mmapu, totalu, totalf, releasable, pools_used, pools_total;
	unsigned pools_cnt;
	unsigned long lheapu, lmmapu, ltotalu, ltotalf, lreleasable, totalmem, lpoolu, lpoolt;

	if(sscanf(line, " heap %lfM mmap %lfM used %lfM free %lfM releasable %lfM pools %u pools_used %lfM pools_total %lfM",
			&heapu, &mmapu, &totalu, &totalf, &releasable, &pools_cnt, &pools_used, &pools_total) != 8)
		return;
	lheapu = heapu*1000;
	lmmapu = mmapu*1000;
	ltotalu = totalu*1000;
	ltotalf = totalf*1000;
	lreleasable = releasable*1000;
	lpoolu = pools_used*1000;
	lpoolt = pools_total*1000;
	werase(mem_window);
	box(mem_window, 0, 0);

	snprintf(buf, sizeof(buf),"heap %4luM mmap %4luM releasable %3luM",
			lheapu/1024, lmmapu/1024, lreleasable/1024);
	mvwprintw(mem_window, 1, 1, "Memory: ");
	print_colored(mem_window, buf);

	mvwprintw(mem_window, 2, 1, "Malloc: ");
	snprintf(buf, sizeof(buf),"used %4luM free %4luM total     %4luM",
			ltotalu/1024, ltotalf/1024, (ltotalu+ltotalf)/1024);
	print_colored(mem_window, buf);

	mvwprintw(mem_window, 3, 1, "Mempool: ");
	snprintf(buf, sizeof(buf), "count  %u  used %4luM total     %4luM",
			pools_cnt, lpoolu/1024, lpoolt/1024);
	print_colored(mem_window, buf);

	totalmem = lheapu + lmmapu + lpoolt;
	if(totalmem > biggest_mem) {
		biggest_mem = totalmem;
		blink = 1;
	}
	show_bar(mem_window, 4, totalmem, lmmapu + lreleasable + lpoolt - lpoolu,
			biggest_mem, blink);
	wrefresh(mem_window);
}

static struct timeval tv_conn;

static void parse_stats(conn_t *conn)
{
	WINDOW *win = stats_head_window;
	char buf[1024];
	size_t i=0 ,j;
	struct timeval tv;
	unsigned conn_dt;

	werase(stats_head_window);
	werase(stats_window);
	werase(mem_window);
	gettimeofday(&tv, NULL);
	tv.tv_sec -= tv_conn.tv_sec;
	tv.tv_usec -= tv_conn.tv_usec;
	conn_dt = tv.tv_sec + tv.tv_usec/1e6;
	mvwprintw(stats_head_window, i++, 0, "Connected since: %02u:%02u:%02u",
			conn_dt/3600, (conn_dt/60)%60, conn_dt%60);
	while(recv_line(conn, buf, sizeof(buf)) && strcmp("END\n",buf) != 0) {
		char *val = strchr(buf, ':');
		if(i >= 4 && win == stats_head_window) {
			win = stats_window;
			i = 0;
		}

		if(buf[0] == '\t') {
			i = parse_queue(conn, i, buf, sizeof(buf));
			continue;
		} else if(val)
			*val++ = '\0';
		if(!strcmp("MEMSTATS", buf)) {
			output_memstats(val);
			continue;
		}
		for(j=1;j<strlen(buf);j++)
			buf[j] = tolower(buf[j]);
		mvwprintw(win, i, 0, "%s", buf);
		if(!val) {
			i++;
			continue;
		}
		waddch(win, ':');
		print_colored(win, val);
		i++;
		if(!strcmp("Threads",buf)) {
			unsigned live, idle, max;
			if(sscanf(val, " live %u idle %u max %u", &live, &idle, &max) != 3)
				continue;
			show_bar(win, i++, live, idle, max, 0);
		} else if (!strcmp("Queue",buf)) {
			int blink = 0;
			unsigned len;
			if(sscanf(val, "%u", &len) != 1)
				continue;
			if(len > biggest_queue) {
				biggest_queue = len;
				blink = 1;
			}
			show_bar(win, i++, len, 0, biggest_queue, blink);
		}
	}
	wrefresh(stats_head_window);
	wrefresh(stats_window);
}

static void read_version(conn_t *conn)
{
	char buf[1024];
	if(recv_line(conn, buf, sizeof(buf))) {
		clamd_version = strdup(buf);
	}
}

static conn_t conn;

int main(int argc, char *argv[])
{
	int ch = 0, need_initwin=0;
	fd_set rfds;
	struct timeval tv_last, tv;

	/* TODO: parse clamd.conf */
	if (make_connection(argc > 1 ? argv[1] : "/tmp/clamd.socket", &conn) < 0)
		exit(2);

	signal(SIGPIPE, SIG_IGN);

	gettimeofday(&tv_conn, NULL);
	send_string(&conn, "SESSION\nVERSION\n");
	read_version(&conn);
	init_ncurses();

	FD_ZERO(&rfds);
	FD_SET(0, &rfds);
	memset(&tv_last, 0, sizeof(tv_last));
	do {
		if(ch == KEY_RESIZE) {
			resize();
			endwin();
			refresh();
			need_initwin = 1;
		}
		if(ch == 'R') {
			biggest_queue = 1;
			biggest_mem = 0;
		}
		gettimeofday(&tv, NULL);
		if(tv.tv_sec - tv_last.tv_sec >= MIN_INTERVAL) {
			if(need_initwin) {
				init_windows();
				need_initwin = 0;
			}
			send_string(&conn, "STATS\n");
			header();
			parse_stats(&conn);
			tv_last = tv;
		}
	} while(toupper(ch = getch()) != 'Q');
	send_string(&conn, "END\n");
	close(conn.sd);
	free(clamd_version);
	normal_exit = 1;
	return 0;
}
