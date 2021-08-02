#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <pwd.h>
#include <netdb.h>
#include <uuid.h>
#include <errno.h>
#include <err.h>
#include <assert.h>

#include <event.h>
#include <libpq-fe.h>

#include "log.h"

#define LINES_USER		"_lined"
#define LINES_PORT		"601"

#define LINES_BUFLEN		(1 << 10)
#define LINES_BUFLEN_MAX	(256 << 10)

struct refcnt {
	unsigned int refs;
};

enum line_state {
	S_PRE_LINE,
	S_LINE,

	S_UTF8_3,
	S_UTF8_2,
	S_UTF8_1,

	S_DEAD,
};

#if 0
static const char *line_state_names[] = {
	"PRE_LINE",
	"LINE",
	"UFT8_3",
	"UFT8_2",
	"UFT8_1",
	"DEAD",
};
#endif

/*
 * anything at this state or above represents and invalid byte
 * sequence to end on.
 */

static inline int
line_state_invalid(state)
{
	return (state >= S_UTF8_3);
}

/*
 * 2021-07-30 16:45:00.123456+10:00
 *           1         2         3 32
 * 01234567890123456789012345678901
 */
#define TIMESTAMPTZ_LEN		33

static const char insert_stmt[] = "ins_stmt";
static const char insert[] = "INSERT INTO \"lines\" ("
	"\"ts\", \"id\", \"type\", "
	"\"saddr\", \"sport\", \"daddr\", \"dport\", \"seq\", "
	"\"msg\""
") VALUES ("
	"$1, $2, $3, "
	"$4, $5, $6, $7, $8, "
	"$9"
")";

#define INSERT_PARAMS	9

struct line {
	TAILQ_ENTRY(line)		 entry;

	void				(*dtor)(struct line *);
	void				*cookie;

	char				 ts[TIMESTAMPTZ_LEN];
	char				*id;

	char				*laddr;
	char				*lport;
	char				*raddr;
	char				*rport;
	unsigned int			 seq;

	unsigned char			 buf[1]; /* must be last */

	/*
	 * this is followed by extra bytes that store the actual
	 * line. the one byte buf is used to account for the
	 * terminating '\0'.
	 */
};

TAILQ_HEAD(lines, line);

struct conn {
	struct server			*server;
	struct event			 ev;

	struct refcnt			 refs;
	unsigned int			 seq;

	char				*laddr;
	char				*lport;
	char				*raddr;
	char				*rport;

	/* state of the buffer */
	unsigned char			*buf;
	size_t				 buflen;

	/* state of the message */
	enum line_state			 state;
	struct timespec			 ts;
	size_t				 head;
	size_t				 tail;
	size_t				 next;
};

struct listener {
	TAILQ_ENTRY(listener)		 entry;
	struct server			*server;
	const char			*host;
	const char			*port;
	struct event			 ev;
};

TAILQ_HEAD(listeners, listener);

struct server {
	struct listeners		 listeners;

	PGconn				*db;
	struct event			 db_ev_rd;
	struct event			 db_ev_wr;

	struct lines			 lines;
	struct event			 store;
};

static void	 server_bind(struct server *s, int,
		     const char *, const char *);
static void	 server_listen(struct server *s);
static void	 server_store(int, short, void *);

static void	 listener_accept(int, short, void *);

static void	 tcp_read(int, short, void *);

static void	 db_connect(struct server *, const char *);

static char	*id_gen(void);
static void	 timestamptz(char *, size_t, const struct timespec *)
		     __attribute__ ((__bounded__(__buffer__,1,2)));

static void
refcnt_init(struct refcnt *r)
{
	r->refs = 1;
}

static void
refcnt_take(struct refcnt *r)
{
	++r->refs;
}

static int
refcnt_rele(struct refcnt *r)
{
	return (--r->refs == 0);
}

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-d] [-u user]\n", __progname);

	exit(1);
}

static const struct timeval store_timeval = { 0, 10000 };

int debug = 0;

int
main(int argc, char *argv[])
{
	struct server server = {
		.listeners = TAILQ_HEAD_INITIALIZER(server.listeners),
		.lines = TAILQ_HEAD_INITIALIZER(server.lines),
	};
	struct server *s = &server;

	const char *user = LINES_USER;
	const char *conn = "";

	int ch;

	struct passwd *pw;

	while ((ch = getopt(argc, argv, "dp:u:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'p':
			conn = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		usage();

	if (geteuid() != 0)
		errx(1, "need root privileges");

	pw = getpwnam(user);
	if (pw == NULL)
		errx(1, "no %s user", user);

	server_bind(s, AF_UNSPEC, NULL, LINES_PORT);

	if (chdir(pw->pw_dir) == -1)
		err(1, "%s", pw->pw_dir);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		errx(1, "can't drop privileges");

	pw = NULL;
	endpwent();

	db_connect(s, conn);

	signal(SIGPIPE, SIG_IGN);

	if (!debug && daemon(1, 1) == -1)
		err(1, "daemon");

	event_init();

	evtimer_set(&s->store, server_store, s);
	server_listen(s);

	event_dispatch();

	return (0);
}

static void
server_bind(struct server *s, int af, const char *host, const char *port)
{
	struct listeners listeners = TAILQ_HEAD_INITIALIZER(listeners);
	struct listener *l;

	struct addrinfo hints, *res, *res0;
	int error;
	int serrno;
	const char *cause;
	int fd;
	int reuse;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(host, port, &hints, &res0);
	if (error != 0) {
		errx(1, "host %s port %s: %s", host ? host : "*", port,
		    gai_strerror(error));
	}

	for (res = res0; res != NULL; res = res->ai_next) {

		fd = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK,
		    res->ai_protocol);
		if (fd == -1) {
			serrno = errno;
			cause = "socket";
			continue;
		}

		if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
			serrno = errno;
			cause = "bind";
			close(fd);
			continue;
		}

		if (listen(fd, 5) == -1) {
			serrno = errno;
			cause = "bind";
			close(fd);
			continue;
		}

		reuse = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
		    &reuse, sizeof(reuse)) == -1) {
			warn("host %s port %s enable reuse port",
			    host ? host : "*", port);
                }

		reuse = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		    &reuse, sizeof(reuse)) == -1) {
			warn("host %s port %s enable reuse addr",
			    host ? host : "*", port);
                }

		l = malloc(sizeof(*l));
		if (l == NULL)
			err(1, "listener alloc");

		event_set(&l->ev, fd, 0, NULL, NULL);
		TAILQ_INSERT_TAIL(&listeners, l, entry);
	}

	if (TAILQ_EMPTY(&listeners)) {
		errc(1, serrno, "host %s port %s %s", host ? host : "*", port,
		    cause);
	}

	TAILQ_CONCAT(&s->listeners, &listeners, entry);
}

static void
server_listen(struct server *s)
{
	struct listener *l;

	TAILQ_FOREACH(l, &s->listeners, entry) {
		l->server = s;
		event_set(&l->ev, EVENT_FD(&l->ev), EV_READ|EV_PERSIST,
		    listener_accept, l);
		event_add(&l->ev, NULL);
	}
}

static void
server_store_line(struct server *s, struct line *line)
{
	PGresult *result;
	char seq[32];
	int rv;

	const char *values[INSERT_PARAMS] = {
		line->ts, line->id, "syslog",
		line->raddr, line->rport, line->laddr, line->lport, seq,
		line->buf
	};

	rv = snprintf(seq, sizeof(seq), "%lld", (long long)line->seq);
	if (rv < 0)
		lerrx(1, "%s: seq encoding error", __func__);
	if ((size_t)rv >= sizeof(seq))
		lerrx(1, "%s: seq buffer too small", __func__);

	result = PQexecPrepared(s->db, insert_stmt, INSERT_PARAMS,
	    values, NULL, NULL, 0);
	if (result == NULL) {
		lwarnc(ENOMEM, "db exec %s, dropping line from %s",
		    insert_stmt, line->raddr);
		return;
	}
	if (PQresultStatus(result) != PGRES_COMMAND_OK) {
		lwarnx("db exec %s: %s", insert_stmt,
		    PQresultErrorField(result, PG_DIAG_MESSAGE_PRIMARY));
	}
	PQclear(result);
}

static void
server_store(int nope, short events, void *arg)
{
	struct server *s = arg;
	struct line *line;

	while ((line = TAILQ_FIRST(&s->lines)) != NULL) {
		TAILQ_REMOVE(&s->lines, line, entry);

		linfo("%s %s, line from %s/%s -> %s/%s seq %u: \"%s\"",
		    line->ts, line->id,
		    line->raddr, line->rport, line->laddr, line->lport,
		    line->seq, line->buf);

		server_store_line(s, line);

		(*line->dtor)(line);
		free(line->id);
		free(line);
	}
}

static void
listener_accept(int fd, short events, void *arg)
{
	struct listener *l = arg;
	struct conn *conn;
	int cfd;
	struct sockaddr_storage ss;
	socklen_t sslen = sizeof(ss);
	char host[NI_MAXHOST];
	char serv[NI_MAXSERV];
	int error;

	cfd = accept4(fd, (struct sockaddr *)&ss, &sslen, SOCK_NONBLOCK);
	if (cfd == -1) {
		lwarn("accept");
		return;
	}

	error = getnameinfo((struct sockaddr *)&ss, sslen,
	    host, sizeof(host), serv, sizeof(serv),
	    NI_NUMERICHOST|NI_NUMERICSERV);
	if (error != 0) {
		lwarnx("connection name lookup: %s", gai_strerror(error));
		close(cfd);
		return;
	}

	conn = malloc(sizeof(*conn));
	if (conn == NULL) {
		lwarn("%s port %s connection", host, serv);
		goto close;
	}

	conn->raddr = strdup(host);
	if (conn->raddr == NULL) {
		lwarn("%s port %s connection raddr", host, serv);
		goto free_conn;
	}

	conn->rport = strdup(serv);
	if (conn->rport == NULL) {
		lwarn("%s port %s connection rport", host, serv);
		goto free_raddr;
	}

	sslen = sizeof(ss);
	if (getsockname(cfd, (struct sockaddr *)&ss, &sslen) == -1)
		lerr(1, "connection getsockname");

	error = getnameinfo((struct sockaddr *)&ss, sslen,
	    host, sizeof(host), serv, sizeof(serv),
	    NI_NUMERICHOST|NI_NUMERICSERV);
	if (error != 0) {
		lwarnx("connection local name lookup: %s",
		    gai_strerror(error));
		goto free_rport;
	}

	conn->laddr = strdup(host);
	if (conn->laddr == NULL) {
		lwarn("%s port %s connection laddr", host, serv);
		goto free_rport;
	}

	conn->lport = strdup(serv);
	if (conn->lport == NULL) {
		lwarn("%s port %s connection lport", host, serv);
		goto free_laddr;
	}

	conn->buf = malloc(LINES_BUFLEN);
	if (conn->buf == NULL) {
		lwarn("%s port %s connection buffer", host, serv);
		goto free_lport;
	}
	conn->buflen = LINES_BUFLEN;

	conn->server = l->server;

	conn->state = S_PRE_LINE;
	conn->head = conn->tail = 0;
	conn->next = 0;

	refcnt_init(&conn->refs);
	conn->seq = 0;

	event_set(&conn->ev, cfd, EV_READ|EV_PERSIST, tcp_read, conn);
	event_add(&conn->ev, NULL);

	ldebug("connection from %s", conn->raddr);

	return;

free_lport:
	free(conn->lport);
free_laddr:
	free(conn->laddr);
free_rport:
	free(conn->rport);
free_raddr:
	free(conn->raddr);
free_conn:
	free(conn);
close:
	close(cfd);
}

static inline struct conn *
conn_ref(struct conn *conn)
{
	refcnt_take(&conn->refs);
	return (conn);
}

static void
conn_rele(struct conn *conn)
{
	if (!refcnt_rele(&conn->refs))
		return;

	free(conn->buf);
	free(conn->lport);
	free(conn->laddr);
	free(conn->rport);
	free(conn->raddr);
	free(conn);
}

static void
conn_close(struct conn *conn)
{
	event_del(&conn->ev);
	close(EVENT_FD(&conn->ev));

	conn_rele(conn);
}

static void
line_dtor_conn(struct line *line)
{
	conn_rele(line->cookie);
}

static int
line_parse_utf8(int ch)
{
	return ((ch & 0xc0) == 0x80);
}

static enum line_state
line_parse(struct conn *conn, int ch)
{
	enum line_state state = conn->state;

	/* whatever state we were in, a newline resets it */
	if (ch == '\n' || ch == '\0') {
		struct server *s = conn->server;
		struct line *line;
		unsigned int seq;
		size_t len;

		if (line_state_invalid(state))
			return (S_DEAD);
		
		len = conn->tail - conn->head;

		if (len == 0)
			goto reset;

		seq = conn->seq++;

		line = malloc(sizeof(*line) + len);
		if (line == NULL) {
			lwarn("unable to allocate %zu byte line from %s",
			    len, conn->raddr);
			goto reset;
		}

		line->laddr = conn->laddr;
		line->lport = conn->lport;
		line->raddr = conn->raddr;
		line->rport = conn->rport;
		line->seq = seq;
		timestamptz(line->ts, sizeof(line->ts), &conn->ts);
		line->id = id_gen();
		if (line->id == NULL) {
			lwarn("unable to generate id for line from %s",
			    conn->raddr);
			free(line);
			goto reset;
		}

		memcpy(line->buf, conn->buf + conn->head, len);
		line->buf[len] = '\0';

		line->cookie = conn_ref(conn);
		line->dtor = line_dtor_conn;

		TAILQ_INSERT_TAIL(&s->lines, line, entry);
		if (!evtimer_pending(&s->store, NULL))
			evtimer_add(&s->store, &store_timeval);

reset:
		conn->head = conn->tail = conn->next;
		return (S_PRE_LINE);
	}

	switch (state) {
	case S_PRE_LINE:
		if (isspace(ch)) {
			/* move the line forward */
			conn->head = conn->tail = conn->next;
			return (S_PRE_LINE);
		}

		if (clock_gettime(CLOCK_REALTIME, &conn->ts) == -1)
			lerr(1, "get time");

		/* FALLTHROUGH */
	case S_LINE:
		if (ch & 0x80) {
			/* start of utf8 sequence */
			switch (ch & 0xe0) {
			case 0xc0:
				return (S_UTF8_1);
			case 0xe0:
				switch (ch & 0xf0) {
				case 0xe0:
					return (S_UTF8_2);
				case 0xf0:
					switch (ch & 0xf8) {
					case 0xf0:
						return (S_UTF8_3);
						break;
					}
					break;
				}
				break;
			}

			/* invalid */
			return (S_DEAD);
		} else if (isspace(ch)) {
			;
		} else if (!isprint(ch)) {
			return (S_DEAD);
		} else {
			conn->tail = conn->next;
		}

		return (S_LINE);

	case S_UTF8_3:
	case S_UTF8_2:
		if (!line_parse_utf8(ch))
			return (S_DEAD);
		return (state + 1);

	case S_UTF8_1:
		if (!line_parse_utf8(ch))
			return (S_DEAD);

		conn->tail = conn->next;
		return (S_LINE);

	case S_DEAD:
		lwarnx("line parser called while state is S_DEAD");
		abort();
	}
}

static void
tcp_read(int cfd, short events, void *arg)
{
	struct conn *conn = arg;
	ssize_t rv;
	size_t len, i;

	rv = read(cfd, conn->buf + conn->next, conn->buflen - conn->next);
	switch (rv) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			/* try again later */
			break;
		default:
			lwarn("%s read", conn->raddr);
			break;
		}
		return;
	case 0:
		ldebug("connection from %s closed", conn->raddr);
		conn_close(conn);
		return;
	default:
		break;
	}

	len = rv;

	for (i = 0; i < len; i++) {
		enum line_state state;
		int ch = conn->buf[conn->next++];

		state = line_parse(conn, ch);
		if (state == S_DEAD) {
			lwarnx("invalid characters from %s, closing",
			    conn->raddr);
			conn_close(conn);
			return;
		}

		conn->state = state;
	}

	if (conn->head == conn->tail) {
		conn->next -= conn->tail;
		conn->head = conn->tail = 0;
	}
	if (conn->next == conn->buflen) {
		unsigned char *nbuf;

		if (conn->buflen >= LINES_BUFLEN_MAX) {
			lwarnx("line from %s is too long (%zu bytes), closing",
			    conn->raddr, conn->buflen);
			conn_close(conn);
			return;
		}

		conn->buflen *= 2;

		nbuf = realloc(conn->buf, conn->buflen);
		if (nbuf == NULL) {
			lwarn("unable to grow buffer to %zu bytes for %s, "
			    "closing", conn->buflen, conn->raddr);
			conn_close(conn);
			return;
		}

		conn->buf = nbuf;
	}
}

static void
timestamptz(char *dst, size_t dstlen, const struct timespec *ts)
{
	struct tm tm;
	int rv;

	if (localtime_r(&ts->tv_sec, &tm) == NULL)
		lerrx(1, "localtime");

	rv = snprintf(dst, dstlen,
	    "%04d-%02d-%02d %02d:%02d:%02d.%06ld%+02ld:%02ld",
	    1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec, ts->tv_nsec / 1000,
	    tm.tm_gmtoff / 3600, labs(tm.tm_gmtoff / 60) % 60);
	if (rv < 0)
		lerrx(1, "%s encoding error", __func__);

	if (dstlen <= (size_t)rv)
		lerrx(1, "%s dstlen %zu too short (%d)", __func__, dstlen, rv);
}

static char *
id_gen(void)
{
	uuid_t uuid;
	uint32_t status;
	char *id;

	uuid_create(&uuid, &status);
	if (status != uuid_s_ok)
		lerrx(1, "%s: uuid_create status=%u", __func__, status);

	uuid_to_string(&uuid, &id, &status);
	switch (status) {
	case uuid_s_ok:
		break;
	case uuid_s_no_memory:
		errno = ENOMEM;
		return (NULL);
	default:
		lerrx(1, "%s: uuid_to_string status=%u", __func__, status);
	}

	return (id);
}

static void
db_connect(struct server *s, const char *conn)
{
	PGresult *result;
	struct timespec ts;
	char tstz[TIMESTAMPTZ_LEN];
	char *id = id_gen();

	const char *values[INSERT_PARAMS] = {
		tstz, id, NULL,
		NULL, NULL, NULL, NULL, NULL,
		"testing line insert"
	};

	s->db = PQconnectdb(conn);
	if (s->db == NULL)
		errc(1, ENOMEM, "postgres connect");

	if (PQstatus(s->db) != CONNECTION_OK) {
		warnx("postgresql connection failed");
		fprintf(stderr, "%s", PQerrorMessage(s->db));
		exit(1);
	}

	result = PQprepare(s->db, insert_stmt, insert, INSERT_PARAMS, NULL);
	if (result == NULL)
		errc(1, ENOMEM, "prepare");
	if (PQresultStatus(result) != PGRES_COMMAND_OK) {
		fprintf(stderr, "%s", PQresultErrorMessage(result));
		exit(1);
	}
	PQclear(result);

	result = PQexec(s->db, "BEGIN");
	if (result == NULL)
		errc(1, ENOMEM, "db BEGIN");
	if (PQresultStatus(result) != PGRES_COMMAND_OK) {
		warnx("db BEGIN");
		fprintf(stderr, "%s", PQresultErrorMessage(result));
		exit(1);
	}
	PQclear(result);

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		err(1, "clock get time");
	timestamptz(tstz, sizeof(tstz), &ts);

	result = PQexecPrepared(s->db, insert_stmt, INSERT_PARAMS,
	    values, NULL, NULL, 0);
	if (result == NULL)
		errc(1, ENOMEM, "db exec %s", insert_stmt);
	if (PQresultStatus(result) != PGRES_COMMAND_OK) {
		warnx("db exec %s (%s %s): %s", insert_stmt, tstz, id,
		    PQresultErrorField(result, PG_DIAG_MESSAGE_PRIMARY));
		fprintf(stderr, "%s", PQresultErrorMessage(result));
		exit(1);
	}
	PQclear(result);

	free(id);

	result = PQexec(s->db, "ROLLBACK");
	if (result == NULL)
		errc(1, ENOMEM, "db ROLLBACK");
	if (PQresultStatus(result) != PGRES_COMMAND_OK) {
		warnx("db ROLLBACK");
		fprintf(stderr, "%s", PQresultErrorMessage(result));
		exit(1);
	}
	PQclear(result);

//	PQfinish(s->db);
}
