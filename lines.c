/*
 * Copyright (c) 2021 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This software was written by David Gwynne <dlg@uq.edu.au> for the
 * Faculty of Engineering, Architecture and Information Technology.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
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

#include <tls.h>
#include <event.h>
#include <libpq-fe.h>

#include "log.h"

#ifndef min
#define min(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#endif

static inline int
istrailer(int ch)
{
	return (ch == '\0' || isspace(ch));
}

#define LINES_USER		"_lined"
#define LINES_PORT_UDP		"601"
#define LINES_PORT_TCP		"601"
#define LINES_PORT_TLS		"syslog-tls"

#define LINES_BUFLEN		(1 << 10)
#define LINES_BUFLEN_MAX	(256 << 10)

struct refcnt {
	unsigned int refs;
};

enum syslog_state {
	S_IDLE,

	S_MSG_LEN,
	S_OCTETS,

	S_LINE,
	S_UTF8_3,
	S_UTF8_2,
	S_UTF8_1,

	S_DEAD,
};

enum db_state {
	SDB_RESET,
	SDB_PREPARE,
	SDB_PREPARING,
	SDB_IDLE,
	SDB_BEGIN,
	SDB_BEGINNING,
	SDB_QUERY,
	SDB_RESULT,
	SDB_COMMIT,
	SDB_COMMITTING
};

/*
 * 2021-07-30 16:45:00.123456+10:00
 *           1         2         3 32
 * 01234567890123456789012345678901
 */
#define TIMESTAMPTZ_LEN		33

static const char insert_stmt[] = "ins_stmt";
static const char insert[] = "INSERT INTO \"messages\" ("
	"\"saddr\", \"sport\", \"daddr\", \"dport\", "
	"\"conn\", \"seq\", "
	"\"ts\", \"id\", \"type\", "
	"\"msg\""
") VALUES ("
	"$1, $2, $3, $4, "
	"$5, $6, "
	"$7, $8, $9, $10"
")";

#define INSERT_PARAMS	10

static const char type_syslog[] = 	"syslog";

struct message {
	TAILQ_ENTRY(message)		 entry;

	void				(*dtor)(struct message *);
	void				*cookie;

	const char			*type;
	char				 ts[TIMESTAMPTZ_LEN];
	char				*id;

	char				*laddr;
	char				*lport;
	char				*raddr;
	char				*rport;
	char				*connid;
	unsigned int			 seq;

	size_t				 buflen;
	unsigned char			 buf[1]; /* must be last */

	/*
	 * this is followed by extra bytes that store the actual
	 * message. the one byte buf is used to account for a
	 * terminating '\0' if needed.
	 */
};

TAILQ_HEAD(messages, message);

#define MESSAGES_INITIALIZER(_msgs) TAILQ_HEAD_INITIALIZER(_msgs)

static inline int
messages_empty(struct messages *msgs)
{
	return (TAILQ_EMPTY(msgs));
}

static inline struct message *
messages_first(struct messages *msgs)
{
	return (TAILQ_FIRST(msgs));
}

static inline void
messages_remove(struct messages *msgs, struct message *msg)
{
	TAILQ_REMOVE(msgs, msg, entry);
}

static inline void
messages_insert_tail(struct messages *msgs, struct message *msg)
{
	TAILQ_INSERT_TAIL(msgs, msg, entry);
}

static const struct timeval messages_wait = { 1, 0 };
static const unsigned int messages_limit = 1000;

struct conn {
	struct server			*server;
	struct event			 rev;
	struct event			 wev;
	struct tls			*tls_ctx;

	struct refcnt			 refs;
	unsigned int			 seq;

	char				*id;
	char				*laddr;
	char				*lport;
	char				*raddr;
	char				*rport;

	/* state of the buffer */
	unsigned char			*buf;
	size_t				 buflen;

	/* state of the message */
	unsigned int			 state;
	struct timespec			 ts;
	size_t				 head;
	size_t				 tail;
	size_t				 next;
	size_t				 octets;
};

struct listener {
	TAILQ_ENTRY(listener)		 entry;
	struct server			*server;
	const char			*host;
	const char			*port;
	struct event			 ev;
};

TAILQ_HEAD(listeners, listener);

struct receiver {
	TAILQ_ENTRY(receiver)		 entry;
	struct server			*server;
	struct event			 ev;

	int				(*cmsg2dst)(struct sockaddr_storage *,
					    struct cmsghdr *);
};

TAILQ_HEAD(receivers, receiver);

enum tx_state {
	STX_IDLE,
	STX_BEGIN,
	STX_MSGS,
	STX_COMMIT,
};

struct transaction {
	TAILQ_ENTRY(transaction)	 entry;
	struct server			*server;
	struct messages			 messages;
	struct message			*message;
	enum tx_state			 state;
};

TAILQ_HEAD(transactions, transaction);

struct server {
	struct listeners		 listeners;
	struct listeners		 slisteners;
	struct receivers		 receivers;

	enum db_state			 db_state;
	PGconn				*db;
	struct event			 db_rev;
	struct event			 db_wev;

	struct messages			 messages;
	unsigned int			 messages_num;
	struct event			 messages_tmo;
	struct transactions		 transactions;
	struct transaction		*transaction;

	struct tls			*tls_ctx;
	struct tls_config		*tls_cfg;
};

static void	 listeners_bind(struct listeners *,
		     int, const char *, const char *);
static void	 receivers_bind(struct server *s, int,
		     const char *, const char *);
static void	 server_listen(struct server *s);
static void	 server_slisten(struct server *s);
static void	 server_receive(struct server *s);

static void	 listener_accept(struct listener *, int, int);
static void	 listener_accept_ev(int, short, void *);
static void	 slistener_accept_ev(int, short, void *);

static void	 syslog_recv(int, short, void *);
static int	 receiver_dst4(struct sockaddr_storage *, struct cmsghdr *);
static int	 receiver_dst6(struct sockaddr_storage *, struct cmsghdr *);

static void	 syslog_read(int, short, void *);
static void	 syslog_tls_io(int, short, void *);
static void	 syslog_input(struct conn *, size_t);

static void	 db_connect(struct server *, const char *);
static void	 db_read(int, short, void *);
static void	 db_write(int, short, void *);

static char	*id_gen(void);
static void	 timestamptz(char *, size_t, const struct timespec *)
		     __attribute__ ((__bounded__(__buffer__,1,2)));

static void	 message_store(struct server *, struct message *);
static void	 message_free(struct message *);
static void	 messages_push(int, short, void *);

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

	fprintf(stderr, "usage: %s [-46d] [-A CA_path] [-a CA_file] "
	    "[-c cert_file] [-k key_file]\n"
	    "\t[-l address] [-S tls_port] [-T tcp_port] [-U udp_port]\n"
	    "\t[-u user]\n", __progname);

	exit(1);
}

static void
gcore(void)
{
	pid_t p;

	p = fork();
	switch (p) {
	case -1:
		lwarn("gcore fork"); /* XXX */
		return;
	case 0: /* child */
		/* crash */
		abort();
		/* NOTREACHED */
	default:
		return;
	}
}

int debug = 0;

static const char *
lines_port_opt(const char *arg)
{
	if (strcmp(arg, "-") == 0)
		return (NULL);

	return (arg);
}

int
main(int argc, char *argv[])
{
	struct server server = {
		.listeners = TAILQ_HEAD_INITIALIZER(server.listeners),
		.slisteners = TAILQ_HEAD_INITIALIZER(server.slisteners),
		.receivers = TAILQ_HEAD_INITIALIZER(server.receivers),
		.messages = MESSAGES_INITIALIZER(server.messages),
		.transactions = TAILQ_HEAD_INITIALIZER(server.transactions),
	};
	struct server *s = &server;

	int family = AF_UNSPEC;
	const char *host = NULL;
	const char *port_udp = LINES_PORT_UDP;
	const char *port_tcp = LINES_PORT_TCP;
	const char *port_tls = LINES_PORT_TLS;

	const char *user = LINES_USER;
	const char *conn = "";

	const char *crt = NULL;
	const char *key = NULL;

	const char *catype = NULL;
	const char *capath = NULL;
	int (*cafunc)(struct tls_config *, const char *) = NULL;

	int ch;

	struct passwd *pw;

	while ((ch = getopt(argc, argv, "46A:a:c:dk:l:p:S:T:U:u:")) != -1) {
		switch (ch) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'A':
			catype = "path";
			capath = optarg;
			cafunc = tls_config_set_ca_path;
			break;
		case 'a':
			catype = "file";
			capath = optarg;
			cafunc = tls_config_set_ca_file;
			break;
		case 'c':
			crt = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'k':
			key = optarg;
			break;
		case 'l':
			host = optarg;
			break;
		case 'p':
			conn = optarg;
			break;
		case 'S':
			port_tls = lines_port_opt(optarg);
			break;
		case 'T':
			port_tcp = lines_port_opt(optarg);
			break;
		case 'U':
			port_udp = lines_port_opt(optarg);
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

	if ((crt == NULL) != (key == NULL)) {
		warnx("key and certificate must be configured together");
		usage();
	}

	if (geteuid() != 0)
		errx(1, "need root privileges");

	pw = getpwnam(user);
	if (pw == NULL)
		errx(1, "no %s user", user);

	if (chdir(pw->pw_dir) == -1)
		err(1, "%s", pw->pw_dir);

	if (port_udp != NULL)
		receivers_bind(s, family, host, port_udp);
	if (port_tcp != NULL)
		listeners_bind(&s->listeners, family, host, port_tcp);

	if (crt != NULL) {
		if (port_tls == NULL)
			errx(1, "TLS configured but listener disabled");

		listeners_bind(&s->slisteners, family, host, port_tls);

		if (tls_init() == -1)
 			errx(1, "tls init failed");

		s->tls_cfg = tls_config_new();
		if (s->tls_cfg == NULL)
			errx(1, "tls server configuration creation failed");

		if (tls_config_set_cert_file(s->tls_cfg, crt) == -1) {
			errx(1, "TLS certificate: %s",
			    tls_config_error(s->tls_cfg));
		}

		if (tls_config_set_key_file(s->tls_cfg, key) == -1) {
			errx(1, "TLS key: %s",
			    tls_config_error(s->tls_cfg));
		}

		if (capath != NULL) {
			if ((*cafunc)(s->tls_cfg, capath) == -1) {
				errx(1, "CA %s: %s", catype,
				    tls_config_error(s->tls_cfg));
			}
			tls_config_verify_client(s->tls_cfg);
		} else {
			warnx("TLS client certificate verification "
			    "is not configured");
		}

		s->tls_ctx = tls_server();
		if (s->tls_ctx == NULL)
			errx(1, "tls server context creation failed");

		if (tls_configure(s->tls_ctx, s->tls_cfg) != 0)
			errx(1, "TLS server configuration: %s",
			    tls_error(s->tls_ctx));
	}

	if (TAILQ_EMPTY(&s->receivers) &&
	    TAILQ_EMPTY(&s->listeners) &&
	    TAILQ_EMPTY(&s->slisteners))
		errx(1, "no protocols enabled");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		errx(1, "can't drop privileges");

	pw = NULL;
	endpwent();

	db_connect(s, conn);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN); /* gcore help */

	if (!debug) {
		extern char *__progname;

		if (daemon(1, 0) == -1)
			err(1, "daemon");

		logger_syslog(__progname);
	}

	event_init();

	event_set(&s->db_rev, PQsocket(s->db), EV_READ|EV_PERSIST,
	    db_read, s);
	event_set(&s->db_wev, PQsocket(s->db), EV_WRITE,
	    db_write, s);

	evtimer_set(&s->messages_tmo, messages_push, s);

	s->db_state = SDB_IDLE;
	event_add(&s->db_rev, 0);

	server_listen(s);
	server_slisten(s);
	server_receive(s);

	event_dispatch();

	return (0);
}

static void
listeners_bind(struct listeners *list,
    int af, const char *host, const char *port)
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
		errx(1, "listener %s port %s: %s",
		    host ? host : "*", port, gai_strerror(error));
	}

	for (res = res0; res != NULL; res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK,
		    res->ai_protocol);
		if (fd == -1) {
			serrno = errno;
			cause = "socket";
			continue;
		}

		reuse = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		    &reuse, sizeof(reuse)) == -1) {
			warn("listener %s port %s enable reuse addr",
			    host ? host : "*", port);
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

		l = malloc(sizeof(*l));
		if (l == NULL)
			err(1, "listener alloc");

		event_set(&l->ev, fd, 0, NULL, NULL);
		TAILQ_INSERT_TAIL(&listeners, l, entry);
	}

	if (TAILQ_EMPTY(&listeners)) {
		errc(1, serrno, "listener %s port %s %s",
		    host ? host : "*", port, cause);
	}

	TAILQ_CONCAT(list, &listeners, entry);
}

static void
receivers_bind(struct server *s, int af, const char *host, const char *port)
{
	struct receivers receivers = TAILQ_HEAD_INITIALIZER(receivers);
	struct receiver *r;
	int (*cmsg2dst)(struct sockaddr_storage *, struct cmsghdr *);

	struct addrinfo hints, *res, *res0;
	int error;
	int serrno;
	const char *cause;
	int fd;
	int on;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(host, port, &hints, &res0);
	if (error != 0) {
		errx(1, "receiver %s port %s: %s",
		    host ? host : "*", port,
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

		on = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		    &on, sizeof(on)) == -1) {
			warn("receiver %s port %s enable reuse addr",
			    host ? host : "*", port);
                }

		if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
			serrno = errno;
			cause = "bind";
			close(fd);
			continue;
		}

		switch (res->ai_family) {
		case AF_INET:
			cmsg2dst = receiver_dst4;

			on = 1;
			if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR,
			    &on, sizeof(on)) == -1)
				err(1, "setsockopt(IP_RECVDSTADDR)");
			on = 1;
			if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTPORT,
			    &on, sizeof(on)) == -1)
				err(1, "setsockopt(IP_RECVDSTPORT)");
			break;
		case AF_INET6:
			cmsg2dst = receiver_dst6;

			on = 1;
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
			    &on, sizeof(on)) == -1)
				err(1, "setsockopt(IPV6_RECVPKTINFO)");
			on = 1;
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVDSTPORT,
			    &on, sizeof(on)) == -1)
				err(1, "setsockopt(IPV6_RECVDSTPORT)");
			break;
		}

		r = malloc(sizeof(*r));
		if (r == NULL)
			err(1, "receiver alloc");

		r->cmsg2dst = cmsg2dst;
		event_set(&r->ev, fd, 0, NULL, NULL);
		TAILQ_INSERT_TAIL(&receivers, r, entry);
	}

	if (TAILQ_EMPTY(&receivers)) {
		errc(1, serrno, "receiver %s port %s %s",
		    host ? host : "*", port, cause);
	}

	TAILQ_CONCAT(&s->receivers, &receivers, entry);
}

static void
server_listen(struct server *s)
{
	struct listener *l;

	TAILQ_FOREACH(l, &s->listeners, entry) {
		l->server = s;
		event_set(&l->ev, EVENT_FD(&l->ev), EV_READ|EV_PERSIST,
		    listener_accept_ev, l);
		event_add(&l->ev, NULL);
	}
}

static void
server_slisten(struct server *s)
{
	struct listener *l;

	TAILQ_FOREACH(l, &s->slisteners, entry) {
		l->server = s;
		event_set(&l->ev, EVENT_FD(&l->ev), EV_READ|EV_PERSIST,
		    slistener_accept_ev, l);
		event_add(&l->ev, NULL);
	}
}

static void
server_receive(struct server *s)
{
	struct receiver *r;

	TAILQ_FOREACH(r, &s->receivers, entry) {
		r->server = s;
		event_set(&r->ev, EVENT_FD(&r->ev), EV_READ|EV_PERSIST,
		    syslog_recv, r);
		event_add(&r->ev, NULL);
	}
}

static void
db_send_query(struct server *s, const char *query)
{
	assert(s->db_state == SDB_IDLE);

	if (!PQsendQuery(s->db, query))
		lerrx(ENOMEM, "DB send %s: %s", query, PQerrorMessage(s->db));

	s->db_state = SDB_QUERY;

	/* try and push the query out quickly */
	db_write(PQsocket(s->db), EV_WRITE, s);
}

static void
db_send_message(struct transaction *t)
{
	struct server *s = t->server;
	struct message *msg = t->message;
	char seq[32];
	int rv;

	const char *values[INSERT_PARAMS] = {
		msg->raddr, msg->rport, msg->laddr, msg->lport,
		msg->connid, seq,
		msg->ts, msg->id, type_syslog, msg->buf
	};
	int lengths[INSERT_PARAMS] = {
		0, 0, 0, 0,
		0, 0,
		0, 0, 0, 1,
	};
	int formats[INSERT_PARAMS] = {
		0, 0, 0, 0,
		0, 0,
		0, 0, 0, (int)msg->buflen,
	};

	assert(s->db_state == SDB_IDLE);

	if (msg->connid != NULL) {
		rv = snprintf(seq, sizeof(seq), "%lld", (long long)msg->seq);
		if (rv < 0)
			lerrx(1, "%s: seq encoding error", __func__);
		if ((size_t)rv >= sizeof(seq))
			lerrx(1, "%s: seq buffer too small", __func__);
	} else
		values[5] = NULL;

	if (0) {
		ldebug("%s %s: %s/%s -> %s/%s: \"%s\"",
		    msg->ts, msg->id,
		    msg->raddr, msg->rport, msg->laddr, msg->lport,
		    msg->buf);
	}

	if (!PQsendQueryPrepared(s->db, insert_stmt, INSERT_PARAMS,
	    values, formats, lengths, 0))
		lerrx(ENOMEM, "DB send query: %s", PQerrorMessage(s->db));

	s->db_state = SDB_QUERY;

	/* try and push the query out quickly */
	db_write(PQsocket(s->db), EV_WRITE, s);
}

static void
db_send_transaction(struct server *s)
{
	struct transaction *t = s->transaction;

	assert(s->db_state == SDB_IDLE);
	assert(t->message == NULL);
	assert(t->state == STX_IDLE);

	t->state = STX_BEGIN;
	db_send_query(s, "BEGIN");
}

static void
message_store(struct server *s, struct message *msg)
{
	unsigned int n;

	messages_insert_tail(&s->messages, msg);
	n = ++s->messages_num;

	if (n == 1) {
#if 0
		ldebug("scheduling transaction");
#endif
		evtimer_add(&s->messages_tmo, &messages_wait);
	} else if (n >= messages_limit) {
#if 0
		ldebug("message limit %u hit", messages_limit);
#endif
		evtimer_del(&s->messages_tmo);
		messages_push(0, 0, s);
	}
}

static void
messages_free(struct messages *msgs)
{
	struct message *msg, *nmsg;

	TAILQ_FOREACH_SAFE(msg, msgs, entry, nmsg) {
		messages_remove(msgs, msg);
		message_free(msg);
	}
}

static void
db_push(struct server *s)
{
	if (s->transaction == NULL) {
		struct transaction *t = TAILQ_FIRST(&s->transactions);
		assert(t != NULL);
		assert(!messages_empty(&t->messages));

		TAILQ_REMOVE(&s->transactions, t, entry);
		s->transaction = t;
	}

	if (s->db_state == SDB_IDLE)
		db_send_transaction(s);
}

static void
messages_push(int nil, short events, void *arg)
{
	struct server *s = arg;
	struct transaction *t;

	t = malloc(sizeof(*t));
	if (t == NULL) {
		messages_free(&s->messages);

		lwarn("unable to allocate transaction, dropping %u %s",
		    s->messages_num,
		    s->messages_num == 1 ? "message" : "messages");

		TAILQ_INIT(&s->messages); /* this should be a nop */
		s->messages_num = 0;

		return;
	}

#if 0
	ldebug("pushing transaction for %u %s",
	    s->messages_num,
	    s->messages_num == 1 ? "message" : "messages");
#endif

	t->server = s;
	TAILQ_INIT(&t->messages);
	t->message = NULL;
	t->state = STX_IDLE;

	TAILQ_CONCAT(&t->messages, &s->messages, entry);

	TAILQ_INIT(&s->messages);
	s->messages_num = 0;

	TAILQ_INSERT_TAIL(&s->transactions, t, entry);
	db_push(s);
}

static void
listener_accept_ev(int fd, short events, void *arg)
{
	listener_accept(arg, fd, 0);
}

static void
slistener_accept_ev(int fd, short events, void *arg)
{
	listener_accept(arg, fd, 1);
}

static void
listener_accept(struct listener *l, int fd, int tls)
{
	struct conn *conn;
	int cfd;
	struct sockaddr_storage ss;
	socklen_t sslen = sizeof(ss);
	char host[NI_MAXHOST];
	char serv[NI_MAXSERV];
	int error;

	cfd = accept4(fd, (struct sockaddr *)&ss, &sslen, SOCK_NONBLOCK);
	if (cfd == -1) {
		switch (errno) {
		case EINTR:
		case EAGAIN:
			break;
		default:
			lwarn("accept");
			break;
		}
		return;
	}

	error = getnameinfo((struct sockaddr *)&ss, sslen,
	    host, sizeof(host), serv, sizeof(serv),
	    NI_NUMERICHOST|NI_NUMERICSERV);
	if (error != 0) {
		lwarnx("connection name lookup: %s", gai_strerror(error));
		goto close;
	}

	conn = malloc(sizeof(*conn));
	if (conn == NULL) {
		lwarn("%s port %s connection", host, serv);
		goto close;
	}

	conn->id = id_gen();
	if (conn->id == NULL) {
		lwarn("%s port %s connection id", host, serv);
		goto free_conn;
	}

	conn->raddr = strdup(host);
	if (conn->raddr == NULL) {
		lwarn("%s port %s connection raddr", host, serv);
		goto free_id;
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

	conn->state = S_IDLE;
	conn->head = conn->tail = 0;
	conn->next = 0;

	refcnt_init(&conn->refs);
	conn->seq = 0;

	if (tls) {
		struct tls *ctx = conn->server->tls_ctx;

		if (tls_accept_socket(ctx, &conn->tls_ctx, cfd) == -1) {
			lwarnx("%s port %s TLS accept: %s", host, serv,
			    tls_error(ctx));
			goto free_buf;
		}

		event_set(&conn->wev, cfd, EV_WRITE,
		    syslog_tls_io, conn);
		event_set(&conn->rev, cfd, EV_READ|EV_PERSIST,
		    syslog_tls_io, conn);
		event_add(&conn->rev, NULL);

		linfo("TLS connection from %s to %s",
		    conn->raddr, conn->laddr);

		syslog_tls_io(cfd, EV_READ, conn);
	} else {
		conn->tls_ctx = NULL;
		event_set(&conn->rev, cfd, EV_READ|EV_PERSIST,
		    syslog_read, conn);
		event_add(&conn->rev, NULL);

		linfo("connection from %s to %s",
		    conn->raddr, conn->laddr);
	}

	return;

free_buf:
	free(conn->buf);
free_lport:
	free(conn->lport);
free_laddr:
	free(conn->laddr);
free_rport:
	free(conn->rport);
free_raddr:
	free(conn->raddr);
free_id:
	free(conn->id);
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
	free(conn->id);
	free(conn);
}

static void
conn_close(struct conn *conn)
{
	event_del(&conn->rev);
	if (conn->tls_ctx != NULL) {
		event_del(&conn->wev);
		tls_free(conn->tls_ctx);
	}
	close(EVENT_FD(&conn->rev));

	conn_rele(conn);
}

static void
message_dtor_conn(struct message *msg)
{
	conn_rele(msg->cookie);
}

static int
line_parse_utf8(int ch)
{
	return ((ch & 0xc0) == 0x80);
}

static void
message_queue(struct conn *conn)
{
	struct server *s = conn->server;
	struct message *msg;
	unsigned int seq;
	size_t len;

	len = conn->tail - conn->head;
	if (len == 0)
		goto reset;

	seq = conn->seq++;

	msg = malloc(sizeof(*msg) + len);
	if (msg == NULL) {
		lwarn("unable to allocate %zu bytes for message from %s",
		    len, conn->raddr);
		goto reset;
	}

	msg->laddr = conn->laddr;
	msg->lport = conn->lport;
	msg->raddr = conn->raddr;
	msg->rport = conn->rport;
	msg->connid = conn->id;
	msg->seq = seq;
	timestamptz(msg->ts, sizeof(msg->ts), &conn->ts);
	msg->id = id_gen();
	if (msg->id == NULL) {
		lwarn("unable to generate id for message from %s",
		    conn->raddr);
		free(msg);
		goto reset;
	}

	memcpy(msg->buf, conn->buf + conn->head, len);
	msg->buf[len] = '\0';
	msg->buflen = len;

	msg->cookie = conn_ref(conn);
	msg->dtor = message_dtor_conn;

	message_store(s, msg);

reset:
	conn->head = conn->tail = conn->next;
}

static enum syslog_state
syslog_parse(struct conn *conn, enum syslog_state state, int ch)
{
	switch (state) {
	case S_IDLE:
		if (ch == '<') {
			/* Non-Transparent-Framing */
			state = S_LINE;
		} else if (isdigit(ch)) {
			conn->octets = ch - '0';
			state = S_MSG_LEN;
		} else
			return (S_DEAD);

		if (clock_gettime(CLOCK_REALTIME, &conn->ts) == -1)
			lerr(1, "get time");

		return (state);

	case S_MSG_LEN:
		if (ch == ' ') {
			conn->head = conn->tail = conn->next;
			state = S_OCTETS;
		} else if (isdigit(ch)) {
			conn->octets *= 10;
			conn->octets += ch - '0';
			if (conn->octets > LINES_BUFLEN_MAX)
				return (S_DEAD);
		} else
			return (S_DEAD);

		return (state);

	case S_OCTETS:
		lwarnx("syslog parser called while state is S_OCTETS");
		abort();
		/* NOTREACHED */

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
		} else if (ch == '\n' || ch == '\0') {
			message_queue(conn);
			state = S_IDLE;
		} else if (isspace(ch)) {
			;
		} else if (!isprint(ch)) {
			return (S_DEAD);
		} else {
			conn->tail = conn->next;
		}

		return (state);

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
		lwarnx("syslog parser called while state is S_DEAD");
		abort();
	}
}

static void
syslog_read(int cfd, short events, void *arg)
{
	struct conn *conn = arg;
	ssize_t rv;

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
		linfo("connection from %s closed", conn->raddr);
		conn_close(conn);
		return;
	default:
		break;
	}

	syslog_input(conn, rv);
}

static void
syslog_tls_io(int cfd, short events, void *arg)
{
	struct conn *conn = arg;
	ssize_t rv;

	rv = tls_read(conn->tls_ctx, conn->buf + conn->next,
	    conn->buflen - conn->next);
	switch (rv) {
	case TLS_WANT_POLLIN:
		/* just wait for the next conn->rev to fire */
		return;
	case TLS_WANT_POLLOUT:
		event_add(&conn->wev, NULL);
		return;

	case -1:
		lwarnx("%s tls io: %s", conn->raddr, tls_error(conn->tls_ctx));
		conn_close(conn);
		return;
	case 0:
		linfo("TLS connection from %s closed", conn->raddr);
		conn_close(conn);
		return;
	default:
		break;
	}

	syslog_input(conn, rv);
}

static void
syslog_input(struct conn *conn, size_t len)
{
	enum syslog_state state;

	state = conn->state;
	do {
		size_t octets;
		int ch;

		switch (state) {
		case S_OCTETS:
			octets = min(conn->octets, len);
			conn->tail += octets;
			conn->next += octets;

			conn->octets -= octets;
			if (conn->octets == 0) {
				/* trim trailing whitespace */
				size_t tail = conn->tail;
				while (tail > conn->head) {
					tail--;
					ch = conn->buf[tail];
					if (!istrailer(ch))
						break;
					conn->tail = tail;
				}
				message_queue(conn);
				conn->head = conn->tail = conn->next;
				state = S_IDLE;
			}

			len -= octets;
			break;

		default:
			ch = conn->buf[conn->next++];
			state = syslog_parse(conn, state, ch);
			if (state == S_DEAD) {
				lwarnx("invalid line from %s, closing",
				    conn->raddr);
				conn_close(conn);
				return;
			}

			len--;
			break;
		}

		conn->state = state;
	} while (len > 0);

	if (conn->head == conn->tail) {
		conn->next -= conn->tail;
		conn->head = conn->tail = 0;
	}
	if (conn->next == conn->buflen) {
		unsigned char *nbuf;

		if (conn->head > 0) {
			memmove(conn->buf, conn->buf + conn->head,
			    conn->next - conn->head);
			conn->next -= conn->head;
			conn->tail -= conn->head;
			conn->head = 0;

			return;
		}

		if (conn->buflen >= LINES_BUFLEN_MAX) {

			lwarnx("line from %s is too long (%zu bytes), closing",
			    conn->raddr, conn->buflen);
			gcore();
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

static int
receiver_dst4(struct sockaddr_storage *ss, struct cmsghdr *cmsg)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

	if (cmsg->cmsg_level != IPPROTO_IP)
		return (0);

	switch (cmsg->cmsg_type) {
	case IP_RECVDSTADDR:
		memcpy(&sin->sin_addr, CMSG_DATA(cmsg), sizeof(sin->sin_addr));
		if (sin->sin_addr.s_addr == INADDR_BROADCAST)
			return (-1);
		break;

        case IP_RECVDSTPORT:
                memcpy(&sin->sin_port, CMSG_DATA(cmsg), sizeof(sin->sin_port));
                break;
        }

	return (0);
}

static int
receiver_dst6(struct sockaddr_storage *ss, struct cmsghdr *cmsg)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	struct in6_pktinfo *ipi = (struct in6_pktinfo *)CMSG_DATA(cmsg);

	if (cmsg->cmsg_level != IPPROTO_IPV6)
                return (0);

	switch (cmsg->cmsg_type) {
	case IPV6_PKTINFO:
		memcpy(&sin6->sin6_addr, &ipi->ipi6_addr,
		    sizeof(sin6->sin6_addr));
#ifdef __KAME__
		if (IN6_IS_ADDR_LINKLOCAL(&ipi->ipi6_addr))
			sin6->sin6_scope_id = ipi->ipi6_ifindex;
#endif
		break;
	case IPV6_RECVDSTPORT:
		memcpy(&sin6->sin6_port, CMSG_DATA(cmsg),
		    sizeof(sin6->sin6_port));
		break;
	}

	return (0);
}

static void
message_dtor_recv(struct message *msg)
{
	free(msg->lport);
	free(msg->laddr);
	free(msg->rport);
	free(msg->raddr);
}

static void
syslog_recv(int fd, short events, void *arg)
{
	struct receiver *r = arg;
	struct server *s = r->server;
	struct message *msg;

	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(struct sockaddr_storage)) +
		    CMSG_SPACE(sizeof(in_port_t))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct msghdr msghdr;
	struct iovec iov;
	ssize_t rv;

	unsigned char buf[4096];
	struct sockaddr_storage src, dst;
	size_t len, tail;
	struct timespec ts;
	char host[NI_MAXHOST];
	char serv[NI_MAXSERV];
	int error;

	memset(&msghdr, 0, sizeof(msghdr));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msghdr.msg_name = &src;
	msghdr.msg_namelen = sizeof(src);
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;
	msghdr.msg_control = &cmsgbuf.buf;
	msghdr.msg_controllen = sizeof(cmsgbuf.buf);

	rv = recvmsg(fd, &msghdr, 0);
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			break;
		default:
			lwarn("%s", __func__);
			break;
		}
		return;
	}

	memset(&dst, 0, sizeof(dst));
	dst.ss_family = src.ss_family;
	dst.ss_len = src.ss_len;

	/* get local address if possible */
	for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
		if (r->cmsg2dst(&dst, cmsg) == -1)
			return;
	}

	len = (size_t)rv;

	/* trim trailing whitespace */
	tail = len;
	while (tail > 0) {
		int ch;

		tail--;
		ch = buf[tail];
		if (!istrailer(ch))
			break;
		len = tail;
	}

	if (len == 0)
		return;

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		lerr(1, "get time");

	error = getnameinfo((struct sockaddr *)&src, msghdr.msg_namelen,
	    host, sizeof(host), serv, sizeof(serv),
	    NI_NUMERICHOST|NI_NUMERICSERV);
	if (error != 0) {
		lwarnx("%s src name lookup: %s", __func__,
		    gai_strerror(error));
		return;
	}

	msg = malloc(sizeof(*msg) + len);
	if (msg == NULL) {
		lwarn("unable to allocate %zu bytes for message from %s",
		    len, host);
		return;
	}

	memset(msg, 0, sizeof(*msg));

	msg->raddr = strdup(host);
	if (msg->raddr == NULL)
		goto free_msg;
	msg->rport = strdup(serv);
	if (msg->rport == NULL)
		goto free_raddr;

	error = getnameinfo((struct sockaddr *)&dst, msghdr.msg_namelen,
	    host, sizeof(host), serv, sizeof(serv),
	    NI_NUMERICHOST|NI_NUMERICSERV);
	if (error != 0) {
		lwarnx("%s dst name lookup: %s", __func__,
		    gai_strerror(error));
		goto free_rport;
	}

	msg->laddr = strdup(host);
	if (msg->laddr == NULL)
		goto free_rport;
	msg->lport = strdup(serv);
	if (msg->lport == NULL)
		goto free_laddr;

	msg->connid = NULL;
	msg->seq = 0;

	timestamptz(msg->ts, sizeof(msg->ts), &ts);
	msg->id = id_gen();
	if (msg->id == NULL) {
		lwarn("unable to generate id for message from %s",
		    msg->raddr);
		goto free_lport;
	}

	memcpy(msg->buf, buf, len);
	msg->buf[len] = '\0';
	msg->buflen = len;

	msg->cookie = NULL;
	msg->dtor = message_dtor_recv;

	message_store(s, msg);

	return;

free_lport:
	free(msg->lport);
free_laddr:
	free(msg->laddr);
free_rport:
	free(msg->rport);
free_raddr:
	free(msg->raddr);
free_msg:
	free(msg);
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
	int on;

	const char *values[INSERT_PARAMS] = {
		NULL, NULL, NULL, NULL, NULL, NULL,
		tstz, id, NULL,
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

	if (PQsetnonblocking(s->db, 1) != 0)
		errx(1, "unable to set db non-blocking");

	on = 1;
	if (ioctl(PQsocket(s->db), FIONBIO, &on, sizeof(on)) == -1)
		err(1, "set db socket non-blocking");
}

static void
message_free(struct message *msg)
{
	(*msg->dtor)(msg);
	free(msg->id);
	free(msg);
}

static void
db_read(int fd, short events, void *arg)
{
	struct server *s = arg;
	struct transaction *t;
	struct message *msg;
	PGresult *r;

	if (!PQconsumeInput(s->db)) {
		/* there was some kind of trouble */
		lerrx(1, "DB consume failed: %s", PQerrorMessage(s->db));
	}

	if (PQisBusy(s->db)) {
		/* wait for more data */
		return;
	}

	while ((r = PQgetResult(s->db)) != NULL) {
		assert(s->db_state == SDB_QUERY);

		if (PQresultStatus(r) != PGRES_COMMAND_OK) {
			lwarnx("db %s result: %s", insert_stmt,
			    PQresultErrorField(r, PG_DIAG_MESSAGE_PRIMARY));
		}
		PQclear(r);
	}
	s->db_state = SDB_IDLE;

	t = s->transaction;

	switch (t->state) {
	case STX_IDLE:
		lwarnx("unexpected IDLE state in transaction");
		abort();
		/* NOTREACHED */

	case STX_BEGIN:
		msg = messages_first(&t->messages);
		assert(msg != NULL);
		t->state = STX_MSGS;
		break;

	case STX_MSGS:
		msg = TAILQ_NEXT(t->message, entry);
		if (msg == NULL) {
			t->message = NULL;
			t->state = STX_COMMIT;
			db_send_query(s, "COMMIT");
			return;
		}

		/* else move onto the next message */
		break;

	case STX_COMMIT:
		/* transaction is complete */
		s->transaction = NULL;

		messages_free(&t->messages);
		free(t);

		if (!TAILQ_EMPTY(&s->transactions))
			db_push(s);
		return;
	}

	t->message = msg;
	assert(t->state == STX_MSGS);
	db_send_message(t);
}

static void
db_write(int fd, short events, void *arg)
{
	struct server *s = arg;
	int rv;

	rv = PQflush(s->db);
	switch (rv) {
	case 0:
		/*
		 * Once PQflush returns 0, wait for the socket to
		 * be read-ready and then read the response as described
		 * above.
		 */

		/* s->db_rev is EV_PERSISTENT */
		break;
	case 1:
		/*
		 * If it returns 1, wait for the socket to become
		 * read- or write-ready. If it becomes write-ready,
		 * call PQflush again.
		 */
		event_add(&s->db_wev, NULL);
		break;
	case -1: /* it failed for some reason */
		lerrx(1, "DB flush failed: %s", PQerrorMessage(s->db));
		/* NOTREACHED */
	}
}
