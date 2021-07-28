#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>

#include <event.h>
#include <libpq-fe.h>

#include "log.h"

#define LINES_USER	"_lines"
#define LINES_PORT	"601"

struct listener {
	TAILQ_ENTRY(listener)		 entry;
	const char			*host;
	const char			*port;
	struct event			 ev;
};

TAILQ_HEAD(listeners, listener);

struct server {
	struct listeners		 listeners;
};

static void	server_bind(struct server *s, int,
		    const char *, const char *);
static void	server_listen(struct server *s);

static void	listener_accept(int, short, void *);

static void	db_connect(struct server *, const char *);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-d] [-u user]\n", __progname);

	exit(1);
}

int debug = 0;

int
main(int argc, char *argv[])
{
	struct server server = {
		.listeners = TAILQ_HEAD_INITIALIZER(server.listeners),
	};
	struct server *s = &server;

	const char *user = LINES_USER;
	const char *conn = "";

	int ch;

	struct passwd *pw;

	while ((ch = getopt(argc, argv, "du:")) != -1) {
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

	if (!debug && daemon(1, 1) == -1)
		err(1, "daemon");

	event_init();

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
		event_set(&l->ev, EVENT_FD(&l->ev), EV_READ|EV_PERSIST,
		    listener_accept, l);
		event_add(&l->ev, NULL);
	}
}

static void
listener_accept(int fd, short events, void *arg)
{
	//struct listener *l = arg;
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

	close(cfd);

	error = getnameinfo((struct sockaddr *)&ss, sslen,
	    host, sizeof(host), serv, sizeof(serv),
	    NI_NUMERICHOST|NI_NUMERICSERV);
	if (error != 0) {
		lwarnx("accept name: %s", gai_strerror(error));
		return;
	}

	linfo("connection from %s port %s", host, serv);
}

static void
db_connect(struct server *s, const char *conn)
{
	PGconn *db;

	db = PQconnectdb(conn);
	if (db == NULL)
		errc(1, ENOMEM, "postgres connect");

	if (PQstatus(db) != CONNECTION_OK) {
		warnx("postgresql connection failed");
		fprintf(stderr, "%s", PQerrorMessage(db));
	}

	PQfinish(db);
}
