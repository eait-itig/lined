CFLAGS_PQ!=pkg-config --cflags libpq
LDFLAGS_PQ!=pkg-config --libs libpq

PROG=lined
SRCS=lines.c log.c
MAN=

CFLAGS+=	${CFLAGS_PQ}
LDFLAGS+=	${LDFLAGS_PQ}

LDADD+=		-levent
DPADD+=		${LIBEVENT}

WARNINGS=	Yes
DEBUG=		-g

.include <bsd.prog.mk>
