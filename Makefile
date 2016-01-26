PROG=	mountd
SRCS=	parser.c network.c tree.c
MAN=

CFLAGS=	-O0 -g
CFLAGS+= -fblocks

LDADD+= -lBlocksRuntime

.include <bsd.prog.mk>
