PROG=	mountd
SRCS=	main.c parser.c network.c tree.c
SRCS+=	mount.c rpc.c
MAN=

CFLAGS=	-O0 -g
CFLAGS+= -fblocks

LDADD+= -lBlocksRuntime

.include <bsd.prog.mk>
