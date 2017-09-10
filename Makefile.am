
bin_PROGRAMS = mitm_ssl

mitm_ssl_SOURCES = \
	src/main.c\
	src/server.c\
	src/client-impl.c\
	src/filter-string.c

mitm_ssl_CFLAGS = \
	${ssl_CLAGS}\
	${PTHREAD_CFLAGS}
mitm_ssl_LDADD = \
	${ssl_LIBS}\
	${PTHREAD_LIBS}\
	-ldl
