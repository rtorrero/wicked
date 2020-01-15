
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_sbin_PROGRAMS		= wickedd-useless

wickedd_useless_CPPFLAGS		= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wickedd_useless_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)	\
				  $(LIBSYSTEMD_CFLAGS)

wickedd_useless_LDFLAGS		= -rdynamic		\
				  $(LIBSYSTEMD_LIBS)
wickedd_useless_LDADD		= $(top_builddir)/src/libwicked.la
wickedd_useless_SOURCES		= \
	main.c


# vim: ai
