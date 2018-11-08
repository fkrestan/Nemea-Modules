bin_PROGRAMS=prefix_tags

prefix_tags_CFLAGS=-g -fsanitize=address -fno-omit-frame-pointer
prefix_tags_SOURCES=\
	prefix_tags.c \
	prefix_tags_config.c prefix_tags_config.h \
	fields.c fields.h
prefix_tags_LDADD=-ltrap -lunirec

pkgdocdir=${docdir}/prefix_tags
dist_pkgdoc_DATA=README.md

include ../aminclude.am

