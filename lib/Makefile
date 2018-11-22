#
# Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
#

CC		:= gcc
CFLAGS		+= -Werror -Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS		+= -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden -fPIC
LDFLAGS		+= -Wl,-z,relro,-z,now -fpic

NAME		:= acvpproxy

DESTDIR		:=
ETCDIR		:= /etc
BINDIR		:= /bin
SBINDIR		:= /sbin
SHAREDIR	:= /usr/share/keyutils
MANDIR		:= /usr/share/man
MAN1		:= $(MANDIR)/man1
MAN3		:= $(MANDIR)/man3
MAN5		:= $(MANDIR)/man5
MAN7		:= $(MANDIR)/man7
MAN8		:= $(MANDIR)/man8
INCLUDEDIR	:= /usr/include
LN		:= ln
LNS		:= $(LN) -sf

###############################################################################
#
# Define compilation options
#
###############################################################################
INCLUDE_DIRS	:= .
LIBRARY_DIRS	:=
LIBRARIES	:= json-c curl pthread

CFLAGS		+= $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS		+= $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS		+= $(foreach library,$(LIBRARIES),-l$(library))

###############################################################################
#
# Get version name and cross check
#
###############################################################################
LIBMAJOR   := $(shell grep '^\#define.*MAJVERSION' internal.h | awk '{print $$3}')
LIBMINOR   := $(shell grep '^\#define.*MINVERSION' internal.h | awk '{print $$3}')
LIBPATCH   := $(shell grep '^\#define.*PATCHLEVEL' internal.h | awk '{print $$3}')
LIBVERSION := $(LIBMAJOR).$(LIBMINOR).$(LIBPATCH)

###############################################################################
#
# Guess at the appropriate lib directory and word size
#
###############################################################################
ifeq ($(origin LIBDIR),undefined)
LIBDIR		:= $(shell ldd /usr/bin/make | grep '\(/libc\.\)' | sed -e 's!.*\(/.*\)/libc[.].*!\1!')
endif
ifeq ($(origin USRLIBDIR),undefined)
USRLIBDIR	:= $(patsubst /lib/%,/usr/lib/%,$(LIBDIR))
endif
BUILDFOR	:= $(shell file /usr/bin/make | sed -e 's!.*ELF \(32\|64\)-bit.*!\1!')-bit

ifeq ($(origin CFLAGS),undefined)
ifeq ($(BUILDFOR),32-bit)
CFLAGS		+= -m32
LIBDIR		:= /lib
USRLIBDIR	:= /usr/lib
else
ifeq ($(BUILDFOR),64-bit)
CFLAGS		+= -m64
LIBDIR		:= /lib64
USRLIBDIR	:= /usr/lib64
endif
endif
endif

###############################################################################
#
# Names
#
###############################################################################
SONAME		:= lib$(NAME).so.$(LIBMAJOR)
LIBNAME		:= lib$(NAME).so.$(LIBVERSION)

###############################################################################
#
# Define files to be compiled
#
###############################################################################
C_SRCS := $(wildcard *.c)
C_SRCS += $(wildcard hash/*.c)
C_SRCS += $(wildcard module_implementations/*.c)
C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS)

analyze_srcs = $(filter %.c, $(sort $(C_SRCS)))
analyze_plists = $(analyze_srcs:%.c=%.plist)

.PHONY: all scan install clean cppcheck distclean 

all: $(NAME)

###############################################################################
#
# Build the library
#
##############################################################################

$(NAME): $(OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $(LIBNAME) $(OBJS) $(LDFLAGS)
	$(LNS) $(LIBNAME) $(SONAME)
	$(LNS) $(LIBNAME) lib$(NAME).so

$(analyze_plists): %.plist: %.c
	@echo "  CCSA  " $@
	clang --analyze $(CFLAGS) $< -o $@

scan: $(analyze_plists)

cppcheck:
	cppcheck --enable=performance --enable=warning --enable=portability *.h *.c

install:
	install -m 0755 $(LIBNAME) -D -t $(DESTDIR)$(LIBDIR)/
	$(LNS) $(LIBNAME) $(DESTDIR)$(LIBDIR)/$(SONAME)
	install -m 0644 acvpproxy.h -D -t $(DESTDIR)$(INCLUDEDIR)

###############################################################################
#
# Build the documentation
#
###############################################################################

clean:
	@- $(RM) $(OBJS)
	@- $(RM) $(LIBNAME)
	@- $(RM) $(SONAME)
	@- $(RM) lib$(NAME).so
	@- $(RM) $(analyze_plists)

distclean: clean

###############################################################################
#
# Build debugging
#
###############################################################################
show_vars:
	@echo LIBVERSION=$(LIBVERSION)
	@echo APIVERSION=$(APIVERSION)
	@echo LIBDIR=$(LIBDIR)
	@echo USRLIBDIR=$(USRLIBDIR)
	@echo BUILDFOR=$(BUILDFOR)
	@echo SONAME=$(SONAME)
	@echo LIBNAME=$(LIBNAME)
	@echo LDFLAGS=$(LDFLAGS)
	@echo CFLAGS=$(CFLAGS)
