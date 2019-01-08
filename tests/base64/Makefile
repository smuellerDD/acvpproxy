#
# Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
#

CC		:= gcc
CFLAGS		+= -Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS		+= -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden -fPIE
LDFLAGS		+= -Wl,-z,relro,-z,now -pie

NAME		:= base64

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
ACVP_DIR	:= ../../apps

INCLUDE_DIRS	:= $(ACVP_DIR)
LIBRARY_DIRS	:=
LIBRARIES	:=

CFLAGS		+= $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS		+= $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS		+= $(foreach library,$(LIBRARIES),-l$(library))

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
# Define files to be compiled
#
###############################################################################
C_SRCS := $(wildcard *.c)

C_SRCS += $(ACVP_DIR)/base64.c
C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS)

###############################################################################


.PHONY: all scan install clean cppcheck distclean

all: $(NAME)

###############################################################################
#
# Build the library
#
###############################################################################

$(NAME): $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

scan:	$(OBJS)
	scan-build --use-analyzer=/usr/bin/clang $(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

cppcheck:
	cppcheck --enable=performance --enable=warning --enable=portability *.h *.c ../lib/*.c ../lib/*.h

install:
	install -m 0755 $(LIBNAME) -D -t $(DESTDIR)$(LIBDIR)/
	$(LNS) $(LIBNAME) $(DESTDIR)$(LIBDIR)/$(SONAME)
	install -m 0644 kcapi.h -D -t $(DESTDIR)$(INCLUDEDIR)

###############################################################################
#
# Build the documentation
#
###############################################################################

clean:
	@- $(RM) $(OBJS)
	@- $(RM) totp_test.o
	@- $(RM) $(NAME)

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
