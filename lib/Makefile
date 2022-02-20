#
# Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
#

CC		?= gcc
CFLAGS		+= -Werror -Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS		+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden -fPIE -Wcast-align -Wmissing-field-initializers -Wshadow -Wswitch-enum -Wno-variadic-macros

#Optimizations
CFLAGS		+= -flto
LDFLAGS		+= -flto

ifneq '' '$(findstring clang,$(CC))'
CFLAGS		+= -Wno-gnu-zero-variadic-macro-arguments
endif

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Linux)
LDFLAGS		+= -Wl,-z,relro,-z,now -pie
LDFLAGS_SO	+= -Wl,-z,relro,-z,now,--as-needed -fpic
endif

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
STRIP		?= strip -x
SRCDIR		:=

# Files to be filtered out and not to be compiled
EXCLUDED	?=

###############################################################################
#
# Define compilation options
#
###############################################################################
INCLUDE_DIRS	:= . ./acvp ./common ./esvp
LIBRARY_DIRS	:=
LIBRARIES	:= curl pthread

ifeq ($(UNAME_S),Darwin)
CFLAGS		+= -mmacosx-version-min=10.14 -Wno-gnu-zero-variadic-macro-arguments
LDFLAGS		+= -framework Foundation -framework Security
EXCLUDED	+= $(SRCDIR)common/network_backend_curl.c $(SRCDIR)common/openssl_thread_support.c
M_SRCS		:= $(wildcard $(SRCDIR)apps/*.m)
M_SRCS		+= $(wildcard $(SRCDIR)lib/common/*.m)
M_OBJS		:= ${M_SRCS:.m=.o}
else
LIBRARIES	+= curl
M_OBJS		:=
endif

CFLAGS		+= $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS		+= $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS		+= $(foreach library,$(LIBRARIES),-l$(library))

###############################################################################
#
# Get version name and cross check
#
###############################################################################
LIBMAJOR   := $(shell grep '^\#define.*MAJVERSION' common/internal.h | awk '{print $$3}')
LIBMINOR   := $(shell grep '^\#define.*MINVERSION' common/internal.h | awk '{print $$3}')
LIBPATCH   := $(shell grep '^\#define.*PATCHLEVEL' common/internal.h | awk '{print $$3}')
LIBVERSION := $(LIBMAJOR).$(LIBMINOR).$(LIBPATCH)

###############################################################################
#
# Guess at the appropriate lib directory and word size
#
###############################################################################
ifeq ($(UNAME_S),Darwin)
LIBDIR		:= /usr/local/lib
else
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
endif

###############################################################################
#
# Shared library compilation
#
###############################################################################
ifeq ($(UNAME_S),Linux)
SONAMEEXT	:= so
LDFLAGS_SONAME	:= -soname
SONAME		:= lib$(NAME).$(SONAMEEXT).$(LIBMAJOR)
LIBNAME		:= lib$(NAME).$(SONAMEEXT).$(LIBVERSION)
else ifeq ($(UNAME_S),Darwin)
SONAMEEXT	:= dylib
LDFLAGS_SO	+= -dylib
LDFLAGS_SONAME	:= -install_name
SONAME		:= lib$(NAME).$(LIBMAJOR).$(SONAMEEXT)
LIBNAME		:= lib$(NAME).$(LIBVERSION).$(SONAMEEXT)
else
SONAMEEXT	:= so
LDFLAGS_SONAME	:= -soname
SONAME		:= lib$(NAME).$(SONAMEEXT).$(LIBMAJOR)
LIBNAME		:= lib$(NAME).$(SONAMEEXT).$(LIBVERSION)
endif

###############################################################################
#
# Define files to be compiled
#
###############################################################################
C_SRCS := $(wildcard *.c)
C_SRCS := $(wildcard json-c/*.c)
C_SRCS += $(wildcard acvp/*.c)
C_SRCS += $(wildcard common/*.c)
C_SRCS += $(wildcard esvp/*.c)
C_SRCS += $(wildcard hash/*.c)
C_SRCS += $(wildcard requests/*.c)
C_SRCS += $(wildcard module_implementations/*.c)
C_SRCS := $(filter-out $(wildcard $(EXCLUDED)), $(C_SRCS))
C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS)

CRYPTOVERSION := $(shell cat $(SRCDIR)hash/bitshift_be.h $(SRCDIR)hash/bitshift_le.h $(SRCDIR)hash/hash.h $(SRCDIR)hash/hmac.c $(SRCDIR)hash/hmac.h $(SRCDIR)hash/memset_secure.h $(SRCDIR)hash/sha256.c $(SRCDIR)hash/sha256.h $(SRCDIR)hash/sha3.c $(SRCDIR)hash/sha3.h $(SRCDIR)hash/sha512.c $(SRCDIR)hash/sha512.h | openssl sha1 | cut -f 2 -d " ")
CFLAGS += -DCRYPTOVERSION=\"$(CRYPTOVERSION)\"

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
	$(CC) -shared -Wl,$(LDFLAGS_SONAME),$(notdir $(LIBNAME))  $(LDFLAGS_SO) -o $(LIBNAME) $(OBJS)
	$(STRIP) $(LIBNAME)
	$(LNS) $(LIBNAME) $(SONAME)
	$(LNS) $(LIBNAME) lib$(NAME).so

$(analyze_plists): %.plist: %.c
	@echo "  CCSA  " $@
	clang --analyze $(CFLAGS) $< -o $@

scan: $(analyze_plists)

cppcheck:
	cppcheck --force -q --enable=performance --enable=warning --enable=portability *.h *.c

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
