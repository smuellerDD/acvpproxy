#
# Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
#

CC		?= gcc
CFLAGS		+= -Werror -Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS		+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden -fPIE -Wno-missing-field-initializers -Wno-gnu-zero-variadic-macro-arguments

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Linux)
LDFLAGS		+= -Wl,-z,relro,-z,now -pie
endif

NAME		?= acvp-proxy

DESTDIR		:=
ETCDIR		:= /etc
BINDIR		:= /bin
SBINDIR		:= /sbin
SHAREDIR	:= /usr/share/$(NAME)
MANDIR		:= /usr/share/man
MAN1		:= $(MANDIR)/man1
MAN3		:= $(MANDIR)/man3
MAN5		:= $(MANDIR)/man5
MAN7		:= $(MANDIR)/man7
MAN8		:= $(MANDIR)/man8
INCLUDEDIR	:= /usr/include
LN		:= ln
LNS		:= $(LN) -sf
BUILDDIR	:= buildpackage
SRCDIR		:= ../../

# Files to be filtered out and not to be compiled
EXCLUDED	?=

###############################################################################
#
# Define compilation options
#
###############################################################################
INCLUDE_DIRS	+= $(SRCDIR)lib $(SRCDIR)apps $(SRCDIR)lib/module_implementations $(SRCDIR)lib/acvp
LIBRARY_DIRS	+=
LIBRARIES	+= pthread dl

ifeq ($(UNAME_S),Darwin)
LDFLAGS		+= -framework Foundation -framework Security
EXCLUDED	+= $(SRCDIR)lib/acvp/network_backend_curl.c $(SRCDIR)lib/acvp/openssl_thread_support.c
M_SRCS		:= $(wildcard $(SRCDIR)apps/*.m)
M_SRCS		+= $(wildcard $(SRCDIR)lib/acvp/*.m)
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
# Define files to be compiled
#
###############################################################################
#C_SRCS += $(wildcard $(SRCDIR)apps/*.c)
C_SRCS += $(wildcard *.c)
C_SRCS += $(wildcard $(SRCDIR)lib/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/acvp/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/hash/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/requests/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/module_implementations/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/json-c/*.c)

C_SRCS := $(filter-out $(wildcard $(EXCLUDED)), $(C_SRCS))

C_OBJS := ${C_SRCS:.c=.o}
C_GCOV := ${C_SRCS:.c=.gcda}
C_GCOV += ${C_SRCS:.c=.gcno}
C_GCOV += ${C_SRCS:.c=.gcov}
OBJS := $(M_OBJS) $(C_OBJS)

CRYPTOVERSION := $(shell cat $(SRCDIR)lib/hash/bitshift_be.h $(SRCDIR)lib/hash/bitshift_le.h $(SRCDIR)lib/hash/hash.h $(SRCDIR)lib/hash/hmac.c $(SRCDIR)lib/hash/hmac.h $(SRCDIR)lib/hash/memset_secure.h $(SRCDIR)lib/hash/sha256.c $(SRCDIR)lib/hash/sha256.h $(SRCDIR)lib/hash/sha3.c $(SRCDIR)lib/hash/sha3.h $(SRCDIR)lib/hash/sha512.c $(SRCDIR)lib/hash/sha512.h | openssl sha1 | cut -f 2 -d " ")
CFLAGS += -DCRYPTOVERSION=\"$(CRYPTOVERSION)\"

analyze_srcs = $(filter %.c, $(sort $(C_SRCS)))
analyze_plists = $(analyze_srcs:%.c=%.plist)

.PHONY: all scan install clean cppcheck distclean debug asanaddress asanthread gcov binarchive

all: $(NAME)

debug: CFLAGS += -g -DDEBUG
debug: DBG-$(NAME)

asanaddress: CFLAGS += -g -DDEBUG -fsanitize=address -fno-omit-frame-pointer
asanaddress: LDFLAGS += -fsanitize=address
asanaddress: DBG-$(NAME)

asanthread: CFLAGS += -g -DDEBUG -fsanitize=thread -fno-omit-frame-pointer
asanthread: LDFLAGS += -fsanitize=thread
asanthread: DBG-$(NAME)

# Compile for the use of GCOV
# Usage after compilation: gcov <file>.c
gcov: CFLAGS += -g -DDEBUG -fprofile-arcs -ftest-coverage
gcov: LDFLAGS += -fprofile-arcs
gcov: DBG-$(NAME)

###############################################################################
#
# Build the application
#
###############################################################################

$(NAME): $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

DBG-$(NAME): $(OBJS)
	$(CC) -g -DDEBUG -o $(NAME) $(OBJS) $(LDFLAGS)

$(analyze_plists): %.plist: %.c
	@echo "  CCSA  " $@
	clang --analyze $(CFLAGS) $< -o $@

scan: $(analyze_plists)

cppcheck:
	cppcheck --force -q --enable=performance --enable=warning --enable=portability $(SRCDIR)apps/*.h $(SRCDIR)apps/*.c $(SRCDIR)lib/*.c $(SRCDIR)lib/*.h $(SRCDIR)lib/module_implementations/*.c $(SRCDIR)lib/module_implementations/*.h $(SRCDIR)lib/json-c/*.c $(SRCDIR)lib/json-c/*.h

install:
	install -m 0755 $(NAME) -D -t $(DESTDIR)$(BINDIR)/


binarchive: $(NAME)
	$(eval APPVERSION_NUMERIC := $(shell ./acvp-proxy --version-numeric 2>&1))
ifeq ($(UNAME_S),Linux)
	install -s -m 0755 $(NAME) -D -t $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/
	install -m 0755 $(SRCDIR)helper/proxy-lib.sh -D -t $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/
	install -m 0755 $(SRCDIR)helper/proxy.sh -D -t $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/
	install -m 0755 $(SRCDIR)helper/Makefile.out-of-tree -D -t $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/
	install -m 0644 $(SRCDIR)lib/*.h -D -t $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/lib/
	install -m 0644 $(SRCDIR)lib/module_implementations/*.h -D -t $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/lib/module_implementations/
else
	@- mkdir -p $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/lib/module_implementations/
	@- cp -f $(NAME) $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(SRCDIR)helper/proxy-lib.sh $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(SRCDIR)helper/proxy.sh $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(SRCDIR)helper/Makefile.out-of-tree $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(SRCDIR)lib/*.h $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/lib/
	@- cp -f $(SRCDIR)lib/module_implementations/*.h $(BUILDDIR)/$(NAME)-$(APPVERSION_NUMERIC)/lib/module_implementations/
endif
	@- tar -cJf $(NAME)-$(APPVERSION_NUMERIC).$(UNAME_S).$(UNAME_M).tar.xz -C $(BUILDDIR) $(NAME)-$(APPVERSION_NUMERIC)

###############################################################################
#
# Clean
#
###############################################################################

clean:
	@- $(RM) $(OBJS)
	@- $(RM) $(NAME)
	@- $(RM) $(NAME)-*
	@- $(RM) .$(NAME).hmac
	@- $(RM) $(C_GCOV)
	@- $(RM) *.gcov
	@- $(RM) $(analyze_plists)
	@- $(RM) -rf $(BUILDDIR)
	@- $(RM) $(NAME)-*.tar.xz

distclean: clean

###############################################################################
#
# Show status
#
###############################################################################
show_vars:
	@echo LIBDIR=$(LIBDIR)
	@echo USRLIBDIR=$(USRLIBDIR)
	@echo BUILDFOR=$(BUILDFOR)
	@echo LDFLAGS=$(LDFLAGS)
	@echo CFLAGS=$(CFLAGS)
	@echo EXCLUDED=$(EXCLUDED)
	@echo SOURCES=$(C_SRCS)
	@echo OBJECTS=$(OBJS)
	@echo CRYPTOVERSION=$(CRYPTOVERSION)
	@echo SRCDIR=$(SRCDIR)
