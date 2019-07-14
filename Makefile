#
# Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
#

CC		?= gcc
CFLAGS		+= -Werror -Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS		+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden -fPIE -Wno-missing-field-initializers -Wno-gnu-zero-variadic-macro-arguments

UNAME_S := $(shell uname -s)
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

# Files to be filtered out and not to be compiled
EXCLUDED	?=

###############################################################################
#
# Define compilation options
#
###############################################################################
INCLUDE_DIRS	:= lib apps
LIBRARY_DIRS	:=
LIBRARIES	:= curl pthread

ifeq ($(UNAME_S),Darwin)
#TODO can we remove the special entry for LIBRARY_DIRS?
# The commented out lines would enable the brew curl with Apple Secure Transport
# If you enable that, remove the LIBRARIES line below
LIBRARY_DIRS	+= /usr/local/opt/openssl/lib
#LIBRARY_DIRS	+= /usr/local/opt/curl/lib
INCLUDE_DIRS	+= /usr/local/opt/openssl/include
#INCLUDE_DIRS	+= /usr/local/opt/openssl@1.1/include /usr/local/opt/curl/include
LIBRARIES	+= crypto
LDFLAGS		+= -framework Foundation
M_SRCS		:= $(wildcard apps/*.m)
M_OBJS		:= ${M_SRCS:.m=.o}
else
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
C_SRCS := $(wildcard apps/*.c)
C_SRCS += $(wildcard lib/*.c)
C_SRCS += $(wildcard lib/hash/*.c)
C_SRCS += $(wildcard lib/module_implementations/*.c)
C_SRCS += $(wildcard lib/json-c/*.c)

C_SRCS := $(filter-out $(wildcard $(EXCLUDED)), $(C_SRCS))

C_OBJS := ${C_SRCS:.c=.o}
C_GCOV := ${C_SRCS:.c=.gcda}
C_GCOV += ${C_SRCS:.c=.gcno}
C_GCOV += ${C_SRCS:.c=.gcov}
OBJS := $(M_OBJS) $(C_OBJS)

CRYPTOVERSION := $(shell cat lib/hash/hash.c lib/hash/hash.h lib/hash/hmac.c lib/hash/hmac.h lib/hash/sha1.c lib/hash/sha1.h lib/hash/sha224.c lib/hash/sha224.h lib/hash/sha256.c lib/hash/sha256.h lib/hash/sha384.c lib/hash/sha384.h lib/hash/sha512.c lib/hash/sha512.h | openssl sha1 | cut -f 2 -d " ")
CFLAGS += -DCRYPTOVERSION=\"$(CRYPTOVERSION)\"

analyze_srcs = $(filter %.c, $(sort $(C_SRCS)))
analyze_plists = $(analyze_srcs:%.c=%.plist)

.PHONY: all scan install clean cppcheck distclean debug asanaddress asanthread gcov

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
	cppcheck --force -q --enable=performance --enable=warning --enable=portability apps/*.h apps/*.c lib/*.c lib/*.h lib/module_implementations/*.c lib/module_implementations/*.h lib/json-c/*.c lib/json-c/*.h

install:
	install -m 0755 $(NAME) -D -t $(DESTDIR)$(BINDIR)/

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
