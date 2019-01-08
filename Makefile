#
# Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
#

CC		:= gcc
CFLAGS		+= -Werror -Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS		+= -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden -fPIE -Wno-missing-field-initializers -Wno-gnu-zero-variadic-macro-arguments

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
LDFLAGS        += -Wl,-z,relro,-z,now -pie
endif

NAME		:= acvp-proxy

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
INCLUDE_DIRS	:= lib apps
LIBRARY_DIRS	:=
LIBRARIES	:= curl pthread

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
C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS)

analyze_srcs = $(filter %.c, $(sort $(C_SRCS)))
analyze_plists = $(analyze_srcs:%.c=%.plist)

.PHONY: all scan install clean cppcheck distclean debug

all: $(NAME)

debug: CFLAGS += -g -DDEBUG
debug: DBG-$(NAME)

###############################################################################
#
# Build the library
#
##############################################################################

$(NAME): $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

DBG-$(NAME): $(OBJS)
	$(CC) -g -DDEBUG -o $(NAME) $(OBJS) $(LDFLAGS)

$(analyze_plists): %.plist: %.c
	@echo "  CCSA  " $@
	clang --analyze $(CFLAGS) $< -o $@

scan: $(analyze_plists)

cppcheck:
	cppcheck --enable=performance --enable=warning --enable=portability apps/*.h apps/*.c lib/*.c lib/*.h lib/module_implementations/*.c lib/module_implementations/*.h lib/json-c/*.c lib/json-c/*.h

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
	@- $(RM) .$(NAME).hmac
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
