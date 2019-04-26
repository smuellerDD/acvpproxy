#
# Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
#

CC		:= gcc
CFLAGS		+= -Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS		+= -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden -fPIE

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
LDFLAGS        += -Wl,-z,relro,-z,now -pie
endif

NAME		:= totp

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
ACVP_DIR	:= ../../

INCLUDE_DIRS	:= $(ACVP_DIR)
LIBRARY_DIRS	:=
LIBRARIES	:= pthread

CFLAGS		+= $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS		+= $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS		+= $(foreach library,$(LIBRARIES),-l$(library))

###############################################################################
#
# Define files to be compiled
#
###############################################################################
C_SRCS := $(wildcard *.c)

C_SRCS += $(ACVP_DIR)/lib/totp_mq_server.c $(ACVP_DIR)/lib/logger.c $(ACVP_DIR)/lib/threading_support.c $(ACVP_DIR)/lib/sleep.c $(wildcard $(ACVP_DIR)/lib/hash/*.c) $(ACVP_DIR)/lib/binhexbin.c
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
	@echo LDFLAGS=$(LDFLAGS)
	@echo CFLAGS=$(CFLAGS)