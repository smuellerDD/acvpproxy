#
# Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
#

CC		?= gcc
CFLAGS		+= -Werror -Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS		+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden -fPIE -Wcast-align -Wmissing-field-initializers -Wshadow -Wswitch-enum -Wno-variadic-macros -Wmissing-prototypes

#Optimizations
CFLAGS		+= -flto
LDFLAGS		+= -flto

GITVER		:= $(shell git log -1 --pretty=%h)
CFLAGS		+= -DGITVER=\"$(GITVER)\"

ifneq '' '$(findstring clang,$(CC))'
CFLAGS		+= -Wno-gnu-zero-variadic-macro-arguments
endif

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Linux)
LDFLAGS		+= -Wl,-z,relro,-z,now -pie
LDFLAGS_SO	+= -Wl,-z,relro,-z,now,--as-needed -fpic
endif

APPNAME		?= acvp-proxy
AMVPNAME	?= amvp-proxy
ESVPNAME	?= esvp-proxy

DESTDIR		:=
ETCDIR		:= /etc
BINDIR		:= /bin
SBINDIR		:= /sbin
SHAREDIR	:= /usr/share/$(APPNAME)
MANDIR		:= /usr/share/man
MAN1		:= $(MANDIR)/man1
MAN3		:= $(MANDIR)/man3
MAN5		:= $(MANDIR)/man5
MAN7		:= $(MANDIR)/man7
MAN8		:= $(MANDIR)/man8
INCLUDEDIR	:= /usr/include
LN		:= ln
LNS		:= $(LN) -sf
STRIP		?= strip
BUILDDIR	:= buildpackage
SRCDIR		:=

# Files to be filtered out and not to be compiled
EXCLUDED	?=

###############################################################################
#
# Get version name and cross check
#
###############################################################################
VERFILE		:= lib/common/internal.h

APPMAJOR	:= $(shell grep '\#define.*MAJVERSION' $(VERFILE) | awk '{print $$3}')
APPMINOR	:= $(shell grep '\#define.*MINVERSION' $(VERFILE) | awk '{print $$3}')
APPPATCH	:= $(shell grep '\#define.*PATCHLEVEL' $(VERFILE) | awk '{print $$3}')
APPVERSION	:= $(APPMAJOR).$(APPMINOR).$(APPPATCH)

###############################################################################
#
# Define compilation options
#
###############################################################################
INCLUDE_DIRS	+= $(SRCDIR)lib $(SRCDIR)apps $(SRCDIR)lib/module_implementations $(SRCDIR)lib/acvp $(SRCDIR)lib/common $(SRCDIR)lib/esvp $(SRCDIR)lib/amvp
LIBRARY_DIRS	+=
LIBRARIES	+= pthread dl

ifeq ($(UNAME_S),Darwin)
CFLAGS		+= -mmacosx-version-min=10.14 -Wno-gnu-zero-variadic-macro-arguments
LDFLAGS		+= -framework Foundation -framework Security
EXCLUDED	+= $(SRCDIR)lib/common/network_backend_curl.c $(SRCDIR)lib/common/openssl_thread_support.c
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
# Shared library compilation
#
###############################################################################
ifeq ($(UNAME_S),Linux)
SONAMEEXT	:= $(APPVERSION).so
LDFLAGS_SONAME	:= -soname
else ifeq ($(UNAME_S),Darwin)
SONAMEEXT	:= $(APPVERSION).dylib
LDFLAGS_SO	+= -dylib
LDFLAGS_SONAME	:= -install_name
else
SONAMEEXT	:= $(APPVERSION).so
LDFLAGS_SONAME	:= -soname
endif

###############################################################################
#
# Define files to be compiled
#
###############################################################################
C_SRCS += $(wildcard $(SRCDIR)apps/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/acvp/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/amvp/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/common/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/esvp/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/hash/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/requests/*.c)
C_SRCS += $(wildcard $(SRCDIR)lib/json-c/*.c)

EX_SRCS += $(wildcard $(SRCDIR)lib/module_implementations/*.c)

C_SRCS := $(filter-out $(wildcard $(EXCLUDED)), $(C_SRCS))

C_OBJS := ${C_SRCS:.c=.o}
EX_OBJS := ${EX_SRCS:.c=.o}
EX_SOOBJS := ${EX_OBJS:.o=.$(SONAMEEXT)}
OBJS := $(M_OBJS) $(C_OBJS)
ALL_OBJS := $(OBJS) $(EX_OBJS)

GCOV_OBJS := $(OBJS) $(EX_OBJS)
C_GCOV := ${GCOV_OBJS:.o=.gcda}
C_GCOV += ${GCOV_OBJS:.o=.gcno}
C_GCOV += ${GCOV_OBJS:.o=.gcov}

CRYPTOVERSION := $(shell cat $(SRCDIR)lib/hash/bitshift_be.h $(SRCDIR)lib/hash/bitshift_le.h $(SRCDIR)lib/hash/hash.h $(SRCDIR)lib/hash/hmac.c $(SRCDIR)lib/hash/hmac.h $(SRCDIR)lib/hash/memset_secure.h $(SRCDIR)lib/hash/sha256.c $(SRCDIR)lib/hash/sha256.h $(SRCDIR)lib/hash/sha3.c $(SRCDIR)lib/hash/sha3.h $(SRCDIR)lib/hash/sha512.c $(SRCDIR)lib/hash/sha512.h | openssl sha1 | cut -f 2 -d " ")
CFLAGS += -DCRYPTOVERSION=\"$(CRYPTOVERSION)\"

analyze_srcs = $(filter %.c, $(sort $(C_SRCS)))
analyze_srcs += $(filter %.c, $(sort $(EX_SRCS)))
analyze_plists = $(analyze_srcs:%.c=%.plist)

.PHONY: all scan install clean cppcheck distclean debug asanaddress asanthread leak gcov binarchive extensions extensionsso

all: $(APPNAME) $(ESVPNAME) $(AMVPNAME)

extensionsso: CFLAGS += -DACVPPROXY_EXTENSION
extensionsso: $(EX_SOOBJS)

extensions: EX-$(APPNAME)
extensions: extensionsso

debug: CFLAGS += -g -DDEBUG
debug: DBG-$(APPNAME)
debug: DBG-$(AMVPNAME)
debug: DBG-$(ESVPNAME)

asanaddress: CFLAGS += -g -DDEBUG -fsanitize=address -fno-omit-frame-pointer
asanaddress: LDFLAGS += -fsanitize=address
asanaddress: DBG-$(APPNAME)
asanaddress: DBG-$(AMVPNAME)
asanaddress: DBG-$(ESVPNAME)

asanthread: CFLAGS += -g -DDEBUG -fsanitize=thread -fno-omit-frame-pointer
asanthread: LDFLAGS += -fsanitize=thread
asanthread: DBG-$(APPNAME)
asanthread: DBG-$(AMVPNAME)
asanthread: DBG-$(ESVPNAME)

leak: CFLAGS += -g -DDEBUG -fsanitize=leak -fno-omit-frame-pointer
leak: LDFLAGS += -fsanitize=leak
leak: DBG-$(APPNAME)
leak: DBG-$(AMVPNAME)
leak: DBG-$(ESVPNAME)

# Compile for the use of GCOV
# Usage after compilation: gcov <file>.c
gcov: CFLAGS += -g -DDEBUG -fprofile-arcs -ftest-coverage
gcov: LDFLAGS += -fprofile-arcs
gcov: DBG-$(APPNAME)

###############################################################################
#
# Build the application
#
###############################################################################

$(APPNAME): $(ALL_OBJS)
	$(CC) -o $(APPNAME) $(OBJS) $(EX_OBJS) $(LDFLAGS)
	$(STRIP) $(APPNAME)

$(AMVPNAME): $(APPNAME)
	$(RM) $(AMVPNAME)
	$(LN) $(APPNAME) $(AMVPNAME)

$(ESVPNAME): $(APPNAME)
	$(RM) $(ESVPNAME)
	$(LN) $(APPNAME) $(ESVPNAME)

DBG-$(APPNAME): $(ALL_OBJS)
	$(CC) -g -DDEBUG -o $(APPNAME) $(OBJS) $(EX_OBJS) $(LDFLAGS)

DBG-$(AMVPNAME): DBG-$(APPNAME)
	$(RM) $(AMVPNAME)
	$(LN) $(APPNAME) $(AMVPNAME)

DBG-$(ESVPNAME): DBG-$(APPNAME)
	$(RM) $(ESVPNAME)
	$(LN) $(APPNAME) $(ESVPNAME)

$(analyze_plists): %.plist: %.c
	@echo "  CCSA  " $@
	clang --analyze $(CFLAGS) $< -o $@

scan: $(analyze_plists)

format:
	clang-format -i apps/*.[ch] lib/common/*.[ch] lib/acvp/*.[ch] lib/esvp/*.[ch]

cppcheck:
	cppcheck --force -q --enable=performance --enable=warning --enable=portability $(SRCDIR)apps/*.h $(SRCDIR)apps/*.c $(SRCDIR)lib/*.c $(SRCDIR)lib/*.h $(SRCDIR)lib/module_implementations/*.c $(SRCDIR)lib/module_implementations/*.h $(SRCDIR)lib/json-c/*.c $(SRCDIR)lib/json-c/*.h

$(EX_OBJS):
	$(CC) -c -o $@ $(basename $@).c $(CFLAGS)
       
%.$(SONAMEEXT): %.o
	$(CC) -shared -Wl,$(LDFLAGS_SONAME),$(notdir $@) -o $@ $< $(LDFLAGS_SO)

EX-$(APPNAME): $(OBJS)
	$(CC) -o $(APPNAME) $(OBJS) $(LDFLAGS)
	$(LN) $(APPNAME) $(ESVPNAME)
	$(LN) $(APPNAME) $(AMVPNAME)

install:
	install -m 0755 $(APPNAME) -D -t $(DESTDIR)$(BINDIR)/


binarchive: extensions
	$(eval APPVERSION_NUMERIC := $(shell ./acvp-proxy --version-numeric 2>&1))
	strip $(APPNAME)

ifeq ($(UNAME_S),Linux)
	install -s -m 0755 $(APPNAME) -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	install -s -m 0755 $(AMVPNAME) -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	install -s -m 0755 $(ESVPNAME) -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	install -m 0755 $(SRCDIR)helper/proxy-lib.sh -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	install -m 0755 $(SRCDIR)helper/proxy.sh -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	install -m 0755 $(SRCDIR)helper/Makefile.out-of-tree -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	install -m 0755 $(SRCDIR)helper/extract_arch.sh -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	install -m 0644 $(SRCDIR)lib/definition_cipher*.h -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	install -m 0644 $(SRCDIR)lib/definition*.h -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	install -m 0644 $(SRCDIR)lib/constructor*.h -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	install -m 0644 $(SRCDIR)lib/aux_helper.h -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	install -m 0644 $(SRCDIR)lib/bool.h -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	install -m 0644 $(SRCDIR)lib/cipher_definitions.h -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	install -m 0644 $(SRCDIR)lib/module_implementations/*.h -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/module_implementations/
	install -m 0755 $(SRCDIR)lib/module_implementations/*.so -D -t $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/extensions/
else
	@- mkdir -p $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/module_implementations/
	@- mkdir -p $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/extensions/
	@- mkdir -p $(BUILDDIR)/$(AMVPNAME)-$(APPVERSION_NUMERIC)/extensions/
	@- mkdir -p $(BUILDDIR)/$(ESVPNAME)-$(APPVERSION_NUMERIC)/extensions/
	@- cp -f $(APPNAME) $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(APPNAME) $(BUILDDIR)/$(AMVPNAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(APPNAME) $(BUILDDIR)/$(ESVPNAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(SRCDIR)helper/proxy-lib.sh $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(SRCDIR)helper/proxy.sh $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(SRCDIR)helper/Makefile.out-of-tree $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(SRCDIR)helper/extract_arch.sh $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/
	@- cp -f $(SRCDIR)lib/definition_cipher*.h $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	@- cp -f $(SRCDIR)lib/definition.h $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	@- cp -f $(SRCDIR)lib/constructor.h $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	@- cp -f $(SRCDIR)lib/bool.h $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	@- cp -f $(SRCDIR)lib/cipher_definitions.h $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/
	@- cp -f $(SRCDIR)lib/module_implementations/*.h $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/lib/module_implementations/
	@- cp -f $(SRCDIR)lib/module_implementations/*.dylib $(BUILDDIR)/$(APPNAME)-$(APPVERSION_NUMERIC)/extensions/
endif
	@- tar -cJf $(APPNAME)-$(APPVERSION_NUMERIC).$(UNAME_S).$(UNAME_M).tar.xz -C $(BUILDDIR) $(APPNAME)-$(APPVERSION_NUMERIC)

###############################################################################
#
# Clean
#
###############################################################################

clean:
	@- $(RM) $(OBJS)
	@- $(RM) $(EX_OBJS)
	@- $(RM) $(EX_SOOBJS)
	@- $(RM) $(APPNAME)
	@- $(RM) $(APPNAME)-*
	@- $(RM) .$(APPNAME).hmac
	@- $(RM) $(AMVPNAME)
	@- $(RM) $(AMVPNAME)-*
	@- $(RM) .$(AMVPNAME).hmac
	@- $(RM) $(ESVPNAME)
	@- $(RM) $(ESVPNAME)-*
	@- $(RM) .$(ESVPNAME).hmac
	@- $(RM) lib/module_implementations/.*.hmac
	@- $(RM) $(C_GCOV)
	@- $(RM) *.gcov
	@- $(RM) $(analyze_plists)
	@- $(RM) lib/module_implementations/*.so
	@- $(RM) lib/module_implementations/*.dylib
	@- $(RM) -rf $(BUILDDIR)
	@- $(RM) $(APPNAME)-*.tar.xz

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
	@echo EXTENSION_OBJECTS=$(EX_OBJS)
	@echo EXTENSION_SOOBJECTS=$(EX_SOOBJS)
	@echo CRYPTOVERSION=$(CRYPTOVERSION)
	@echo SRCDIR=$(SRCDIR)
	@echo APPVERSION=$(APPVERSION)
