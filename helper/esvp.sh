#!/bin/bash
#
# Helper script to invoke the ESVP Proxy.
#
# This directory defines the IUT-specific information in order to invoke the
# ESVP Proxy. This script is intended to be copied into the separate folder
# where the IUT test information is kept.
#
# Steps how to use this script:
#
#	1. Copy this script to the directory where your IUT information shall
#	   be stored.
#	2. Update the variables below as needed.
#	3. Invoke with no parameters to register and upload files to ESVP server.
#   4. Invoke with anyop --testid nnnn (the testid obtained from previous interaction) to submit extra files, update the status.
#   5. Invoke with anyop --testid --publish to initiate the "certify" step.
#

#
# Directory where:
# 1. Testvectors are to be stored
# 2. Secure datastore is to be stored
# 3. (optionally) modules_defintions directory is used (if not present,
#    the modules_definitions directory from the home of the ESVP Proxy is used)
# 4. (optionally) modules_implementations directory is used - if this directory
#    is present and has a Makefile, the Makefile is invoked. If the Makefile is
#    not present, each *.so file is used as an ACVP Proxy extension
#
# Example:
#	TARGETDIR="/my/specific/IUT/path/acvpproxy"
#
TARGETDIR=${TARGETDIR:-"."}

#
# Development environment of ESVP Proxy: point to the directory where either
# the ESVP sources are found or at least the ESVP Proxy header files.
#
# This variable must only be set if the ESVP Proxy binary distribution
# generated is not installed and referenced by PROXYBINPATH
#
# Example:
#	PROXYCODEPATH="$HOME/my/ACVP/source/code/directory"
#
PROXYCODEPATH=${PROXYCODEPATH:-""}

#
# Specify the ESVP Proxy version. This is used as a sanity check in case the
# ESVP Proxy binary is updated. To set this variable, invoke the following
# command and copy its result into this variable.
#
#	ESVP-proxy --version-numeric
#
# Example:
#	PROXYVERSION="1020000"
#
PROXYVERSION=${PROXYVERSION:-"1070800"}

#
# Specify the ESVP search parameters if needed. As documented with the ESVP
# Proxy, the search scope is vital to ensure the ESVP Proxy only operates on
# the intended IUT definitions.
#
# The entire search string that is used on the command line is to be applied
# here. Note, a string is quoted with single quotes, if needed. If no search
# scope is needed, all IUT definitions known to the ESVP Proxy are used.
#
# To verify the correctness of the search scope, you may execute this script
# as follows:
#	./esvp.sh list
#
# Example:
#	PROXYSEARCH="-m 'My IUT(R) Name (64bit)' -e 'Specific CPU'"
#
PROXYSEARCH=${PROXYSEARCH:-""}

#
# Directory where the ESVP Proxy is located. Commonly the ESVP Proxy is
# found in this directory. It is permissible that the ESVP Proxy binary is
# symlinked in that directory.
#
# Note: This directory expects also the esvpproxy_conf.json and
#	esvpproxy_conf_production.json configuration files. It is permissible
#	to have symlinks to those files there.
#
# Note 2: If the ESVP Proxy binary distribution along with the ESVP Proxy
#	  header files are deployed in that directory, no ESVP Proxy source
#	  code is needed.
#
# Note 3: It is permissible to unpack the ESVP Proxy binary distribution into
#	  this directory to have it found automatically. This allows the
#	  parallel installation of multiple different ESVP Proxy binary
#	  distributions (one for each version) where the right binary
#	  distribution is used depending on the settion of PROXYVERSION
#
# Example:
#	PROXYBINPATH="$HOME/bin"
#
PROXYBINPATH=${PROXYBINPATH:-"$HOME/bin"}

##########################################
# DO NOT CHANGE THE CODE AFTER THIS LINE #
##########################################

ARGS="$@"
ARGSLEN="$#"
PARAMS=""

# Identify the type of invocation, or type of proxy binary to invoke: acvp-proxy or esvp-proxy. It will be processed by proxy-lib.sh
PROXYTYPE="esvp"

if [ -z "$PROXYCODEPATH" -a -f "$PROXYBINPATH/acvp-proxy-${PROXYVERSION}/proxy-lib.sh" ]
then
	source "$PROXYBINPATH/acvp-proxy-${PROXYVERSION}/proxy-lib.sh"
elif [ -n "$PROXYCODEPATH" -a -d "$PROXYCODEPATH" ]
then
	source $PROXYCODEPATH/helper/proxy-lib.sh
elif [ -z "$PROXYCODEPATH" -a -f "$PROXYBINPATH/proxy-lib.sh" ]
then
	source $PROXYBINPATH/proxy-lib.sh
else
	echo "File proxy-lib.sh not found."
	echo "Either configure PROXYCODEPATH to point to the ACVP Proxy source repository or provide the proxy-lib.sh in the directory $PROXYBINPATH."
fi
