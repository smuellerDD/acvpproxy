#!/bin/bash
#
# Wrapper script to invoke ACVP Proxy with limited numbers of arguments
#
# Written by Stephan Mueller <smueller@chronox.de>
# Written by Quentin Gouchet
#
# This script is never meant to be invoked by itself, but rather by
# the proxy.sh script sourcing this file.
#

# Testvectors directory
TESTVECTORS_DIR="testvectors"
# Secure datastore directory
SECUREDATA_DIR="secure-datastore"
# Module definition directory
MODULEDEF_DIR="module_definitions"
# ACVP Proxy extension directory
EXTENSION_DIR="module_implementations"
# ACVP Proxy log file
LOGFILE="acvp-proxy"

# File that will contain a general cipher options overview
CIPHER_OPTION_OVERVIEW="cipher_options_overview.txt"

# name of the executable
PROXYBIN="acvp-proxy"

##########################################
# DO NOT CHANGE THE CODE AFTER THIS LINE #
##########################################

DATE=$(date "+%Y%m%d-%H-%M-%S")
# Global variables
INVOCATION_TYPE=""
SHOW_CMD=""
PRODUCTION=""
DOLOG=0

PRODUCTION_CONF="acvpproxy_conf_production.json"
DEMO_CONF="acvpproxy_conf.json"

if [ `uname -s` == "Darwin" ]
then
       LIBEXT="dylib"
else
       LIBEXT="so"
fi

# If the binary distribution directory is found for the given version,
# use this instead of the generic ACVP Proxy location
if [ -d "${PROXYBINPATH}/${PROXYBIN}-${PROXYVERSION}" ]
then
	PROXYBINPATH="${PROXYBINPATH}/${PROXYBIN}-${PROXYVERSION}"
fi

PATH=$PROXYBINPATH:$PATH
if [ -z "$TARGETDIR" ]
then
	TARGETDIR=$(pwd)
fi

usage() {
	echo "Usage:"
	echo "$0 [--official] [--show-cmd] [--log] [get|post|publish|list|status|approval]"
	echo
	echo "$0 must be used with one of the following commands"
	echo -e "\tlist\t\tList the module definitions in scope for operations"
	echo -e "\tget\t\tGet test vectors from ACVP server"
	echo -e "\tpost\t\tPost the test responses to ACVP server and get verdicts"
	echo -e "\tpublish\t\tPublish the tests to obtain certificate"
	echo -e "\tstatus\t\tList of verdicts, request IDs and certificates"
	echo -e "\tapproval\tGet files that vendor must approve"
	echo
	echo "The following additional options are allowed"
	echo -e "\t--official\tUse the production ACVP server (default: demo server)"
	echo -e "\t--show-cmp\tShow the used ACVP Proxy command without execution"
	echo -e "\t--log\t\tCreate log file with detailed logging"
}

# Invoke command
invoke() {
	if [ -n "$SHOW_CMD" ]
	then
		echo $@ ${PROXYSEARCH}
		return
	fi
	eval $@ ${PROXYSEARCH}
	if [ $? -ne 0 ]
	then
		echo "Command invocation returned $?"
	fi
}

# Check command line
checkArgLen() {
	if [ $ARGSLEN -eq 0 ]; then
		echo "No arguments provided"
		echo
		usage
		exit 0
	fi
}	

checkProxyVersion() {
	# check proxy version
	if [ $($PROXYBIN --version-numeric 2>&1) -ne $PROXYVERSION ]
	then
		echo "Proxy versions do match. Aborting."
		exit 1
	fi
}

checkForBinary() {
	# check if binary is compiled/exists
	if [ ! -x "$PROXYBINPATH/$PROXYBIN" ]
	then
		echo "acvp-proxy is not found, please make it available as referenced by PROXYBINPATH"
		exit 1
	fi
}

compileExtension() {
	if [ -f "$TARGETDIR/$EXTENSION_DIR/Makefile" ]
	then
		local dir=${PROXYCODEPATH}

		trap "make -s -C $TARGETDIR/$EXTENSION_DIR clean; exit" 0 1 2 15
		trap "killall -3 ${PROXYBIN}; make -s -C $TARGETDIR/$EXTENSION_DIR clean; exit" 3

		if [ ! -d "$dir" ]
		then
			dir="${PROXYBINPATH}/"
			if [ ! -d "$dir" ]
			then
				dir="/usr/include/acvpproxy"
				if [ ! -d "$dir" ]
				then
					echo "No ACVP Proxy source code found, please set PROXYCODEPATH or install ACVP Proxy binary/development archive and point to it with PROXYBINPATH"
					exit 1
				fi
			fi
		fi
		CFLAGS="-I${dir}/lib -I${dir}/lib/module_implementations" make -s -C "$TARGETDIR/$EXTENSION_DIR"
		if [ $? -ne 0 ]
		then
			echo "Compilation of extension failed"
			exit 1
		fi
	fi
}

# Set parameters of ACVP Proxy invocation
setParams() {
	local production=0

	# check each and every argument to make sure they are valid
	for arg in $ARGS
	do
		case "$arg" in
			"--official")
				PRODUCTION="-production"
				production=1
				if [ ! -f "$PROXYBINPATH/$PRODUCTION_CONF" ]
				then
					echo "ACVP Proxy production server configuration file $PROXYBINPATH/$PRODUCTION_CONF not found"
					exit 1
				fi
				PARAMS="--official $PARAMS -c $PROXYBINPATH/$PRODUCTION_CONF"
				;;
			"--show-cmd")
				SHOW_CMD="y"
				;;
			"get"|"post"|"publish"|"list"|"status"|"approval")
				INVOCATION_TYPE=$arg
				;;
			"--log")
				DOLOG=1
				;;
			*)
				PARAMS="$PARAMS $arg"
				;;
		esac
	done

	PARAMS="$PARAMS -b $TARGETDIR/${TESTVECTORS_DIR}${PRODUCTION}"
	PARAMS="$PARAMS -s $TARGETDIR/${SECUREDATA_DIR}${PRODUCTION}"

	# Set module definition
	if [ -d "$TARGETDIR/${MODULEDEF_DIR}" ]
	then
		PARAMS="$PARAMS --definition-basedir $TARGETDIR/${MODULEDEF_DIR}"
	elif [ -n "$PROXYCODEPATH" ]
	then
		PARAMS="$PARAMS --definition-basedir $PROXYCODEPATH/${MODULEDEF_DIR}"
	elif [ ! -d "${MODULEDEF_DIR}" ]
	then
		echo "Module definition not found - either create directory $TARGETDIR/${MODULEDEF_DIR} and store the module definitions there or point PROXYCODEPATH to the ACVP Proxy source code repository that may have the module definitions."
		exit 1
	fi

	# Set extensions
	if [ -d "$TARGETDIR/$EXTENSION_DIR" ]
	then
		compileExtension
		for i in "$TARGETDIR/$EXTENSION_DIR/*.$LIBEXT"
		do
			PARAMS="$PARAMS --proxy-extension $i"
		done
	fi

	if [ "$production" -eq 0 ]
	then
		if [ ! -f "$PROXYBINPATH/$DEMO_CONF" ]
		then
			echo "ACVP Proxy demo server configuration file $PROXYBINPATH/$DEMO_CONF not found"
			exit 1
		fi
		PARAMS="$PARAMS -c $PROXYBINPATH/$DEMO_CONF"
	fi

	if [ -z "$INVOCATION_TYPE" ]
	then
		echo "Empty invocation type"
		usage
		exit 1
	fi
}

addlogging()
{
	local file=$1

	if [ -z "$file" ]
	then
		return
	fi

	if [ $DOLOG -eq 1 ]
	then
		echo "-vvv --logfile $file"
	fi
}

checkPrereqs()
{
	if [ ! -d "$TARGETDIR" ]
	then
		echo "Creating directory $TARGETDIR"
		mkdir -p $TARGETDIR
		if [ -$? -ne 0 ]
		then
			echo "Creation of target directory $TARGETDIR failed"
			exit $?
		fi
	fi
}

getVendorApprovalPackage()
{
	local moddef=""
	local dirs=""

	if [ ! -d "$TARGETDIR" ]
	then
		echo "$TARGETDIR not found"
		exit 1
	fi

	if [ ! -d "$TARGETDIR/${SECUREDATA_DIR}${PRODUCTION}" ]
	then
		echo "$TARGETDIR/${SECUREDATA_DIR}${PRODUCTION} not found"
		exit 1
	fi

	if [ -d "$TARGETDIR/${MODULEDEF_DIR}" ]
	then
		moddef="$TARGETDIR/${MODULEDEF_DIR}"
	elif [ -n "$PROXYCODEPATH" ]
	then
		moddef="$PROXYCODEPATH/${MODULEDEF_DIR}"
	elif [ -d "${MODULEDEF_DIR}" ]
	then
		moddef="${MODULEDEF_DIR}"
	else
		echo "Module definition not found - either create directory $TARGETDIR/${MODULEDEF_DIR} and store the module definitions there or point PROXYCODEPATH to the ACVP Proxy source code repository that may have the module definitions."
		exit 1
	fi

	invoke $PROXYBIN $PARAMS --list-cipher-options > $TARGETDIR/$CIPHER_OPTION_OVERVIEW

	dirs="${dirs} $TARGETDIR/$CIPHER_OPTION_OVERVIEW"
	dirs="${dirs} $(find ${moddef} -name oe)"
	dirs="${dirs} $(find ${moddef} -name vendor)"
	dirs="${dirs} $(find ${moddef} -name module_info)"
	dirs="${dirs} $(find $TARGETDIR/${SECUREDATA_DIR}${PRODUCTION} -name request-*.json)"

	tar -cJf vendor-approval-package-${DATE}.tar.xz $dirs

	rm -f $TARGETDIR/$CIPHER_OPTION_OVERVIEW
}

getvectors() {
	local log="${LOGFILE}-post-${DATE}.log"
	invoke $PROXYBIN $PARAMS --request $(addlogging "$log")

	echo
	echo "Archive $TARGETDIR/${TESTVECTORS_DIR}${PRODUCTION} and send this archive to vendor to process it with the ACVP Parser."
	echo -e "\ttar -C $TARGETDIR/ -czf testvectors${PRODUCTION}.tar.gz ${TESTVECTORS_DIR}${PRODUCTION}/"
	echo
	echo "After processing the archive, the vendor shall return the archive from the following command:"
	echo -e "\ttar -czf results${PRODUCTION}.tar.gz \$(find ${TESTVECTORS_DIR}${PRODUCTION}/ -name testvector-response.json)"
	echo
	echo "Unpack the received responses with the following command:"
	echo -e "\ttar -C $TARGETDIR/ -xzf results${PRODUCTION}.tar.gz"
}

postvectors() {
	local log="${LOGFILE}-post-${DATE}.log"
	invoke $PROXYBIN $PARAMS $(addlogging "$log")

	invoke $PROXYBIN $PARAMS --list-verdicts

	echo
	echo "Check if all listed verdicts are PASSED - if yes, you may proceed to publish IUT"
}

publish() {
	local log="${LOGFILE}-publish-${DATE}.log"
	invoke $PROXYBIN $PARAMS --publish $(addlogging $log)

	invoke $PROXYBIN $PARAMS --list-request-ids-sparse

	echo
	echo "Check the above listing - if request IDs are present, inform NIST to approve them and re-invoke this command."
	echo
	echo "========================================="
	echo
	echo "The following certificates were obtained:"
	echo
	invoke $PROXYBIN $PARAMS --list-certificates
}

statuslist() {
	echo "Listing of verdicts"
	echo "==================="
	invoke $PROXYBIN $PARAMS --list-verdicts

	echo
	echo "Listing of outstanding request IDs"
	echo "=================================="
	invoke $PROXYBIN $PARAMS --list-request-ids-sparse
	
	echo
	echo "Listing of obtained certificates"
	echo "================================"
	invoke $PROXYBIN $PARAMS --list-certificates

	echo
	echo "Listing for TE.01.12.01"
	echo "======================="
	invoke $PROXYBIN $PARAMS --list-cert-details
}

listscope() {
	invoke $PROXYBIN $PARAMS -l
}

checkArgLen
checkForBinary
checkProxyVersion
checkPrereqs
setParams

case "$INVOCATION_TYPE" in
	"get")
		getvectors
		;;
	"post")
		postvectors
		;;
	"publish")
		publish
		;;
	"list")
		listscope
		;;
	"status")
		statuslist
		;;
	"approval")
		getVendorApprovalPackage
		;;
	*)
		echo "Unknown invocation type $INVOCATION_TYPE"
		;;
esac
