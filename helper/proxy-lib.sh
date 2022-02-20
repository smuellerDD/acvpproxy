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
# Local ACVP Proxy extension directory with source code
EXTENSION_DIR="module_implementations"
# Global ACVP Proxy extension directory
GLOBAL_EXTENSION_DIR="extensions"
# ACVP Proxy log file
LOGFILE="acvp-proxy"
# ACVP Proxy test vector files
REQFILE="testvector-request.json"
# proxy-lib.sh status file
SCRIPT=${0//[.\/]/_}
PROXYLIBSTATUS=".proxy-lib-status-$SCRIPT.txt"
PROXYLIBSTATUSPOST=".proxy-lib-status-post-$SCRIPT.txt"

# File that will contain a general cipher options overview
CIPHER_OPTION_OVERVIEW="cipher_options_overview.txt"

# name of the executable
PROXYBIN="acvp-proxy"

# Directory hlding the ACVP Proxy extensions - if empty, the extensions
# shipped with the current version of the TOE are used. If you, however,
# want to point to a different version of the extensions (e.g. using a
# newer version of teh the ACVP proxy code and older versions of the)
# extensions defining the cipher options, point to the extension directory
# here.
EXTENSION_BASE_DIR=""

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

# Point the extension base to the current ACVP Proxy code base
if [ -z "$EXTENSION_BASE_DIR" ]
then
	EXTENSION_BASE_DIR=${PROXYBINPATH}
fi

usage() {
	echo "Usage:"
	echo "$0 [--official] [--show-cmd] [--log] [get|post|publish|list|status|approval|anyop]"
	echo
	echo "$0 must be used with one of the following commands"
	echo -e "\tlist\t\tList the module definitions in scope for operations"
	echo -e "\tget\t\tGet test vectors from ACVP server"
	echo -e "\tpost\t\tPost the test responses to ACVP server and get verdicts"
	echo -e "\tpublish\t\tPublish the tests to obtain certificate"
	echo -e "\tstatus\t\tList of verdicts, request IDs and certificates"
	echo -e "\tapproval\tGet files that vendor must approve"
	echo -e "\tanyop\t\tJust set the test directories and configuration file"
	echo -e	"\t\t\tand pass through any option to the proxy for unspecified"
	echo -e "\t\t\toperations with the ACVP Proxy"
	echo
	echo "The following additional options are allowed"
	echo -e "\t--official\tUse the production ACVP server (default: demo server)"
	echo -e "\t--show-cmp\tShow the used ACVP Proxy command without execution"
	echo -e "\t--log\t\tCreate log file with detailed logging"
}

color()
{
	bg=0
	echo -ne "\033[0m"
	while [[ $# -gt 0 ]]; do
		code=0
		case $1 in
			black) code=30 ;;
			red) code=31 ;;
			green) code=32 ;;
			yellow) code=33 ;;
			blue) code=34 ;;
			magenta) code=35 ;;
			cyan) code=36 ;;
			white) code=37 ;;
			background|bg) bg=10 ;;
			foreground|fg) bg=0 ;;
			reset|off|default) code=0 ;;
			bold|bright) code=1 ;;
		esac
		[[ $code == 0 ]] || echo -ne "\033[$(printf "%02d" $((code+bg)))m"
		shift
	done
}

# Invoke command
invoke() {
	if [ -n "$SHOW_CMD" ]
	then
		echo $@ ${PROXYSEARCH}
		return
	fi
	eval $@ ${PROXYSEARCH}
	local ret=$?
	if [ $ret -ne 0 ]
	then
		echo "Command invocation returned $ret"
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
	PROXYBINARYVERSION=$($PROXYBIN --version-numeric 2>&1)
	if [ $PROXYBINARYVERSION -ne $PROXYVERSION ]
	then
		echo "Proxy versions do not match. Aborting."
		echo "proxy.sh version: $PROXYVERSION"
		echo "Proxy binary version: $PROXYBINARYVERSION"
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

		for file in $TARGETDIR/$EXTENSION_DIR/*.c
		do
			local libfile=$(basename $file)
			libfile_noext=${libfile%%.c}
			#CFLAGS="-I${dir}/lib -I${dir}/lib/module_implementations" C_SRCS=$libfile SONAME=${libfile_noext}.so LIBNAME=${libfile_noext}.so make -s -C "$TARGETDIR/$EXTENSION_DIR" show_vars
			CFLAGS="-I${dir}/lib -I${dir}/lib/module_implementations" C_SRCS=$libfile SONAME=${libfile_noext}.so LIBNAME=${libfile_noext}.$LIBEXT make -s -C "$TARGETDIR/$EXTENSION_DIR"
			if [ $? -ne 0 ]
			then
				echo "Compilation of extension failed"
				exit 1
			fi
		done
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
			"get"|"post"|"publish"|"list"|"status"|"approval"|"anyop")
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
		for i in $TARGETDIR/$EXTENSION_DIR/*.$LIBEXT
		do
			PARAMS="$PARAMS --proxy-extension $i"
		done
	fi

	# Set global extension directory if present
	if [ -d "${EXTENSION_BASE_DIR}/${GLOBAL_EXTENSION_DIR}" ]
	then
		PARAMS="$PARAMS --proxy-extension-dir ${EXTENSION_BASE_DIR}/${GLOBAL_EXTENSION_DIR}"
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

	for moddef in $(find ${MODULEDEF_DIR} -maxdepth 1 -mindepth 1 -type d )
	do
		dirs="${dirs} $TARGETDIR/$CIPHER_OPTION_OVERVIEW"
		dirs="${dirs} $(find ${moddef} -name oe)"
		dirs="${dirs} $(find ${moddef} -name vendor)"
		dirs="${dirs} $(find ${moddef} -name module_info)"
		dirs="${dirs} $(find $TARGETDIR/${SECUREDATA_DIR}${PRODUCTION} -name request-*.json)"

		moddef=$(basename $moddef)
		tar --exclude="__MACOSX" --exclude=".*" --exclude="._*" -cJf ${moddef}-vendor-approval-package-${DATE}.tar.xz $dirs
	done

	rm -f $TARGETDIR/$CIPHER_OPTION_OVERVIEW
}

checkvectors() {
	local ret=0

	for reqfile in $(find $TARGETDIR/${TESTVECTORS_DIR}${PRODUCTION} -name ${REQFILE})
	do

		if (grep -q status $reqfile)
		then
			echo $(color "yellow")[INVALID]$(color off) "Test vector $reqfile contains status information"
			ret=1
		fi
	done

	return $ret
}

getvectors() {
	local log="${LOGFILE}-post-${DATE}.log"

	if [ -e $TARGETDIR/$PROXYLIBSTATUS ]
	then
		local libstatus=$(cat $TARGETDIR/$PROXYLIBSTATUS)
		rm -f $TARGETDIR/$PROXYLIBSTATUS

		if [ x"$libstatus" = x"register success" ]
		then
			invoke $PROXYBIN $PARAMS --request --testid -1 $(addlogging "$log")
		else
			invoke $PROXYBIN $PARAMS --request $(addlogging "$log")
		fi
	else
		invoke $PROXYBIN $PARAMS --request --register-only $(addlogging "$log")

		local ret=$?
		if [ $ret -eq 0 ]
		then
			echo "register success" > $TARGETDIR/$PROXYLIBSTATUS

			echo "Now go out and sip some coffee and re-invoke command at a later time of your choice."
			echo "There is no network operation happening until you re-invoke the command allowing you to go about your business without considering at the ACVP connection"
		else
			echo "register error: $ret" > $TARGETDIR/$PROXYLIBSTATUS
			echo "Error occurred during register operation, re-invoke command"
		fi

		exit $ret
	fi

	echo

	checkvectors
	if [ $? -ne 0 ]
	then
		echo "Re-obtain test vectors by removing the listed status files and invoke 'proxy.sh anyop --request --testid -1'"
		exit 1
	fi

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

	if [ -e $TARGETDIR/$PROXYLIBSTATUSPOST ]
	then
		local libstatus=$(cat $TARGETDIR/$PROXYLIBSTATUSPOST)
		rm -f $TARGETDIR/$PROXYLIBSTATUSPOST

		if [ x"$libstatus" = x"post success" ]
		then
			invoke $PROXYBIN $PARAMS $(addlogging "$log")
		else
			invoke $PROXYBIN $PARAMS $(addlogging "$log")
		fi
	else
		invoke $PROXYBIN $PARAMS --upload-only $(addlogging "$log")

		local ret=$?
		if [ $ret -eq 0 ]
		then
			echo "post success" > $TARGETDIR/$PROXYLIBSTATUSPOST

			echo "Now go out and sip some coffee and re-invoke command at a later time of your choice."
			echo "There is no network operation happening until you re-invoke the command allowing you to go about your business without considering at the ACVP connection"
		else
			echo "post error: $ret" > $TARGETDIR/$PROXYLIBSTATUSPOST
			echo "Error occurred during post operation, re-invoke command"
		fi

		exit $ret
	fi

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

anyop() {
	local log="${LOGFILE}-anyop-${DATE}.log"
	invoke $PROXYBIN $PARAMS $(addlogging "$log")
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
	"anyop")
		anyop
		;;
	*)
		echo "Unknown invocation type $INVOCATION_TYPE"
		;;
esac
