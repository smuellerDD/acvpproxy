#!/bin/bash
#
# Script to extract testvectors for a specific CPU and platform
#
# Written by Stephan Mueller <smueller@chronox.de>
#

TESTDIR="testvectors/"
TESTDIR_PROD="testvectors-production/"
DEFREF="definition_reference.json"

ARG1=$1
ARG2=$2
ARG3=$3

TARDIRS=""

usage()
{
	echo
	echo "Use the script as follows:"
	echo
	echo -e "\t$0 <search1> [<search2> <search3>]"
	echo
	echo "Where the search strings must match with the data in ${DEFREF}:"
	echo
	echo -e "CPU:\t\treference of the CPU found in \"processor\" keyword -"
	echo -e "\t\texact string match"
	echo -e "Platform:\treference of OE found in \"execenv\" - substring match"
	echo -e "Module name:\treference of module found in \"moduleName\" - substring match"
	echo
	echo "The test vectors are expected in directory: ${TESTDIR} or ${TESTDIR_PROD}"
	echo
	echo "The found data is stored in the local directory at"
	echo "testvectors-<search1>[-<search2>-<search3>].tar.xz"
	exit 1
}

if [ x"$ARG1" = x ]
then
	echo "Provide a search string you want to search for"
	usage
fi

get_tardirs()
{
	local dir=$1

	if [ ! -d $dir ]
	then
		return
	fi

	for i in $(find ${dir} -name ${DEFREF})
	do
		local proc=$(cat $i | grep \"processor\" | cut -f2 -d":" | cut -d"\"" -f2)
		local exec=$(cat $i | grep \"execenv\" | cut -f2 -d":" | cut -d"\"" -f2)
		local name=$(cat $i | grep \"moduleName\" | cut -f2 -d":" | cut -d"\"" -f2)

		if [ x"$ARG1" != x ]
		then
			if [ x"$proc" != x"$ARG1" ]
			then
				if ! ( echo "$exec" | grep -q "$ARG1")
				then
					if ! ( echo "$name" | grep -q "$ARG1")
					then
						continue
					fi
				fi
			fi
		fi

		if [ x"$ARG2" != x ]
		then
			if [ x"$proc" != x"$ARG2" ]
			then
				if ! ( echo "$exec" | grep -q "$ARG2")
				then
					if ! ( echo "$name" | grep -q "$ARG2")
					then
						continue
					fi
				fi
			fi
		fi

		if [ x"$ARG3" != x ]
		then
			if [ x"$proc" != x"$ARG3" ]
			then
				if ! ( echo "$exec" | grep -q "$ARG3")
				then
					if ! ( echo "$name" | grep -q "$ARG3")
					then
						continue
					fi
				fi
			fi
		fi

		TARDIRS="${TARDIRS} $(dirname $i)"
	done
}

get_tardirs $TESTDIR
get_tardirs $TESTDIR_PROD

ARG1=$(echo -n $ARG1 | tr -c [:alnum:] _)
FILENAME="$ARG1"

if [ x"$ARG2" != x ]
then
	ARG2=$(echo -n $ARG2 | tr -c [:alnum:] _)
	FILENAME="$FILENAME-$ARG2"
fi
if [ x"$ARG3" != x ]
then
	ARG3=$(echo -n $ARG3 | tr -c [:alnum:] _)
	FILENAME="$FILENAME-$ARG3"
fi

if [ x"$TARDIRS" != x ]
then
	tar -cvJf testvectors-${FILENAME}.tar.xz ${TARDIRS}
else
	echo "No matching test vectors found"
	exit 1
fi
