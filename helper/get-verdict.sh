#!/bin/bash
#
# If you want to iterate over all testIDs of several module definitions, you
# may want to use the following code:
# module="OpenSSL"; for a in $(for i in $(find testvectors/ -name ${module}*); do echo $(basename $i); done | sort | uniq | grep -v "^0"); do echo -e "====================== $a ============================"; helper/get-verdict.sh $a; done

_LIB_EXEC="./acvp-parser"
_LIB_IUT="testvectors"
_LIB_REQ="testvector-request.json"
_LIB_RESP="testvector-response.json"
_LIB_VER="verdict.json"

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

echo_pass()
{
	echo $(color "green")[PASSED]$(color off) $@
}

echo_fail()
{
	echo $(color "red")[FAILED]$(color off) $@
	failures=$(($failures+1))
}

echo_deact()
{
	echo $(color "yellow")[DEACTIVATED]$(color off) $@
}

find_module()
{
	local module=$1
	shift
	local vsid=${@}

	local vendordir
	local i
	local j

	if [ -z "$module" ]
	then
		echo "No module name provided, skipping"
		return
	fi

	if [ ! -d "${_LIB_IUT}" ]
	then
		echo "Test vector base directory ${_LUB_IUT} not found"
		return
	fi

	for vendordir in ${_LIB_IUT}/*
	do
		if [ ! -d "$vendordir" ]
		then
			continue
		fi

		local iutdir="$vendordir/$module"

		if [ ! -d "${iutdir}" ]
		then
			echo "No test vectors found for module $iutdir"
			continue
		fi

		for i in $(find ${iutdir} -name ${_LIB_REQ})
		do
			local dir=$(dirname $i)
			local vsid_dir=$(basename $dir)
			local testid_dir=$(basename $dir)
			local found=0
			local cipher
			local vsidval
			local verdict

			for j in $vsid
			do
				if [ "$j" = "$vsid_dir" ]
				then
					found=1
					break
				fi
			done

			# If no search vsids are given, execute testing
			if [ -z "$vsid" ]
			then
				found=1
			fi

			if [ $found -eq 0  ]
			then
				echo_deact "Skipping vsId $vsid_dir as it does not match search criteria"
				continue
			fi

			if (grep -q status $dir/$_LIB_REQ)
			then
				echo_deact "Request contains status information - skipping $dir"
				continue
			fi

			cipher=$(cat $dir/$_LIB_REQ | grep algorithm | cut -d":" -f 2 | cut -d "," -f1 | cut -d"\"" -f 2)

			vsidval=$vsid_dir

			if [ ! -f $dir/$_LIB_VER ]
			then
				echo_deact "$vsidval - $cipher: (no test verdict)"
				continue
			fi

			verdict=$(cat $dir/$_LIB_VER | grep disposition | cut -d":" -f 2 | cut -d"," -f 1 | cut -d "\"" -f 2)

			if [ x"$verdict" = x"passed" ]
			then
				echo_pass "$vsidval - $cipher: $verdict"
			else
				echo_fail "$vsidval - $cipher: $verdict"
			fi
		done
	done
}

MODULE=$1

if [ -z "$MODULE" ]
then
	echo "Module parameter missing"
	exit 1
fi

find_module $MODULE
