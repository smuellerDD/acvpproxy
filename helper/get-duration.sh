#!/bin/bash
#
# Print out a TAB-delimited table with the download and upload duration
# for all ciphers
#

_LIB_IUT="testvectors"
_LIB_REQ="testvector-request.json"
_LIB_DOWN="download_duration.txt"
_LIB_UP="upload_duration.txt"

echo -e "TestID\tVsID\tAlgorithm\tDownload Duration\tUpload Duration"
print_duration()
{
	for i in $(find ${_LIB_IUT}/ -name ${_LIB_DOWN})
	do
		local dir=$(dirname $i)

		local downtime=$(cat $i)
		local uptime="N/A"

		if [ -f "$dir/${_LIB_UP}" ]
		then
			uptime=$(cat $dir/${_LIB_UP})
		fi

		if [ -f "$dir/${_LIB_REQ}" ]
		then
			local vsid=$(basename $dir)
			local testid=$(dirname $dir)
			testid=$(basename $testid)

			local algo=$(grep algorithm "$dir/${_LIB_REQ}" | cut -d":" -f2 | sed 's/.*"\(.*\)".*/\1/')

			echo -e "$testid\t$vsid\t$algo\t$downtime\t$uptime"
		else
			local testid=$(basename $dir)
			if [ $testid -eq 0 ]
			then
				continue
			fi

			echo -e "$testid\t<test session>\tN/A\t$downtime\t$uptime"
		fi

	done
}

print_duration
