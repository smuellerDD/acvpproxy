#!/bin/bash

. ../libtest.sh

EXEC="./acvp-proxy"
NAME="$(basename $EXEC)"

ACTUALDIR="actual"
EXPECTEDDIR="expected"
LOGDIR="logs"

ACTUALRES="-actual.json"
EXPECTEDRES="-expected.json"
LOGFILE=".log"

# Set to 1 to generate expected results for all tests
GENERATE=0

generate_expected()
{
	local testtype=$1

	local result=$($EXEC -q -m "${testtype}" -f -s ${testtype}/secure-datastore/ -b ${testtype}/testvectors/ -d ${testtype}/acvpproxy_0.5/ --publish --dump-register > "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}")

	if [ $? -ne 0 ]
	then
		echo_fail "Generate $testtype: $result"
	else
		echo_pass "Generate $testtype"
	fi
}

test_common()
{
	local testtype=$1

	if [ $GENERATE -ne 0 ]
	then
		generate_expected $testtype
		return
	fi

	local result=$($EXEC -v -v -v -m "${testtype}" -f -s ${testtype}/secure-datastore/ -b ${testtype}/testvectors/ -d ${testtype}/acvpproxy_0.5/ --publish --dump-register 2>"${LOGDIR}/${testtype}${LOGFILE}" > "${ACTUALDIR}/${testtype}${ACTUALRES}")
	if [ $? -ne 0 ]
	then
		echo_fail "Publish $testtype: $result"
		return
	fi

	# we cannot use the parser's match logic as the output contains
	# several fully complete JSON constructs
#	result=$($EXEC -s ${testtype}/secure-datastore/ -b ${testtype}/testvectors/ -d ${testtype}/acvpproxy_0.5/ --match-expected "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}" --match-actual "${ACTUALDIR}/${testtype}${ACTUALRES}")
result=$(diff -wB "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}" "${ACTUALDIR}/${testtype}${ACTUALRES}")

	if [ $? -ne 0 ]
	then
		echo_fail "Publish $testtype: $result"
	else
		echo_pass "Publish $testtype"
	fi

	gcov_analyze "../../lib/acvp_testsession_publish.c" "$testtype"
	gcov_analyze "../../lib/definition.c" "$testtype"
}

init()
{
	if [ ! -d ${ACTUALDIR} ]
	then
		mkdir ${ACTUALDIR}
	fi

	if [ ! -d ${EXPECTEDDIR} ]
	then
		mkdir ${EXPECTEDDIR}
	fi

	if [ ! -d ${LOGDIR} ]
	then
		mkdir ${LOGDIR}
	fi
}

init_common
init

test_common "ACVPProxy"

exit_test
