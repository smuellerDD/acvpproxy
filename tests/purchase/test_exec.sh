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

	local result=$($EXEC -q -c ./acvpproxy_conf.json --purchase ${testtype} --dump-register > "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}")

	if [ $? -ne 0 ]
	then
		echo_fail "Generate purchase request $testtype: $result"
	else
		echo_pass "Generate purchase request $testtype"
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

	local result=$($EXEC -v -v -v -c ./acvpproxy_conf.json --purchase ${testtype}  --dump-register 2>"${LOGDIR}/${testtype}${LOGFILE}" > "${ACTUALDIR}/${testtype}${ACTUALRES}")

	if [ $? -ne 0 ]
	then
		echo_fail "Purchase request $testtype: $result"
		return
	fi

	result=$(diff -urN "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}" "${ACTUALDIR}/${testtype}${ACTUALRES}")

	if [ $? -ne 0 ]
	then
		echo_fail "Purchase request $testtype: $result"
	else
		echo_pass "Purchase request $testtype"
	fi
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

gcov_analysis()
{
	gcov_analyze "../../lib/acvp/acvp_payment.c" "test_common"
}

init_common
init

test_common "1"
test_common "2"
test_common "3"

gcov_analysis

exit_test
