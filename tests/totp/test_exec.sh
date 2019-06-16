#!/bin/bash

. ../libtest.sh

EXEC="./totp"
NAME="$(basename $EXEC)"

# Test 1
#
# Purpose: Execute RFC 4226 HOTP tests
# Expected result: Test results match expected results listed in RFC 4226
test1()
{
	local result=$($EXEC)

	if [ $? -ne 0 ]
	then
		echo_fail "Test $NAME 1: $result"
	else
		echo_pass "Test $NAME 1"
	fi

	gcov_analyze "totp_test.c" "test1"
}

init_common

test1

exit_test
