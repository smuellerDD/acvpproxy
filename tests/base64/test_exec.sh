#!/bin/bash

. ../libtest.sh

EXEC="./base64"
NAME="$(basename $EXEC)"

# Test 1
#
# Purpose: Execute RFC4648 chapter 10 tests
# Expected result: Test results match expected results listed in RFC
test1()
{
	local result=$($EXEC)

	if [ $? -ne 0 ]
	then
		echo_fail "Test $NAME 1: $result"
	else
		echo_pass "Test $NAME 1"
	fi

	gcov_analyze "../../apps/base64.c" "test1"
}

init_common

test1

exit_test
