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
}

init()
{
	trap "make -s clean; exit" 0 1 2 3 15

	make -s
}

init

test1

exit_test
