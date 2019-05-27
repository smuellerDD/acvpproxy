#!/bin/bash

. ../libtest.sh

EXEC="./bin2hex"
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
}

init()
{
	trap "make -s clean; exit" 0 1 2 3 15

	make -s
}

init

test1

exit_test
