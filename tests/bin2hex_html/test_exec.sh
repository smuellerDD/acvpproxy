#!/bin/bash

. ../libtest.sh

EXEC="./bin2hex_html"
NAME="$(basename $EXEC)"

# Test 1
#
# Purpose: convert provided string and compare it with expected string
# Expected result: Test results match with expected string
test1()
{
	local input=$1
	local expected=$2

	if [ -z "$input" -o -z "$expected" ]
	then
		echo_fail "Missing data"
		return
	fi

	local result=$($EXEC $input)

	if [ $? -ne 0 ]
	then
		echo_fail "Test $NAME: $result"
		return
	fi

	if [ x"$result" != x"$expected" ]
	then
		echo_fail "Test $NAME: $result"
	else
		echo_pass "Test $NAME: $result"
	fi

	gcov_analyze "../../lib/acvp/binhexbin.c" "test1"
}

init_common

# URL conversion
test1 "http://www.chronox.de/foo/bar.html" "http%3A%2F%2Fwww.chronox.de%2Ffoo%2Fbar.html"

# Parameter conversion
test1 "http://www.chronox.de/foo/bar.html?arg1=foo&arg2=bar" "http%3A%2F%2Fwww.chronox.de%2Ffoo%2Fbar.html%3Farg1%3Dfoo%26arg2%3Dbar"

# Keep ACVP server parameter unchanged
test1 "http://www.chronox.de/foo/bar.html?arg1=foo&arg2=bar?arg3[0]=baz" "http%3A%2F%2Fwww.chronox.de%2Ffoo%2Fbar.html%3Farg1%3Dfoo%26arg2%3Dbar%3Farg3%5B0%5D%3Dbaz"

# Conversion of non-ASCII-7 characters
test1 "http://www.chronox.de/foo/bar.html?äöüß" "http%3A%2F%2Fwww.chronox.de%2Ffoo%2Fbar.html%3F%C3%A4%C3%B6%C3%BC%C3%9F"

exit_test
