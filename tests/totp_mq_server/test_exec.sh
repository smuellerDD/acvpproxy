#!/bin/bash

. ../libtest.sh

EXEC="./totp_mq_server"
NAME="$(basename $EXEC)"
OUTDIR="/tmp/totp_mq_server_test"

# Test 1
#
# Purpose: Have 2 concurrent callers which both execute till completion
# Expected result: Both callers obtain all requested TOTP values
test1()
{
	($EXEC > $OUTDIR/t1_p1) &
	local pid1=$!

	sleep 5
	($EXEC >> $OUTDIR/t1_p2 ) &
	local pid2=$!

	wait $pid1 $pid2

	local res1=$(cat $OUTDIR/t1_p1)
	local res2=$(cat $OUTDIR/t1_p2)

	if [ $(echo $res1 | wc -w) -eq 3 -a \
	     $(echo $res2 | wc -w) -eq 3 ]
	then
		echo_pass "Test $NAME 1"
	else
		echo_fail "Test $NAME 1: $res1 | $res2"
	fi
}

test_kill_caller2()
{
	local testcase=$1
	local kill_caller_sec=$2
	local exp_res1=$3

	$EXEC > $OUTDIR/t${testcase}_p1 &
	local pid1=$!

	sleep 5
	$EXEC > /dev/null &
	local pid2=$!

	sleep $kill_caller_sec
	kill -SIGQUIT $pid2

	wait $pid1

	local res1=$(cat $OUTDIR/t${testcase}_p1)

	if [ $(echo $res1 | wc -w) -eq $exp_res1 ]
	then
		echo_pass "Test $NAME ${testcase}"
	else
		echo_fail "Test $NAME ${testcase}: $res1"
	fi
}

test_kill_caller1()
{
	local testcase=$1
	local kill_caller_sec=$2
	local exp_res2=$3

	($EXEC > /dev/null) &
	local pid1=$!

	sleep 5
	($EXEC > $OUTDIR/t${testcase}_p2) &
	local pid2=$!

	sleep $kill_caller_sec
	kill -SIGQUIT $pid1

	wait $pid2

	local res2=$(cat $OUTDIR/t${testcase}_p2)

	if [ $(echo $res2 | wc -w) -eq $exp_res2 ]
	then
		echo_pass "Test $NAME ${testcase}"
	else
		echo_fail "Test $NAME ${testcase}: $res1 | $res2"
	fi
}

# Test 2
#
# Purpose: Have 2 concurrent callers. Caller 2 is spawned 5 seconds after the
#	   first caller and is terminated 5 seconds later.
# Expected result: First caller obtains all TOTP values
test2()
{
	test_kill_caller2 2 5 3
}

# Test 3
#
# Purpose: Have 2 concurrent callers. Caller 2 is spawned 5 seconds after the
#	   first caller and is terminated 35 seconds later.
# Expected result: First caller obtains all TOTP values
test3()
{
	test_kill_caller2 3 35 3
}

# Test 4
#
# Purpose: Have 2 concurrent callers. Caller 2 is spawned 5 seconds after the
#	   first caller, first caller is terminated 5 seconds later.
# Expected result: 2nd caller receives all TOTP values
test4()
{
	test_kill_caller1 4 5 3
}

# Test 5
#
# Purpose: Have 2 concurrent callers. Caller 2 is spawned 5 seconds after the
#	   first caller, first caller is terminated 35 seconds later.
# Expected result: 2nd caller receives all TOTP values
test5()
{
	test_kill_caller1 5 35 3
}

init()
{
	trap "rm -rf $OUTDIR; make -s clean; exit" 0 1 2 3 15
	mkdir $OUTDIR 2>/dev/null
	if [ $? -ne 0 ]
	then
		echo_fail "Cannot create directory $OUTDIR"
		exit 1
	fi

	make -s

	echo "Testing $NAME commences - may take several minutes per test"
}

init

test1
test2
test3
test4
test5

exit_test
