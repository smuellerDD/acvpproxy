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

	if [ $(echo $res1 | wc -w) -eq 9 -a \
	     $(echo $res2 | wc -w) -eq 9 ]
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
	test_kill_caller2 2 5 9
}

# Test 3
#
# Purpose: Have 2 concurrent callers. Caller 2 is spawned 5 seconds after the
#	   first caller and is terminated 35 seconds later.
# Expected result: First caller obtains all TOTP values
test3()
{
	test_kill_caller2 3 35 9
}

# Test 4
#
# Purpose: Have 2 concurrent callers. Caller 2 is spawned 5 seconds after the
#	   first caller, first caller is terminated 5 seconds later.
# Expected result: 2nd caller receives all TOTP values
test4()
{
	test_kill_caller1 4 5 9
}

# Test 5
#
# Purpose: Have 2 concurrent callers. Caller 2 is spawned 5 seconds after the
#	   first caller, first caller is terminated 35 seconds later.
# Expected result: 2nd caller receives all TOTP values
test5()
{
	test_kill_caller1 5 35 9
}

# Test 6
#
# Purpose: Have 10 concurrent callers which both execute till completion
# Expected result: All callers obtain all requested TOTP values
test6()
{
	make clean
	CFLAGS="$CFLAGS -DTOTP_STEP_SIZE=3" make -s

	($EXEC > $OUTDIR/t6_p1) &
	local pid1=$!

	sleep 2
	($EXEC >> $OUTDIR/t6_p2 ) &
	local pid2=$!

	sleep 2
	($EXEC >> $OUTDIR/t6_p3 ) &
	local pid3=$!

	echo_info "Disregard following notification about process killing"
	kill -9 $pid1

	sleep 2
	($EXEC >> $OUTDIR/t6_p4 ) &
	local pid4=$!

	sleep 2
	($EXEC >> $OUTDIR/t6_p5 ) &
	local pid5=$!

	sleep 2
	($EXEC >> $OUTDIR/t6_p6 ) &
	local pid6=$!

	sleep 2
	($EXEC >> $OUTDIR/t6_p7 ) &
	local pid7=$!

	sleep 2
	($EXEC >> $OUTDIR/t6_p8 ) &
	local pid8=$!

	sleep 2
	($EXEC >> $OUTDIR/t6_p9 ) &
	local pid9=$!

	sleep 2
	($EXEC >> $OUTDIR/t6_p10 ) &
	local pid10=$!

	wait $pid2 $pid3 $pid4 $pid5 $pid6 $pid7 $pid8 $pid9 $pid10

	local res2=$(cat $OUTDIR/t6_p2)
	local res3=$(cat $OUTDIR/t6_p3)
	local res4=$(cat $OUTDIR/t6_p4)
	local res5=$(cat $OUTDIR/t6_p5)
	local res6=$(cat $OUTDIR/t6_p6)
	local res7=$(cat $OUTDIR/t6_p7)
	local res8=$(cat $OUTDIR/t6_p8)
	local res9=$(cat $OUTDIR/t6_p9)
	local res10=$(cat $OUTDIR/t6_p10)

	if [ $(echo $res2 | wc -w) -eq 9 -a \
	     $(echo $res3 | wc -w) -eq 9 -a \
	     $(echo $res4 | wc -w) -eq 9 -a \
	     $(echo $res5 | wc -w) -eq 9 -a \
	     $(echo $res6 | wc -w) -eq 9 -a \
	     $(echo $res7 | wc -w) -eq 9 -a \
	     $(echo $res8 | wc -w) -eq 9 -a \
	     $(echo $res9 | wc -w) -eq 9 -a \
	     $(echo $res10 | wc -w) -eq 9 ]
	then
		echo_pass "Test $NAME 6"
	else
		echo_fail "Test $NAME 6: $res2 | $res3 | $res4 | $res5 | $res6 | $res7 | $res8 | $res9 | $res10"
	fi
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

	CFLAGS="-DTOTP_STEP_SIZE=10" make -s

	echo_info "Testing $NAME commences - may take several minutes per test"
}

test7()
{
	local prepid=0
	local i=0

	while [ $i -lt 100 ]

	do
		( ./totp_mq_server )&
		local b=$!;

		i=$((i+1))

		sleep 1
		if [ $prepid -ne 0 ]
		then
			kill -9 $prepid
			echo "killed $prepaid"
		fi;

		prepid=$b
	done

	wait $prepid
	echo_pass "Test $NAME 7"
}

init

test1
test2
test3
test4
test5
test6
test7

exit_test
