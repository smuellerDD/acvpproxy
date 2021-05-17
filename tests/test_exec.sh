#!/bin/bash

. ./libtest.sh

EXEC="test_exec.sh"

for i in *
do
	if [ ! -x "$i/$EXEC" ]
	then
		continue
	fi

	cd $i
	./$EXEC
	res=$?
	cd ..
	failures=$(($failures+$res))
done

echo_final
exit_test
