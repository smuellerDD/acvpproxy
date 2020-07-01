#!/bin/bash

. ../libtest.sh

EXEC="../../acvp-proxy"
NAME="$(basename $EXEC)"

TESTVECTORS_ORIG="testvectors.orig"
SECUREDATASTORE_ORIG="secure-datastore.orig"
TESTVECTORS="testvectors"
SECUREDATASTORE="secure-datastore"
MODULE_DEF_DIR="nettle_3.4"
MODULE_DEF_DIR_TMP="${MODULE_DEF_DIR}_tmp"
MODULE_DEF_DIR_NEWNAME="nettle_3.4_newname"
MODULE_DEF_DIR_NEWVER="nettle_3.4_newver"
MODULE_DEF_DIR_NEWOENAME="nettle_3.4_newoename"
LOGDIR="logs"

LOGFILE=".log"

init_test()
{
	cp -r $MODULE_DEF_DIR $MODULE_DEF_DIR_TMP
}

cleanup_test()
{
	rm -rf $MODULE_DEF_DIR_TMP
}

cleanup()
{
	rm -rf $SECUREDATASTORE
	rm -rf $TESTVECTORS
	cleanup_test
}

init_dirs()
{
	cp -r $TESTVECTORS_ORIG $TESTVECTORS
	cp -r $SECUREDATASTORE_ORIG $SECUREDATASTORE
	cp -r $MODULE_DEF_DIR $MODULE_DEF_DIR_TMP
}

#
# Test rename module name
#
# Purpose: Rename a module name
# Expected result: Rename is successful and module listing after rename works
#		   and shows a listing
test_rename_name()
{
	cleanup
	init_dirs

	local result=$($EXEC -vvv -c acvpproxy_conf.json -d $MODULE_DEF_DIR -b $TESTVECTORS -s $SECUREDATASTORE -m Nettle -f --list-verdicts > $LOGDIR/rename_name_1${LOGFILE} 2>&1)
	if [ $? -ne 0 ]
	then
		echo_fail "Rename name: $result"
		return
	fi

	if ! (cat $LOGDIR/rename_name_1${LOGFILE} | tail -n3 | grep -q PASSED)
	then
		echo_fail "Rename name: Cannot find verdict listing in test log $LOGDIR/rename_name_1${LOGFILE}"
		return
	fi

	local result=$($EXEC -vvv -c acvpproxy_conf.json -d $MODULE_DEF_DIR_TMP -b $TESTVECTORS -s $SECUREDATASTORE -m Nettle -f --rename-name Nettle-newname > $LOGDIR/rename_name_2${LOGFILE} 2>&1)

	if [ $? -ne 0 ]
	then
		echo_fail "Rename name: $result"
		return
	fi

	local result=$($EXEC -vvv -c acvpproxy_conf.json -d $MODULE_DEF_DIR_NEWNAME -b $TESTVECTORS -s $SECUREDATASTORE -m Nettle-newname -f --list-verdicts > $LOGDIR/rename_name_3${LOGFILE} 2>&1)
	if [ $? -ne 0 ]
	then
		echo_fail "Rename name: $result"
		return
	fi

	local result=$(diff -urN $MODULE_DEF_DIR_TMP $MODULE_DEF_DIR_NEWNAME > $LOGDIR/rename_name_4${LOGFILE} 2>&1)
	if [ $? -ne 0 ]
	then
		echo_fail "Rename name: $result"
		return
	fi

	if ! (cat $LOGDIR/rename_name_3${LOGFILE} | tail -n3 | grep -q PASSED)
	then
		echo_fail "Rename name: Cannot find verdict listing in test log $LOGDIR/rename_name_3${LOGFILE}"
		return
	fi

	echo_pass "Rename name"
}

#
# Test rename module version string
#
# Purpose: Rename a module version string
# Expected result: Rename is successful and module listing after rename works
#		   and shows a listing
test_rename_version()
{
	cleanup
	init_dirs

	local result=$($EXEC -vvv -c acvpproxy_conf.json -d $MODULE_DEF_DIR -b $TESTVECTORS -s $SECUREDATASTORE -m Nettle -f --list-verdicts > $LOGDIR/rename_version_1${LOGFILE} 2>&1)
	if [ $? -ne 0 ]
	then
		echo_fail "Rename version: $result"
		return
	fi

	if ! (cat $LOGDIR/rename_version_1${LOGFILE} | tail -n3 | grep -q PASSED)
	then
		echo_fail "Rename version: Cannot find verdict listing in test log $LOGDIR/rename_version_1${LOGFILE}"
		return
	fi

	local result=$($EXEC -vvv -c acvpproxy_conf.json -d $MODULE_DEF_DIR_TMP -b $TESTVECTORS -s $SECUREDATASTORE -m Nettle -f --rename-version 3.5 > $LOGDIR/rename_version_2${LOGFILE} 2>&1)

	if [ $? -ne 0 ]
	then
		echo_fail "Rename version: $result"
		return
	fi

	local result=$($EXEC -vvv -c acvpproxy_conf.json -d $MODULE_DEF_DIR_NEWVER -b $TESTVECTORS -s $SECUREDATASTORE -m Nettle -f --list-verdicts > $LOGDIR/rename_version_3${LOGFILE} 2>&1)
	if [ $? -ne 0 ]
	then
		echo_fail "Rename version: $result"
		return
	fi

	local result=$(diff -urN $MODULE_DEF_DIR_TMP $MODULE_DEF_DIR_NEWVER > $LOGDIR/rename_version_4${LOGFILE} 2>&1)
	if [ $? -ne 0 ]
	then
		echo_fail "Rename name: $result"
		return
	fi

	if ! (cat $LOGDIR/rename_version_3${LOGFILE} | tail -n3 | grep -q PASSED)
	then
		echo_fail "Rename version: Cannot find verdict listing in test log $LOGDIR/rename_version_3${LOGFILE}"
		return
	fi

	echo_pass "Rename version"
}

#
# Test rename OE name string
#
# Purpose: Rename a OE name string
# Expected result: Rename is successful and module listing after rename works
#		   and shows a listing
test_rename_oename()
{
	cleanup
	init_dirs

	local result=$($EXEC -vvv -c acvpproxy_conf.json -d $MODULE_DEF_DIR -b $TESTVECTORS -s $SECUREDATASTORE -m Nettle -f --list-verdicts > $LOGDIR/rename_oename_1${LOGFILE} 2>&1)
	if [ $? -ne 0 ]
	then
		echo_fail "Rename oename: $result"
		return
	fi

	if ! (cat $LOGDIR/rename_oename_1${LOGFILE} | tail -n3 | grep -q PASSED)
	then
		echo_fail "Rename oename: Cannot find verdict listing in test log $LOGDIR/rename_oename_1${LOGFILE}"
		return
	fi

	local result=$($EXEC -vvv -c acvpproxy_conf.json -d $MODULE_DEF_DIR_TMP -b $TESTVECTORS -s $SECUREDATASTORE -m Nettle -f --rename-oename "Fedora 30" > $LOGDIR/rename_oename_2${LOGFILE} 2>&1)

	if [ $? -ne 0 ]
	then
		echo_fail "Rename oename: $result"
		return
	fi

	local result=$($EXEC -vvv -c acvpproxy_conf.json -d $MODULE_DEF_DIR_NEWOENAME -b $TESTVECTORS -s $SECUREDATASTORE -m Nettle -f --list-verdicts > $LOGDIR/rename_oename_3${LOGFILE} 2>&1)
	if [ $? -ne 0 ]
	then
		echo_fail "Rename oename: $result"
		return
	fi

	local result=$(diff -urN $MODULE_DEF_DIR_TMP $MODULE_DEF_DIR_NEWOENAME > $LOGDIR/rename_oename_4${LOGFILE} 2>&1)
	if [ $? -ne 0 ]
	then
		echo_fail "Rename name: $result"
		return
	fi

	if ! (cat $LOGDIR/rename_oename_3${LOGFILE} | tail -n3 | grep -q PASSED)
	then
		echo_fail "Rename oename: Cannot find verdict listing in test log $LOGDIR/rename_oename_3${LOGFILE}"
		return
	fi

	echo_pass "Rename oename"
}

init()
{
	trap "cleanup; make -s -C ../../ clean; exit"  0 1 2 3 15

	if [ ! -d ${LOGDIR} ]
	then
		mkdir ${LOGDIR}
	fi

	make -s -C ../../ clean
	make -s -C ../../
}

init

init_test
test_rename_name
cleanup_test

init_test
test_rename_version
cleanup_test

init_test
test_rename_oename
cleanup_test

exit_test
