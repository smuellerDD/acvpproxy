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

#
# Test the internal dependency resolution.
#
# This test verifies that there is an automated dependency resolution
# The key output in the expected result is the following:
#
# [
#   {
#     "acvVersion":"1.0"
#   },
#   {
#     "moduleUrl":"/acvp/v1/modules/11983",
#     "oeUrl":"/acvp/v1/oes/22796",
#     "algorithmPrerequisites":[
#       {
#         "algorithm":"ACVP-AES-GCM",
#         "prerequisites":[
#           {
#             "algorithm":"AES",
#             "validationId":"A99"
#           },
#           {
#             "algorithm":"DRBG",
#             "validationId":"A100"
#           }
#         ]
#       },
#       {
#         "algorithm":"ACVP-AES-GCM",
#         "prerequisites":[
#           {
#             "algorithm":"AES",
#             "validationId":"A99"
#           },
#           {
#             "algorithm":"DRBG",
#             "validationId":"A100"
#           }
#         ]
#       },
#       {
#         "algorithm":"ctrDRBG",
#         "prerequisites":[
#           {
#             "algorithm":"AES",
#             "validationId":"A99"
#           }
#         ]
#       }
#     ]
#   }
# ]
#
# This output shows that the dependency for AES is satisfied by the certificate
# A99 (AESNI). The dependency for the DRBG is satisifed by the certificate
# A100 (AESNI_ASM).
#
generate_expected()
{
	local testtype=$1

	local result=$($EXEC -vvv -s ${testtype}/secure-datastore/ -b ${testtype}/testvectors/ -d ${testtype}/openssl/ --publish --dump-register > "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}" 2>"/dev/null")

	if [ $? -ne 0 ]
	then
		echo_fail "Generate $testtype: $result"
	else
		echo_pass "Generate $testtype"
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

	local result=$($EXEC -v -v -v -s ${testtype}/secure-datastore/ -b ${testtype}/testvectors/ -d ${testtype}/openssl/ --publish --dump-register 2>"${LOGDIR}/${testtype}${LOGFILE}" > "${ACTUALDIR}/${testtype}${ACTUALRES}")
	if [ $? -ne 0 ]
	then
		echo_fail "Publish $testtype: $result"
		return
	fi

	# we cannot use the parser's match logic as the output contains
	# several fully complete JSON constructs
#	result=$($EXEC -s ${testtype}/secure-datastore/ -b ${testtype}/testvectors/ -d ${testtype}/acvpproxy_0.5/ --match-expected "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}" --match-actual "${ACTUALDIR}/${testtype}${ACTUALRES}")
	result=$(diff -wB "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}" "${ACTUALDIR}/${testtype}${ACTUALRES}")

	if [ $? -ne 0 ]
	then
		echo_fail "Publish internal dependencies $testtype: $result"
	else
		echo_pass "Publish internal dependencies $testtype"
	fi

	gcov_analyze "../../lib/acvp_testsession_publish.c" "$testtype"
	gcov_analyze "../../lib/definition.c" "$testtype"
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

init_common
init

test_common "openssl"

exit_test
