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

generate_expected()
{
	local testtype=$1

	local result=$($EXEC -q -m "Tests (${testtype})" --request --dump-register > "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}")

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

	local result=$($EXEC -v -v -v -m "Tests (${testtype})" --request --dump-register 2>"${LOGDIR}/${testtype}${LOGFILE}" > "${ACTUALDIR}/${testtype}${ACTUALRES}")

	if [ $? -ne 0 ]
	then
		echo_fail "Request $testtype: $result"
		return
	fi

	result=$($EXEC --match-expected "${EXPECTEDDIR}/${testtype}${EXPECTEDRES}" --match-actual "${ACTUALDIR}/${testtype}${ACTUALRES}")

	if [ $? -ne 0 ]
	then
		echo_fail "Request $testtype: $result"
	else
		echo_pass "Request $testtype"
	fi
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

gcov_analysis()
{
	gcov_analyze "../../lib/request_cipher_sha.c" "test_common"
	gcov_analyze "../../lib/request_cipher_hmac.c" "test_common"
	gcov_analyze "../../lib/request_cipher_shake.c" "test_common"
	gcov_analyze "../../lib/request_cipher_sym.c" "test_common"
	gcov_analyze "../../lib/request_cipher_drbg.c" "test_common"
	gcov_analyze "../../lib/request_cipher_rsa.c" "test_common"
	gcov_analyze "../../lib/request_cipher_dsa.c" "test_common"
	gcov_analyze "../../lib/request_cipher_ecdsa.c" "test_common"
	gcov_analyze "../../lib/request_cipher_kas_ecc.c" "test_common"
	gcov_analyze "../../lib/request_cipher_kas_ffc.c" "test_common"
	gcov_analyze "../../lib/request_cipher_kdf_108.c" "test_common"
	gcov_analyze "../../lib/request_cipher_kdf_ikev1.c" "test_common"
	gcov_analyze "../../lib/request_cipher_kdf_ikev2.c" "test_common"
	gcov_analyze "../../lib/request_cipher_kdf_ssh.c" "test_common"
	gcov_analyze "../../lib/request_cipher_kdf_tls.c" "test_common"
	gcov_analyze "../../lib/request_cipher_pbkdf.c" "test_common"
	gcov_analyze "../../lib/request_cipher_eddsa.c" "test_common"
}

init_common
init

test_common "SHA"
test_common "HMAC"
test_common "SHAKE"
test_common "AES-SYM"
test_common "AES-AEAD"
test_common "TDES-SYM"
test_common "DRBG"
test_common "RSA"
test_common "DSA"
test_common "ECDSA"
test_common "KAS-ECC"
test_common "KAS-FFC"
test_common "KDF"
test_common "EDDSA"

gcov_analysis

exit_test
