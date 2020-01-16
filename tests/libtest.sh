#!/bin/bash
#
# Copyright (C) 2017 - 2020, Stephan Mueller <smueller@chronox.de>
#
# License: see LICENSE file in root directory
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
# WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
#
# Common code for test cases
#

#####################################################################
# Common functions
#####################################################################

failures=0
GCOV=$(type -p gcov)
GCOV_LOGDIR="gcov"

# color -- emit ansi color codes
color()
{
	bg=0
	echo -ne "\033[0m"
	while [[ $# -gt 0 ]]; do
		code=0
		case $1 in
			black) code=30 ;;
			red) code=31 ;;
			green) code=32 ;;
			yellow) code=33 ;;
			blue) code=34 ;;
			magenta) code=35 ;;
			cyan) code=36 ;;
			white) code=37 ;;
			background|bg) bg=10 ;;
			foreground|fg) bg=0 ;;
			reset|off|default) code=0 ;;
			bold|bright) code=1 ;;
		esac
		[[ $code == 0 ]] || echo -ne "\033[$(printf "%02d" $((code+bg)))m"
		shift
	done
}

echo_pass()
{
	echo $(color "green")[PASSED]$(color off) $@
}

echo_fail()
{
	echo $(color "red")[FAILED]$(color off) $@
	failures=$(($failures+1))
}

echo_deact()
{
	echo $(color "yellow")[DEACTIVATED]$(color off) $@
}

echo_info()
{
	echo $(color "blue")[INFO]$(color off) $@
}


echo_final()
{
	echo "==================================================="
	if [ $failures -eq 0 ]
	then
		echo_pass "ALL TESTS PASSED"
	else
		echo_fail "TEST FAILURES: $failures"
	fi
}

exit_test()
{
	exit $failures
}

init_common()
{
	trap "make -s clean; exit" 0 1 2 3 15

	make clean

	if [ -x "${GCOV}" ]
	then
		make -s gcov
	else
		make -s
	fi
}

gcov_analyze()
{
	local file=$1
	local tag=$2

	if [ ! -f "$file" ]
	then
		return
	fi

	if [ ! -x "${GCOV}" ]
	then
		return
	fi

	if [ ! -d "${GCOV_LOGDIR}" ]
	then
		mkdir ${GCOV_LOGDIR} 2>/dev/null
		if [ $? -ne 0 ]
		then
			return
		fi
	fi

	local gcov_log=$(basename $file)
	gcov_log="${gcov_log}.${tag}.gcov_log"
	${GCOV} $file > ${GCOV_LOGDIR}/$gcov_log
}
