/*
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>

#include "logger.h"
#include "internal.h"
#include "threading_support.h"
#include "totp.h"

static int test_thread(void *arg)
{
	uint32_t totp_val, i;
	int ret = 0;

	(void)arg;

	for (i = 0; i < 3; i++) {
		CKINT(totp(&totp_val));
		printf("%u\n", totp_val);
	}

out:
	return ret;
}

int main(int argc, char *argv[])
{
	unsigned int i;
	int ret;
	uint8_t seed[10] = { 0 };

	(void)argc;
	(void)argv;

#ifdef TESTDEBUG
	logger_set_verbosity(LOGGER_DEBUG);
#else
	logger_set_verbosity(LOGGER_NONE);
#endif

	CKINT(thread_init(1));
	CKINT(sig_install_handler());

	CKINT(totp_set_seed(seed, sizeof(seed), 0, 0, NULL));

	for (i = 0; i < 3; i++) {
		CKINT(thread_start(test_thread, NULL, 0, NULL));
		logger(LOGGER_DEBUG, LOGGER_C_ANY, "Thread %u started %d\n", i, ret);
	}

out:
	ret |= thread_wait();
	totp_release_seed();
	thread_release(1, 1);
	sig_uninstall_handler();
	return -ret;
}
