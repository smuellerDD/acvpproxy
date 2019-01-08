/*
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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

int main(int argc, char *argv[])
{
	uint32_t totp_val, i;
	int ret;
	uint8_t seed[10] = { 0 };

	(void)argc;
	(void)argv;

	thread_init(1);
	sig_install_handler();

	logger_set_verbosity(LOGGER_NONE);

	ret = totp_set_seed(seed, sizeof(seed), 0, NULL);
	if (ret < 0)
		goto out;

	for (i = 0; i < 3; i++) {
		CKINT(totp(&totp_val));
		printf("%u\n", totp_val);
	}

out:
	totp_release_seed();
	thread_release(1, 1);
	sig_uninstall_handler();
	return -ret;
}
