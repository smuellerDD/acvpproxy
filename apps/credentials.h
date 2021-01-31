/*
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
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

#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include "json-c/json.h"

#ifdef __cplusplus
extern "C" {
#endif

struct opt_cred {
	char *configfile;
	struct json_object *config;

	const char *tlskey;
	const char *tlspasscode;
	const char *tlscert;
	const char *tlscertkeychainref;
	const char *tlscabundle;
	const char *tlscakeychainref;
	const char *seedfile;
};

int set_totp_seed(struct opt_cred *cred, const bool official_testing,
		  const bool enable_net);
int load_config(struct opt_cred *cred);
void cred_free(struct opt_cred *cred);
void last_gen_cb(const time_t now);

#ifdef __cplusplus
}
#endif

#endif /* CREDENTIALS_H */
