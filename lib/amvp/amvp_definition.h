/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef AMVP_DEFINITION_H
#define AMVP_DEFINITION_H

#include "definition_internal.h"
#include "json_wrapper.h"
#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

struct amvp_def {
	struct json_object *validation_definition;
	struct json_object *registration_definition;

	/* SP parts */
	char *logo_file;
	char *sp_template_file;
	struct json_object *sp_general;
	struct json_object *sp_crypt_mod_interfaces;
	struct json_object *sp_crypt_mod_spec;
	struct json_object *sp_lifecycle;
	struct json_object *sp_oe;
	struct json_object *sp_mitigation_other_attacks;
	struct json_object *sp_non_invasive_sec;
	struct json_object *sp_phys_sec;
	struct json_object *sp_roles_services;
	struct json_object *sp_self_tests;
	struct json_object *sp_ssp_mgmt;
	struct json_object *sp_sw_fw_sec;
};

/*
 * The order of states matter: their order shows the order of processing states
 * and thus its order should match the order applied by the AMVP server.
 */
enum amvp_request_state {
	AMVP_REQUEST_STATE_UNKNOWN,
	AMVP_REQUEST_STATE_INITIAL,
	AMVP_REQUEST_STATE_ONGOING,
	AMVP_REQUEST_STATE_PENDING_PROCESSING_SUBMISSION,
	AMVP_REQUEST_STATE_PENDING_GENERATION,
	AMVP_REQUEST_STATE_PENDING_PROCESSING_GENERATION,
	AMVP_REQUEST_STATE_COMPLETED,
	AMVP_REQUEST_STATE_COMPLETED_OVERALL,
	AMVP_REQUEST_STATE_IN_REVIEW,
	AMVP_REQUEST_STATE_APPROVED,

	/* must be last */
	AMVP_REQUEST_STATE_REJECTED,
};

struct amvp_state {
	/* Overall certificate request state */
	enum amvp_request_state overall_state;

	/*
	 * The following states are only non-zero if all evidence for the
	 * respective part is submitted as only then the AMVP server can
	 * return a meaningful state.
	 */
	enum amvp_request_state sp_state; /* SP submission state */
	enum amvp_request_state ft_te_state; /* Functional testing TE state */

#define AMVP_CERTIFICATE_BUF_SIZE	8
	char certificate[AMVP_CERTIFICATE_BUF_SIZE];

	bool test_report_template_fetched;
	bool submit_once_done;

	bool esv_certs_submitted;
	bool cavp_certs_submitted;

#define AMVP_SP_LAST_CHAPTER 12
#define AMVP_SP_HASH_SIZE SHA256_SIZE_DIGEST

	/*
	 * Hash of the SP template file
	 */
	uint8_t *sp_template_hash;

	/*
	 * hash in binary form - to ensure we do not need to reallocate the
	 * buffer when changing the hash
	 */
	uint8_t *sp_chapter_hash[AMVP_SP_LAST_CHAPTER];
};

struct definition;

void amvp_def_free(struct amvp_def *amvp);
int amvp_def_config(const char *directory, const struct definition *def,
		    struct amvp_def **amvp);


#ifdef __cplusplus
}
#endif

#endif /* AMVP_DEFINITION_H */
