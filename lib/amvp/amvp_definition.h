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

enum amvp_request_state {
	AMVP_REQUEST_STATE_UNKNOWN,
	AMVP_REQUEST_STATE_ONGOING,
	AMVP_REQUEST_STATE_COMPLETED,
	AMVP_REQUEST_STATE_APPROVED,
};

enum amvp_sp_state {
	AMVP_SP_STATE_UNKNOWN,
	AMVP_SP_STATE_PROCESSED,
	AMVP_SP_OPEN_CHAPTER_1 = 1 << 10,
	AMVP_SP_OPEN_CHAPTER_2 = 1 << 11,
	AMVP_SP_OPEN_CHAPTER_3 = 1 << 12,
	AMVP_SP_OPEN_CHAPTER_4 = 1 << 13,
	AMVP_SP_OPEN_CHAPTER_5 = 1 << 14,
	AMVP_SP_OPEN_CHAPTER_6 = 1 << 15,
	AMVP_SP_OPEN_CHAPTER_7 = 1 << 16,
	AMVP_SP_OPEN_CHAPTER_8 = 1 << 17,
	AMVP_SP_OPEN_CHAPTER_9 = 1 << 18,
	AMVP_SP_OPEN_CHAPTER_10 = 1 << 19,
	AMVP_SP_OPEN_CHAPTER_11 = 1 << 20,
	AMVP_SP_OPEN_CHAPTER_12 = 1 << 21,
};

struct amvp_state {
	enum amvp_request_state request_state;
	bool test_report_template_fetched;

#define AMVP_SP_LAST_CHAPTER 12
#define AMVP_SP_HASH_SIZE SHA256_SIZE_DIGEST
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
