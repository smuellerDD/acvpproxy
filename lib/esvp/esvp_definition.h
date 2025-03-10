/*
 * Copyright (C) 2021 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESVP_DEFINITION_H
#define ESVP_DEFINITION_H

#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

struct esvp_sd_file_def {
	char *filename;
 	bool submitted;
	struct acvp_buf data_hash;
	struct esvp_sd_file_def *next;
};

enum esvp_document_type {
	esvp_document_unknown,
	esvp_document_other,
	esvp_document_ear,
	esvp_document_pud,
	esvp_document_attestation,
};

struct esvp_sd_def {
	struct acvp_auth_ctx *sd_auth;
	unsigned int sd_id;
	struct esvp_sd_file_def *file;
	bool submit;

	enum esvp_document_type document_type;

	struct esvp_sd_def *next;
};

struct esvp_cc_def {
	struct acvp_buf data_hash;

	double min_h_in;
	unsigned int min_n_in;
	unsigned int nw;
	unsigned int n_out;
	double h_out;

	uint64_t cc_id;

	char *description;
	char *acvts_certificate;

	char *config_dir;

	struct esvp_cc_def *next;

	bool output_submitted;

	bool vetted;
	bool bijective;
};

struct esvp_es_def {
	//TODO due to es_auth, this structure cannot be constified any more
	// which implies that all operations must be single-threaded
	// fix: create some
	// struct esvp_es_def_instance {const struct esvp_es_def' struct acvp_auth_ctx *es_auth;}
	struct acvp_auth_ctx *es_auth;
	struct acvp_buf raw_noise_data_hash;
	struct acvp_buf raw_noise_restart_hash;

	double h_min_estimate;
	unsigned int bits_per_sample;
	unsigned int alphabet_size;
	unsigned int raw_noise_number_restarts;
	unsigned int raw_noise_samples_restart;

	uint64_t es_id;
	uint64_t raw_noise_id;
	uint64_t restart_id;

	char *primary_noise_source_desc;
	char *lab_test_id;

	char *esv_certificate;

	char *config_dir;

	const char *ear_file;
	const char *pud_file;

	bool raw_noise_submitted;
	bool restart_submitted;

	char *ea_runtime_results_status;
	char *ea_restart_results_status;

	bool iid;
	bool physical;
	bool additional_noise_sources;
	bool limit_es_vendor;

	struct esvp_cc_def *cc;
	struct esvp_sd_def *sd;
};

void esvp_def_sd_free(struct esvp_sd_def *sd);
void esvp_def_es_free(struct esvp_es_def *es);
int esvp_def_config(const char *directory, struct esvp_es_def **es);

#ifdef __cplusplus
}
#endif

#endif /* ESVP_DEFINITION_H */
