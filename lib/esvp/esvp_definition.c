/* Loading of the ESVP dependency configurations
 *
 * Copyright (C) 2021, Stephan Mueller <smueller@chronox.de>
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

#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esvpproxy.h"
#include "binhexbin.h"
#include "definition_internal.h"
#include "esvp_definition.h"
#include "esvp_internal.h"
#include "hash/sha256.h"
#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"
#include "threading_support.h"

#include <json-c/json.h>

/*************************************************************************/

static void esvp_def_cc_free_one(struct esvp_cc_def *cc)
{
	if (!cc)
		return;

	acvp_free_buf(&cc->data_hash);
	ACVP_PTR_FREE_NULL(cc->description);
	ACVP_PTR_FREE_NULL(cc->acvts_certificate);
	ACVP_PTR_FREE_NULL(cc->config_dir);
	free(cc);
}

static void esvp_def_cc_free(struct esvp_cc_def *cc)
{
	if (!cc)
		return;

	while (cc) {
		struct esvp_cc_def *tmp = cc->next;

		esvp_def_cc_free_one(cc);

		cc = tmp;
	}
}

void acvp_release_auth_sd(struct esvp_sd_def *sd)
{
	struct acvp_auth_ctx *auth;

	if (!sd)
		return;

	auth = sd->sd_auth;
	acvp_release_acvp_auth_ctx(auth);
	ACVP_PTR_FREE_NULL(sd->sd_auth);

	ACVP_PTR_FREE_NULL(sd->filename);
}

static void esvp_def_sd_free_one(struct esvp_sd_def *sd)
{
	if (!sd)
		return;

	acvp_release_auth_sd(sd);
	free(sd);
}

void esvp_def_sd_free(struct esvp_sd_def *sd)
{
	if (!sd)
		return;

	while (sd) {
		struct esvp_sd_def *tmp = sd->next;

		esvp_def_sd_free_one(sd);

		sd = tmp;
	}
}

void esvp_def_es_free(struct esvp_es_def *es)
{
	struct acvp_auth_ctx *auth;

	if (!es)
		return;

	auth = es->es_auth;
	acvp_release_acvp_auth_ctx(auth);
	ACVP_PTR_FREE_NULL(es->es_auth);

	acvp_free_buf(&es->raw_noise_data_hash);
	acvp_free_buf(&es->raw_noise_restart_hash);

	ACVP_PTR_FREE_NULL(es->primary_noise_source_desc);
	ACVP_PTR_FREE_NULL(es->config_dir);

	esvp_def_cc_free(es->cc);
	esvp_def_sd_free(es->sd);
	free(es);
}

static int esvp_read_cc_def_one(const char *cc_dir_name, struct esvp_es_def *es)
{
	struct json_object *cc_conf = NULL;
	struct stat statbuf;
	struct esvp_cc_def *cc = NULL;
	char cc_file_name[FILENAME_MAX], cc_data_name[FILENAME_MAX];
	const char *str;
	int ret;

	/* Entry not found */
	if (stat(cc_dir_name, &statbuf))
		return 1;

	/* We only use a directory */
	if (!S_ISDIR(statbuf.st_mode)) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "File system object %s is not the expected directory!\n",
		       cc_dir_name);
		return 1;
	}

	snprintf(cc_file_name, sizeof(cc_file_name), "%s/%s%s", cc_dir_name,
		 ESVP_ES_FILE_DEF, ESVP_ES_CONFIG_FILE_EXTENSION);
	cc_conf = json_object_from_file(cc_file_name);
	CKNULL(cc_conf, -EFAULT);

	cc = calloc(1, sizeof(struct esvp_cc_def));
	CKNULL(cc, -ENOMEM);

	CKINT(acvp_duplicate(&cc->config_dir, cc_dir_name));

	CKINT(json_get_string(cc_conf, "description", &str));
	CKINT(acvp_duplicate(&cc->description, str));

	CKINT(json_get_double(cc_conf, "minHin", &cc->min_h_in));
	CKINT(json_get_uint(cc_conf, "minNin", &cc->min_n_in));
	CKINT(json_get_uint(cc_conf, "nw", &cc->nw));
	CKINT(json_get_uint(cc_conf, "nOut", &cc->n_out));

	CKINT(json_get_bool(cc_conf, "vetted", &cc->vetted));

	/*
	 * According to the spec, the bijective claim and the required to
	 * provide a conditioning output is only applicable if we have a
	 * non-vetted component.
	 */
	if (!cc->vetted) {
		CKINT(json_get_bool(cc_conf, "bijective", &cc->bijective));

		snprintf(cc_data_name, sizeof(cc_data_name), "%s/%s%s",
			 cc->config_dir, ESVP_ES_FILE_CC_DATA,
			 ESVP_ES_BINARY_FILE_EXTENSION);
		CKINT(acvp_hash_file(cc_data_name, sha256, &cc->data_hash));
	}

	/*
	 * If we have a vetted component, we require the certificate ID
	 */
	if (cc->vetted) {
		CKINT_LOG(
			json_get_string(cc_conf, "acvtsCertificate", &str),
			"If  a vetted conditioning component is specified, an ACVTS certificate must be referencced\n");
		CKINT(acvp_duplicate(&cc->acvts_certificate, str));

		/*
		 * The check if the given algo name is a correct one is
		 * performed when building the request to be sent to the ESVP
		 * server.
		 */
	}

	/*
	 * Append the new conditioning component entry at the end of the list
	 * because the order matters.
	 */
	if (es->cc) {
		struct esvp_cc_def *iter_cc = es->cc;

		while (iter_cc) {
			if (!iter_cc->next) {
				iter_cc->next = cc;
				break;
			}
			iter_cc = iter_cc->next;
		}
	} else {
		es->cc = cc;
	}

out:
	ACVP_JSON_PUT_NULL(cc_conf);
	if (ret)
		esvp_def_cc_free(cc);
	return ret;
}

static int esvp_read_cc_def(const char *directory, struct esvp_es_def *es)
{
	char cc_dir_name[FILENAME_MAX - 256];
	unsigned int i = 1;
	int ret;

	CKNULL(es, -EINVAL);
	CKNULL(directory, -EINVAL);

	while (1) {
		snprintf(cc_dir_name, sizeof(cc_dir_name), "%s/%s%u", directory,
			 ESVP_ES_DIR_CONDCOMP, i);
		i++;

		ret = esvp_read_cc_def_one(cc_dir_name, es);
		if (ret) {
			if (ret == 1)
				ret = 0;
			break;
		}
	}

out:
	return ret;
}

static int esvp_read_es_def(const char *directory, struct esvp_es_def **es_out)
{
	struct json_object *es_conf = NULL;
	struct esvp_es_def *es = NULL;
	struct stat statbuf;
	const char *str;
	char pathname[FILENAME_MAX], es_data_file[FILENAME_MAX];
	int ret = 0;

	CKNULL(es_out, -EINVAL);
	CKNULL(directory, -EINVAL);

	snprintf(pathname, sizeof(pathname), "%s/%s/%s%s", directory,
		 ESVP_ES_DIR_ENTROPY_SOURCE, ESVP_ES_FILE_DEF,
		 ESVP_ES_CONFIG_FILE_EXTENSION);

	if (stat(pathname, &statbuf)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Noise source definition not found at %s - skipping entropy source definitions\n",
		       pathname);
		goto out;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Reading configuration file %s\n",
	       pathname);

	es_conf = json_object_from_file(pathname);
	CKNULL(es_conf, -EFAULT);

	es = calloc(1, sizeof(struct esvp_es_def));
	CKNULL(es, -ENOMEM);

	/*
	 * Entropy Source ID is set by us, may not exist before -
	 * we do not check return code.
	 */
	json_get_uint(es_conf, ACVP_DEF_PRODUCTION_ID("esId"), &es->es_id);

	CKINT(acvp_duplicate(&es->config_dir, directory));

	CKINT(json_get_string(es_conf, "primaryNoiseSource", &str));
	CKINT(acvp_duplicate(&es->primary_noise_source_desc, str));

	snprintf(es_data_file, sizeof(es_data_file), "%s/%s/%s%s",
		 es->config_dir, ESVP_ES_DIR_ENTROPY_SOURCE,
		 ESVP_ES_FILE_RAW_NOISE, ESVP_ES_BINARY_FILE_EXTENSION);
	CKINT(acvp_hash_file(es_data_file, sha256, &es->raw_noise_data_hash));

	snprintf(es_data_file, sizeof(es_data_file), "%s/%s/%s%s",
		 es->config_dir, ESVP_ES_DIR_ENTROPY_SOURCE,
		 ESVP_ES_FILE_RESTART_DATA, ESVP_ES_BINARY_FILE_EXTENSION);
	CKINT(acvp_hash_file(es_data_file, sha256,
			     &es->raw_noise_restart_hash));

	CKINT(json_get_uint(es_conf, "bitsPerSample", &es->bits_per_sample));
	CKINT(json_get_uint(es_conf, "alphabetSize", &es->alphabet_size));
	CKINT(json_get_uint(es_conf, "numberOfRestarts",
			    &es->raw_noise_number_restarts));
	CKINT(json_get_uint(es_conf, "samplesPerRestart",
			    &es->raw_noise_samples_restart));
	CKINT(json_get_double(es_conf, "hminEstimate", &es->h_min_estimate));

	CKINT(json_get_bool(es_conf, "iid", &es->iid));
	CKINT(json_get_bool(es_conf, "physical", &es->physical));
	CKINT(json_get_bool(es_conf, "itar", &es->itar));
	CKINT(json_get_bool(es_conf, "additionalNoiseSources",
			    &es->additional_noise_sources));

	CKINT(esvp_read_cc_def(directory, es));

	*es_out = es;

out:
	ACVP_JSON_PUT_NULL(es_conf);
	if (ret) {
		*es_out = NULL;
		esvp_def_es_free(es);
	}
	return ret;
}

int esvp_def_config(const char *directory, struct esvp_es_def **es)
{
	int ret = 0;

	CKNULL_LOG(directory, -EINVAL, "Configuration directory missing\n");

	/* Read entropy source definitions */
	CKINT(esvp_read_es_def(directory, es));

	return 0;

out:
	return ret;
}
