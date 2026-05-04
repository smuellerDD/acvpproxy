/* Loading of the RBG dependency configurations
 *
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "internal.h"
#include "logger.h"
#include "rbg_definition.h"
#include "rbg_internal.h"
#include "ret_checkers.h"

#include <json-c/json.h>

/*************************************************************************/

void rbg_def_free(struct rbg_def *rbg)
{
	struct acvp_auth_ctx *auth;
	unsigned int i;

	if (!rbg)
		return;

	auth = rbg->rbg_auth;
	acvp_release_acvp_auth_ctx(auth);
	ACVP_PTR_FREE_NULL(rbg->rbg_auth);

	for (i = 0; i < rbg->num_rbg_definitions; i++) {
		ACVP_JSON_PUT_NULL(rbg->rbg_definitions[i]);
	}

	free(rbg);
}

static int rbg_read_def_one(const char *directory, struct rbg_def *rbg)
{
	struct json_object *rbg_conf = NULL;
	struct stat statbuf;
	char pathname[FILENAME_MAX];
	int ret = 0;

	CKNULL(rbg, -EINVAL);
	CKNULL(directory, -EINVAL);

	snprintf(pathname, sizeof(pathname), "%s/%s%u/%s%s", directory,
		 RBG_ES_DIR_RBG, rbg->num_rbg_definitions, RBG_ES_FILE_DEF,
		 RBG_CONFIG_FILE_EXTENSION);

	if (stat(pathname, &statbuf)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Noise source definition not found at %s - skipping entropy source definitions\n",
		       pathname);
		return 1;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Reading configuration file %s\n",
	       pathname);

	rbg_conf = json_object_from_file(pathname);
	CKNULL(rbg_conf, -EFAULT);

	rbg->rbg_definitions[rbg->num_rbg_definitions] = rbg_conf;
	rbg->num_rbg_definitions++;

out:
	return ret;
}

static int rbg_read_def(const char *directory, struct rbg_def **rbg_out)
{
	struct rbg_def *rbg;
	unsigned int ctr;
	int ret = 0;
	bool found = false;

	rbg = calloc(1, sizeof(struct rbg_def));
	CKNULL(rbg, -ENOMEM);

	for (ctr = 0; ctr < RBG_MAX_DEFINITIONS; ctr++) {
		ret = rbg_read_def_one(directory, rbg);

		if (ret)
			break;
		found = 1;
	}

	if (ret == 1)
		ret = 0;
	CKINT(ret);

	if (!found) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Reading of RBG definition failed to find at least one definition\n");
		goto out;
	}

	*rbg_out = rbg;
	rbg = NULL;

out:
	rbg_def_free(rbg);
	return ret;
}

int rbg_def_config(const char *directory, struct rbg_def **rbg)
{
	int ret = 0;

	CKNULL_LOG(directory, -EINVAL, "Configuration directory missing\n");

	/* Read entropy source definitions */
	CKINT(rbg_read_def(directory, rbg));

	return 0;

out:
	return ret;
}
