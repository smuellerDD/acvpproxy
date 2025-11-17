/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include <string.h>

#include "acvpproxy.h"
#include "amvpproxy.h"
#include "amvp_internal.h"
#include "aux_helper.h"
#include "internal.h"
#include "json_wrapper.h"
#include "request_helper.h"
#include "sleep.h"
#include "threading_support.h"

/******************************************************************************
 * Module handling
 ******************************************************************************/

/*
 * Process response from the module_register_op
 */
int amvp_module_process_req(struct acvp_testid_ctx *module_ctx,
			    const struct acvp_buf *response)
{
	uint64_t module_id;
	int ret;

	/* Analyze the result from the POST */
	ret = acvp_meta_register_get_id(response, &module_id);
	if (ret == -EAGAIN)
		ret = 0;
	if (ret)
		goto out;

	//TODO: why do we need to do this?
	//https://github.com/usnistgov/AMVP/issues/399
	module_id = acvp_id(module_id);
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Obtained module ID %"PRIu64"\n",
	       module_id);

	/* The received module ID is stored for the session */
	module_ctx->testid = module_id;

	logger_status(LOGGER_C_ANY, "Module registered with ID %"PRIu64"\n",
		      module_id);

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(module_ctx, AMVP_DS_MODULEIDMETA,
					      true, response));

out:
	return ret;
}
