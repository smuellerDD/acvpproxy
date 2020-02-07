/*
 * Copyright (C) 2019 - 2020, Stephan Mueller <smueller@chronox.de>
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

#include "definition_internal.h"
#include "internal.h"

static int acvp_list_certificates_cb(const struct acvp_ctx *ctx,
				     const struct definition *def,
				     const uint32_t testid)
{
	const struct def_info *def_info;
	struct acvp_testid_ctx testid_ctx;
	struct acvp_auth_ctx *auth;
	int ret;

	def_info = def->info;

	memset(&testid_ctx, 0, sizeof(testid_ctx));
	testid_ctx.def = def;
	testid_ctx.ctx = ctx;
	testid_ctx.testid = testid;
	CKINT(acvp_init_auth(&testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(&testid_ctx));

	/* Get testsession ID */
	auth = testid_ctx.server_auth;

	if (!auth->testsession_certificate_number)
		goto out;

	fprintf(stdout, "%-50s | %-8u | %-10s\n",
		def_info->module_name, testid,
		auth->testsession_certificate_number);

out:
	acvp_release_auth(&testid_ctx);
	return ret;
}

DSO_PUBLIC
int acvp_list_certificates(const struct acvp_ctx *ctx)
{
	fprintf(stdout, "%-50s | %-8s | %-10s\n",
		"Module Name", "Test ID", "Certificate No");
	return acvp_process_testids(ctx, &acvp_list_certificates_cb);
}
