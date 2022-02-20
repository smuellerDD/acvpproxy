/* ACVP meta data main entrance code
 *
 * Copyright (C) 2020 - 2022, Stephan Mueller <smueller@chronox.de>
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

#include "acvp_meta_internal.h"
#include "internal.h"

int acvp_handle_open_requests(const struct acvp_testid_ctx *testid_ctx)
{
	int ret;

	CKINT(acvp_vendor_handle_open_requests(testid_ctx));
	CKINT(acvp_person_handle_open_requests(testid_ctx));
	CKINT(acvp_oe_handle_open_requests(testid_ctx));
	CKINT(acvp_module_handle_open_requests(testid_ctx));
out:
	return ret;
}

int acvp_sync_metadata(const struct acvp_testid_ctx *testid_ctx)
{
	int ret = 0, ret2;

	/*
	 * The following error checking shall allow invocation of all
	 * functions with a potential register operation even if the previous
	 * register operation returned -EAGAIN (i.e. a register was performed).
	 * Any other error will cause termination immediately.
	 *
	 * I.e. we allow all potential register operation to proceed. The final
	 * publish operation, however, is only performed if no prior register
	 * operations happened (i.e. if no -EAGAIN was returned beforehand).
	 */

	/* Verify / register the vendor information */
	ret2 = acvp_vendor_handle(testid_ctx);
	if (ret2 < 0) {
		ret = ret2;
		if (ret != -EAGAIN)
			goto out;
	}

	/* Verify / register the person / contact information */
	if (!ret) {
		ret2 = acvp_person_handle(testid_ctx);
		if (ret2 < 0) {
			ret = ret2;
			if (ret != -EAGAIN)
				goto out;
		}
	}

	/* Verify / register the operational environment information */
	ret2 = acvp_oe_handle(testid_ctx);
	if (ret2 < 0) {
		ret = ret2;
		if (ret != -EAGAIN)
			goto out;
	}

	/*
	 * We stop processing here if there was an error, including when there
	 * is a request ID present.
	 */
	if (ret)
		goto out;

	/* Verify / register the operational environment information */
	CKINT(acvp_module_handle(testid_ctx));

out:
	return ret;
}
