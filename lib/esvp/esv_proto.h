/*
 * Copyright (C) 2020 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESV_PROTO_H
#define ESV_PROTO_H

#include "esvp_internal.h"
#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

static const struct acvp_net_proto esv_proto_def = {
	.url_base = "esv/v1",
	.proto_version = "1.0",
	.proto_version_keyword = "esvVersion",
	.proto = esv_protocol,
	.proto_name = "ESVP",
	.basedir = ESVP_DS_DATADIR,
	.basedir_production = ESVP_DS_DATADIR_PRODUCTION,
	.secure_basedir = ESVP_DS_CREDENTIALDIR,
	.secure_basedir_production = ESVP_DS_CREDENTIALDIR_PRODUCTION,

	.session_url = NIST_VAL_OP_REG,
	.vector_url = NIST_VAL_OP_VECTORSET,
	.session_url_keyword = "url",
	.vector_url_keyword = "vectorSetUrls",

	.resultsfile = ACVP_DS_TESTRESPONSE,
	.resultsdir = NULL,

	.version_in_object = 0,
};

#ifdef __cplusplus
}
#endif

#endif /* ESV_PROTO_H */
