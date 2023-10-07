/*
 * Copyright (C) 2020 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef AMV_PROTO_H
#define AMV_PROTO_H

#include "amvp_internal.h"
#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

static const struct acvp_net_proto amv_proto_def = {
	.url_base = "amvp/v1",
	.proto_version = "1.0",
	.proto_version_keyword = "amvVersion",
	.proto = amv_protocol,
	.proto_name = "AMVP",
	.basedir = AMVP_DS_DATADIR,
	.basedir_production = AMVP_DS_DATADIR_PRODUCTION,
	.secure_basedir = AMVP_DS_CREDENTIALDIR,
	.secure_basedir_production = AMVP_DS_CREDENTIALDIR_PRODUCTION,

	.session_url = NIST_VAL_OP_CRSESSIONS,
	.vector_url = NIST_VAL_OP_EVIDENCESETS,
	.session_url_keyword = "url",
	.vector_url_keyword = "crUrls",
};

#ifdef __cplusplus
}
#endif

#endif /* AMV_PROTO_H */
