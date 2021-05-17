/*
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESVP_INTERNAL_H
#define ESVP_INTERNAL_H

#include "acvpproxy.h"
#include "bool.h"
#include "buffer.h"
#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Status handing: write the status file
 */
int esvp_write_status(const struct acvp_testid_ctx *testid_ctx);

/**
 * Status handing: read the status file
 */
int esvp_read_status(const struct acvp_testid_ctx *testid_ctx,
		     struct json_object *status);

/**
 * Support to create the supporting document array
 */
int esvp_build_sd(const struct acvp_testid_ctx *testid_ctx,
		  struct json_object *data, bool write_extended);

/**
 * Start certification operation
 */
int esvp_certify(struct acvp_testid_ctx *testid_ctx);

/* File holding the general entropy source information */
#define ESVP_ES_FILE_DEF "definition"

/* Directory holding the raw noise data */
#define ESVP_ES_DIR_ENTROPY_SOURCE "entropy_source"
/* File with the raw noise data */
#define ESVP_ES_FILE_RAW_NOISE "raw_noise_bits"
/* File with the restart data */
#define ESVP_ES_FILE_RESTART_DATA "restart_bits"
/* File with the conditioning data */
#define ESVP_ES_FILE_CC_DATA "conditioned_bits"

/* Directory containing one sub-directory per conditioning component */
#define ESVP_ES_DIR_CONDCOMP "conditioning_component"

/* Directory holding documentation */
#define ESVP_ES_DIR_DOCUMENTATION "documentation"

#define ESVP_ES_CONFIG_FILE_EXTENSION ".json"
#define ESVP_ES_BINARY_FILE_EXTENSION ".bin"

/* File holding the metadata about the test session provided by ESVP server */
#define ESVP_DS_TESTIDMETA "esvid_metadata.json"

/* Data store directory for sensitive data including debug logs */
#define ESVP_DS_CREDENTIALDIR "esvp-secure-datastore"
#define ESVP_DS_CREDENTIALDIR_PRODUCTION "esvp-secure-datastore-production"
/* Data store directory for testvectors and other regular data */
#define ESVP_DS_DATADIR "esvp-testvectors"
#define ESVP_DS_DATADIR_PRODUCTION "esvp-testvectors-production"


#ifdef __cplusplus
}
#endif

#endif /* ESVP_INTERNAL_H */
