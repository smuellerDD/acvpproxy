/*
 * Copyright (C) 2020 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRAMS OR IMPLIED
 * WARRANTIAM, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIAM
 * OF MERCHANTABILITY AND FITNAMS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGAM (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICAM; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINAMS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef AMVPPROXY_H
#define AMVPPROXY_H

#include "acvpproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NIST_AMVP_DEFAULT_SERVER "amvts.nist.gov"
//#define NIST_AMVP_TEST_SERVER "demo.amvts.nist.gov"
#define NIST_AMVP_TEST_SERVER "10.252.9.45"
#define NIST_AMVP_DEFAULT_SERVER_PORT 443

/* Requests: HTTP GET */
#define NIST_AMVP_VAL_OP_REQUESTS "requests"
/* Test sessions: HTTP GET, POST, PUT, DELETE */
#define NIST_AMVP_VAL_OP_TESTSESSIONS "testSessions"
/* Test sessions results: HTTP GET */
#define NIST_AMVP_VAL_OP_RESULTS "results"

/**
 * @brief Perform network operation to register a new entropy source with
 *	  AMVP.
 *
 * @param [in] ctx ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int amvp_register(struct acvp_ctx *ctx);

/**
 * @brief Register a certificate request from a module request ID
 *
 * This operation is used after registering a module and the caller received
 * the module request ID. This ID can now be provided here to continue the
 * operation.
 *
 * @param [in] ctx ACVP Proxy library context
 * @param [in] module_request_id Module request ID
 * @return 0 on success, < 0 on error
 */
int amvp_certrequest_from_module_request_id(struct acvp_ctx *ctx,
					    uint64_t module_request_id);

/**
 * @brief Register a certificate request from a valid module ID
 *
 * Using the valid module ID, a certificate request is issued
 *
 * @param [in] ctx ACVP Proxy library context
 * @param [in] module_id Module ID
 * @return 0 on success, < 0 on error
 */
int amvp_certrequest_from_module_id(struct acvp_ctx *ctx, uint64_t module_id);

/**
 * @brief Perform network operation to submit AMVP results to CMVP and retrieve
 *	  the verdict from CMVP. The source of the test results is defined by
 *	  the datastore backend.
 *
 * NOTE: When the option of ctx.req_details.download_pending_vsid is set to
 * true, this function will not submit test results, but try to download
 * yet not downloaded test vectors! This allows the restart of a download if
 * the download somehow failed before.
 *
 * @param [in] ctx ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int amvp_continue(const struct acvp_ctx *ctx);

/**
 * @brief Load all module definition configurations from the default
 *	  configuration directory.
 *
  @param [in] config_basedir Root directory holding the configuration files.
 *			     The caller is allowed to provide a NULL string
 *			     where the ACVP proxy library uses the default
 *			     directory.
 *
 * @return 0 on success, < 0 on error
 */
int amvp_def_default_config(const char *config_basedir);

#ifdef __cplusplus
}
#endif

#endif /* AMVPPROXY_H */
