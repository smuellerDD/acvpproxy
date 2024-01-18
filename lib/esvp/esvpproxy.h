/*
 * Copyright (C) 2020 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESVPPROXY_H
#define ESVPPROXY_H

#include "acvpproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NIST_ESVP_DEFAULT_SERVER "esvts.nist.gov"
#define NIST_ESVP_TEST_SERVER "demo.esvts.nist.gov"
#define NIST_ESVP_DEFAULT_SERVER_PORT 7443

#define NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT "entropyAssessments"
#define NIST_ESVP_VAL_OP_DATAFILE "dataFiles"
#define NIST_ESVP_VAL_OP_SUPPDOC "supportingDocumentation"
#define NIST_ESVP_VAL_OP_CERTIFY "certify"

/**
 * @brief Perform network operation to register a new entropy source with
 *	  ESVP.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int esvp_register(const struct acvp_ctx *ctx);

/**
 * @brief Continue operation on entropy source
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int esvp_continue(const struct acvp_ctx *ctx);

/**
 * @brief Load all module definition configurations from the default
 *	  configuration directory.
 *
  @param config_basedir [in] Root directory holding the configuration files.
 *			     The caller is allowed to provide a NULL string
 *			     where the ACVP proxy library uses the default
 *			     directory.
 *
 * @return 0 on success, < 0 on error
 */
int esvp_def_default_config(const char *config_basedir);

#ifdef __cplusplus
}
#endif

#endif /* ESVPPROXY_H */
