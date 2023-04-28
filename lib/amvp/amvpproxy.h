/*
 * Copyright (C) 2020 - 2023, Stephan Mueller <smueller@chronox.de>
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
#define NIST_AMVP_TEST_SERVER "demo.amvts.nist.gov"
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
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int amvp_register(const struct acvp_ctx *ctx);

/**
 * @brief Continue operation on entropy source
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int amvp_continue(const struct acvp_ctx *ctx);

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
int amvp_def_default_config(const char *config_basedir);

#ifdef __cplusplus
}
#endif

#endif /* AMVPPROXY_H */
