/*
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
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
 * DAMAGE.int acvp_list_unregistered_definitions(void)
 */

#ifndef ACVPPROXY_H
#define ACVPPROXY_H

#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include "bool.h"
#include "config.h"
#include "mutex.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define ACVP_VERSION			"0.5"

/* acvp_protocol.txt: section 5.1 */
#define NIST_DEFAULT_SERVER		"acvts.nist.gov"
#define NIST_TEST_SERVER		"demo.acvts.nist.gov"
#define NIST_DEFAULT_SERVER_PORT	443
#define NIST_VAL_CTX			"acvp/acvp/v1"

/* acvp_protocol.txt: section 5.2 */
#define NIST_VAL_OP_LOGIN		"login"
#define NIST_VAL_OP_REG			"testSessions"
#define NIST_VAL_OP_VECTORSET		"vectorSets"
#define NIST_VAL_OP_RESULTS		"results"
#define NIST_VAL_OP_EXPECTED_RESULTS	"expected"
#define NIST_VAL_OP_VENDOR		"vendors"
#define NIST_VAL_OP_OE			"oes"
#define NIST_VAL_OP_MODULE		"modules"
#define NIST_VAL_OP_DEPENDENCY		"dependencies"
#define NIST_VAL_OP_ALGORITHMS		"algorithms"

/* acvp_protocol.txt: section 11.1 */
#define ACVP_JWT_TOKEN_MAX      	1024
/* lifetime of token in seconds - we subtract some grace time */
#define ACVP_JWT_TOKEN_LIFETIME		(1800 - 300)

struct acvp_auth_ctx {
	char *jwt_token;	/* JWT token provided by server */
	size_t jwt_token_len;
	time_t jwt_token_generated; /* generation time in seconds since Epoch */
	/*
	 * As auth ctx is shared between multiple vsIds belonging to one testId,
	 * we must lock if we want to change it.
	 */
	mutex_t mutex;
};

struct acvp_net_ctx {
	char *server_name;
	unsigned int server_port;
#define ACVP_NET_URL_MAXLEN		1024
	char *certs_ca_file;	/* CA certificates used to verify peer */
	char certs_ca_file_type[4]; /* File type of CA certificate */
	char *certs_clnt_file;	/* Client cert for TLS client auth */
	char certs_clnt_file_type[4]; /* File type of certificate */
	char *certs_clnt_key_file; /* Client key for TLS client auth */
	char certs_clnt_key_file_type[4]; /* File type of certificate */
	char *certs_clnt_passcode; /* Passcode */
};

struct acvp_modinfo_ctx {
	char *specificver;
	char *specificver_filesafe;
};

/**
 * @brief Search parameters that can be set by the caller. If an entry is NULL
 *	  it is not used as a search criteria.
 * @param modulename Module name as reported by the list operation
 * @param moduleversion Version string as reported by the list operation
 * @param vendorname Vendor name as reported by the list operation
 * @param execenv Execution environment as reported by the list operation
 * @param processor Processor name as reported by the list operation
 * @param fuzzy_name_search Use the given search strings in a fuzzy search
 *			    (i.e. use strstr to search the name and not
 *			     strncmp)
 *
 * @param submit_vsids Array of vsIds to be processed (if empty, all vsIDs are
 *		       in scope).
 * @param nr_submit_vsids Number of vsIDs that are to be searched.
 * @param submit_testids Array of testIds to be processed (if empty, all
 *			 testIDs are in scope).
 * @param nr_submit_testids Number of testIDs that are to be searched.
 */
struct acvp_search_ctx {
	char *modulename;
	char *moduleversion;
	char *vendorname;
	char *execenv;
	char *processor;
	bool fuzzy_name_search;

	unsigned int submit_vsid[MAX_SUBMIT_ID];
	unsigned int nr_submit_vsid;
	unsigned int submit_testid[MAX_SUBMIT_ID];
	unsigned int nr_submit_testid;
};

/*
 * Data required for the datastore
 */
struct acvp_datastore_ctx {
	struct acvp_search_ctx search;
	char *basedir;
	char *secure_basedir;
	char *vectorfile;
	char *resultsfile;
	char *jwttokenfile;
	char *verdictfile;
	char *processedfile;
	char *srcserver;
	char *expectedfile;
};

struct acvp_req_ctx {
	/*
	 * certificateRequest - If an algorithm certificate is not desired
	 * for this registration populate the field "certificateRequest" with
	 * "no", otherwise "yes".
	 */
	bool certificateRequest;

	/*
	 * debugRequest - If this vector session is for the purposes of
	 * testing the client or DUT prior to a certificate request and
	 * desires the answers to the vectors as well, indicate with "yes",
	 * otherwise omit the keyword or indicate with "no"
	 */
	bool debugRequest;

	/*
	 * production - If this is a production environment indicate so with
	 * "yes", otherwise omit this keyword or indicate with "no".  A
	 * production environment may not be able to support intermediate
	 * value tests and therefore those tests will be excluded.
	 */
	bool production;

	/*
	 * encryptAtRest - The client may request the server to encrypt all
	 * data at rest by registering "encryptAtRest" with "yes".  Omitting
	 * the "encryptAtRest" field or registering with "no" will indicate
	 * to the server that no encryption is require for the data at rest.
	 */
	bool encryptAtRest;

	/*
	 * Dump register request instead of sending it to server.
	 */
	bool dump_register;

	/*
	 * Request a test sample with expected results instead of the real
	 * test vectors.
	 */
	bool request_sample;

	/*
	 * Force a refresh of the authentication token.
	 */
	bool auth_token_force_refresh;

	/*
	 * Request the download of vsIDs whose download failed before.
	 */
	bool download_pending_vsid;
};

struct acvp_opts_ctx {
	/*
	 * Resubmit an already submitted vsID result.
	 */
	bool resubmit_result;

	/*
	 * If the vendor definition is not found on the ACVP server, register
	 * the vendor as new.
	 */
	bool register_new_vendor;

	/*
	 * If the operational environment definition is not found on the
	 * ACVP server, register the OE as new.
	 */
	bool register_new_oe;

	/*
	 * If the module definition is not found on the
	 * ACVP server, register the module as new.
	 */
	bool register_new_module;
};

struct acvp_ctx {
	struct acvp_modinfo_ctx modinfo;
	struct acvp_req_ctx req_details;
	struct acvp_datastore_ctx datastore;
	struct acvp_opts_ctx options;
};

/**
 * @brief Initialize ACVP Proxy library
 *
 * It is permissible to call this function multiple times even while other
 * API calls are either in progress or have been completed to update the
 * TOTP seed.
 *
 * @param seed [in] TOTP seed
 * @param seed_len [in] TOTP seed buffer length
 * @param last_gen [in] Time stamp when TOTP value was generated last time. It
 *			is permissible to set it to 0 in case TOTP was never
 *			used or caller does not know.
 * @param last_gen_cb [in] Callback to be invoked when a TOTP value is generated
 *			   to allow a framework to store the current time
 *			   for potential later initialization. This function
 *			   may be NULL if no callback is requested.
 *
 * @return 0 on success, < 0 on error
 */
int acvp_init(const uint8_t *seed, uint32_t seed_len, time_t last_gen,
	      void (*last_gen_cb)(time_t now));

/**
 * @brief Release ACVP Proxy library
 *
 * All global resources released and freed.
 */
void acvp_release(void);

/**
 * @brief Initialize ACVP context data structure.
 *
 * @param ctx [out] Pointer to retrieve allocated ACVP Proxy library context
 * @param datastore_basedir [in] Root directory holding the datastore for the
 *				 test vectors, test responses, and verdicts.
 *				 The caller is allowed to provide a NULL string
 *				 where the ACVP proxy library uses the default
 *				 directory.
 * @param secure_basedir [in] Root directory holding the datastore with
 *			      sensitive parameters, such as the JWT auth token.
 * 			      The caller is allowed to provide a NULL string
 *			      where the ACVP proxy library uses the default
 *			      directory.
 *
 * @return 0 on success, < 0 on error
 */
int acvp_ctx_init(struct acvp_ctx **ctx, const char *datastore_basedir,
		  const char *secure_basedir);

/**
 * @brief Release ACVP Proxy context data structure
 *
 * All resources associated with the context are released and freed.
 *
 * @param ctx [in] ACVP Proxy library context
 */
void acvp_ctx_release(struct acvp_ctx *ctx);

/**
 * @brief Set networking information to reach CAVP server
 *
 * @param server_name [in] CAVP server name
 * @param port [in] CAVP server port
 * @param ca [in] CA file to support server authentication. If NULL, server
 *	     certificate is not validated.
 * @param client_cert [in] TLS client cert used for client authentication
 * @param client_key [in] TLS client key applicable to the client certificate.
 *			  This value may be NULL (e.g. when a P12 certificate
 *			  is used which contains the private key).
 * @param passcode [in] Passcode applicable to the private key (may be NULL
 *			if no passcode is required).
 *
 * @return 0 on success, < 0 on error
 */
int acvp_set_net(const char *server_name, unsigned int port, const char *ca,
		 const char *client_cert, const char *client_key,
		 const char *passcode);

/**
 * @brief Define the module specification for which test vectors are to be
 *	  obtained or for which test results are to be submitted. The search
 *	  criteria allows narrowing the search base for IUT definitions known
 *	  to the library. The less search parameters are specified, the broader
 *	  is the search scope. If no search parameter is given (or this API
 *	  call) is not invoked), all IUT definitions are in scope and are
 *	  processed.
 *
 * @param ctx [in] ACVP Proxy library context
 * @param caller_search [in] Set the search criteria to find the cipher
 *			    implementation definition.
 * @param specific_ver [in] Provide a version number that shall be registered
 *		      with CAVP instead of @param moduleversion.
 * @return 0 on success, < 0 on error
 */
int acvp_set_module(struct acvp_ctx *ctx,
			const struct acvp_search_ctx *caller_search,
			const char *specific_ver);

/**
 * @brief Mark a CAVP register request as a production CAVS test /
 *	 official CAVS test
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_req_production(struct acvp_ctx *ctx);

/**
 * @brief Perform network operation to register a new test with CAVP and
 *	  retrieve the test vectors. The test vectors are stored as defined by
 *	  the datastore backend.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_register(const struct acvp_ctx *ctx);

/**
 * @brief Perform network operation to submit test results to CAVP and retrieve
 *	  the verdict from CAVP. The source of the test results is defined by
 *	  the datastore backend.
 *
 * Note: When the option of ctx.req_details.download_pending_vsid is set to
 * true, this function will not submit test results, but try to download
 * yet not downloaded test vectors! This allows the restart of a download if
 * the download somehow failed before.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_respond(const struct acvp_ctx *ctx);

/**
 * @brief Before this call, all test vector communication with the ACVP is
 *	  kept private, i.e. it will not be published. With the invocation of
 *	  this call, the test results for the test IDs in question are
 *	  announced to the ACVP server to be published.
 *
 * 	  The publication operation also involves the specification of the
 *	  auxiliary information like vendor information, module definition,
 *	  operational environment information.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_publish(const struct acvp_ctx *ctx);

/**
 * @brief Refresh JWT authentication token for all already obtained test vectors
 *	 limited by the search criteria.
 *
 * @param ctx [in] ACVP Proxy library context
 * @param submit_vsid [in] vsID to be refreshed or UINT_MAX to refresh all test
 *			  vectors.
 * @return 0 on success, < 0 on error
 */
int acvp_refresh_authtoken(struct acvp_ctx *ctx, unsigned int submit_vsid);

/**
 * @brief Return version string of the ACVP Proxy library
 *
 * @param buf [in/out] Caller allocated buffer that will be filled with the
 * 	     version information
 * @param buflen [in] Size of the buffer
 * @return 0 on success, < 0 on error
 */
int acvp_versionstring(char *buf, size_t buflen);

/**
 * @brief Dump all registered module definitions to STDERR
 *
 * @param search Search parameters that can be set by the caller. If an entry is
 *		 NULL it is not used as a search criteria.
 *
 * @return 0 on success, < 0 on error
 */
int acvp_list_registered_definitions(const struct acvp_search_ctx *search);

/**
 * @brief List all unregistered cipher definitions with their references to
 *	  STDERR.
 *
 * @return 0 on success, < 0 on error
 */
int acvp_list_unregistered_definitions(void);

/**
 * @brief Load definition configuration files which imply that the associated
 *	  cipher definitions are registered and usable from this point on.
 *
 * @param directory points to the directory name that contains the module
 *		    definition. The directory must have the subdirectories of
 *		    "vendor", "oe", and "module_info" which in turn hold one
 *		    or more definition files. All permutations of definition
 *		    files are applied.
 *
 * @return 0 on success, < 0 on error
 */
int acvp_def_config(const char *directory);

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
int acvp_def_default_config(const char *config_basedir);

/**
 * @brief Set the options for the given context.
 *
 * @param ctx [in] ACVP Proxy library context
 * @param options [in] Options to be set for the ACVP Proxy context
 *
 * @return 0 on success, < 0 on error
 */
int acvp_set_options(struct acvp_ctx *ctx, const struct acvp_opts_ctx *options);

/**
 * @brief List all testIDs where the download of vectors failed
 *
 * A download may fail due to networking issues or other problems. Using the
 * listed testIDs again, the user can retry downloading these testIDs using
 * an appropriate search operation.
 *
 * Note, it is even possible to register the request and terminate the network
 * connection to come back at a later point in time. I.e. the ACVP server's
 * retry information can be disregarded.
 *
 * One function invocation returns one testid for a given index pointer. The
 * caller shall invoke this function repeatedly starting with @param idx_ptr
 * containing a zero. Every subsequent invocation shall use the @param idx_ptr
 * value that was returned from the previous round. If the return code -ENOENT
 * is returned, the caller shall stop the iteration. Every recorded testid
 * is returned with @param testid.
 *
 * @param idx_ptr [in/out] Index pointer to obtain the testID
 * @param testid [out] TestID at the given index pointer
 *
 * @return 0 on success, -ENOENT identifies that there is no testid for given
 *	   @param idx_ptr, < 0 on other error
 */
int acvp_list_failed_testid(int *idx_ptr, uint32_t *testid);

/**
 * @brief List all vsIDs with a verdict provided in @param passed
 *
 * During the download of the vsIDs, the verdict returned from the ACVP server
 * is processed and the global verdict for the vsID is obtained. The failing
 * and passing verdicts are maintained separately.
 *
 * With the function, the caller can obtain all vsIDs with failing or passing
 * verdicts. Naturally, the data is only present after a
 *
 * @param idx_ptr [in/out] Index pointer to obtain the testID
 * @param testid [out] TestID at the given index pointer
 * @param passed [in] Boolean whether to look for passing verdicts (true) or
 *		      failing verdicts (false).
 *
 * @return 0 on success, -ENOENT identifies that there is no testid for given
 *	   @param idx_ptr, < 0 on other error
 */
int acvp_list_verdict_vsid(int *idx_ptr, uint32_t *vsid, bool passed);

/**
 * Retrieve all details about cipher definitions from the ACVP server and dump
 * it.
 *
 * @param ctx [in] ACVP Proxy library context
 * @param ciphername [in] Cipher name to search for - if NULL, the list of
 *			  ciphers is provided
 * @param pathname [in] File to write the cipher definitions to
 *
 * @return 0 on success, < 0 on error
 */
int acvp_cipher_get(const struct acvp_ctx *ctx, const char *ciphername,
		    const char *pathname);

#ifdef __cplusplus
}
#endif

#endif /* ACVPPROXY_H */
