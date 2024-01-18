/*
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef ACVPPROXY_H
#define ACVPPROXY_H

#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include "bool.h"
#include "config.h"
#include "mutex.h"

#ifdef __cplusplus
extern "C" {
#endif

/* acvp_protocol.txt: section 5.1 */
#define NIST_DEFAULT_SERVER "acvts.nist.gov"
#define NIST_TEST_SERVER "demo.acvts.nist.gov"
#define NIST_DEFAULT_SERVER_PORT 443

/* acvp_protocol.txt: section 5.2 / 04-amvprotocol.adoc */
#define NIST_VAL_OP_LOGIN "login"
#define NIST_VAL_OP_LOGIN_REFRESH "login/refresh"
#define NIST_VAL_OP_REG "testSessions"
#define NIST_VAL_OP_VECTORSET "vectorSets"
#define NIST_VAL_OP_RESULTS "results"
#define NIST_VAL_OP_EXPECTED_RESULTS "expected"
#define NIST_VAL_OP_VENDOR "vendors"
#define NIST_VAL_OP_ADDRESSES "addresses"
#define NIST_VAL_OP_PERSONS "persons"
#define NIST_VAL_OP_OE "oes"
#define NIST_VAL_OP_MODULE "modules"
#define NIST_VAL_OP_DEPENDENCY "dependencies"
#define NIST_VAL_OP_ALGORITHMS "algorithms"
#define NIST_VAL_OP_LARGE "large"
#define NIST_VAL_OP_REQUESTS "requests"
#define NIST_VAL_OP_VALIDATIONS "validations"
#define NIST_VAL_OP_PURCHASE "purchase"
#define NIST_VAL_OP_PURCHASE_OPTIONS NIST_VAL_OP_PURCHASE "/options"
#define NIST_VAL_OP_LAB "lab"
#define NIST_VAL_OP_AVAIL_VSIDS NIST_VAL_OP_LAB "/availablevectorsets"
#define NIST_VAL_OP_LABS "labs"
#define NIST_VAL_OP_CRSESSIONS "crSessions"
#define NIST_VAL_OP_CERTREQUESTS "certRequests"
#define NIST_VAL_OP_EVIDENCESETS "evSets"
#define NIST_VAL_OP_ACVP "acvp"
#define NIST_VAL_OP_ESVP "esv"

/* acvp_protocol.txt: section 11.1 */
#define ACVP_JWT_TOKEN_MAX 16384
/* lifetime of token in seconds - we subtract some grace time */
#define ACVP_JWT_TOKEN_LIFETIME (1800 - 300)

struct acvp_auth_ctx {
	char *jwt_token; /* JWT token provided by server */
	size_t jwt_token_len;
	time_t jwt_token_generated; /* generation time in seconds since Epoch */

	/*
	 * Maximum size of message for regular submission (submissions with
	 * larger size must use the /large endpoint).
	 */
	uint32_t max_reg_msg_size;

	/*
	 * Certificate request ID of test session. If 0, no test session
	 * certificate request ID was applied for yet.
	 */
	uint32_t testsession_certificate_id;

	/*
	 * Certificate number of test session. If NULL, no test session
	 * certificate number was awarded yet. Note, if this value is non-NULL
	 * the publication of the test session is complete.
	 */
	char *testsession_certificate_number;

	/*
	 * As auth ctx is shared between multiple vsIds belonging to one testId,
	 * we must lock if we want to change it.
	 */
	mutex_t mutex;
};

struct acvp_modinfo_ctx {
	char *specificver;
	char *specificver_filesafe;
};

/**
 * @brief Search parameters that can be set by the caller. If an entry is NULL
 *	  it is not used as a search criteria.
 * @var modulename Module name as reported by the list operation
 * @var orig_modulename Module name without the implementation name
 * @var moduleversion Version string as reported by the list operation
 * @var vendorname Vendor name as reported by the list operation
 * @var execenv Execution environment as reported by the list operation
 * @var processor Processor name as reported by the list operation
 * @var modulename_fuzzy_search Use the given search strings in a fuzzy search
 *			    	(i.e. use strstr to search the name and not
 *			    	strncmp) for modulename
 * @var moduleversion_fuzzy_search Use the given search strings in a fuzzy
 *				   search (i.e. use strstr to search the name
 *				   and not strncmp) for moduleversion
 * @var vendorname_fuzzy_search Use the given search strings in a fuzzy search
 *			    	(i.e. use strstr to search the name and not
 *			    	strncmp) for vendorname
 * @var execenv_fuzzy_search Use the given search strings in a fuzzy search
 *			     (i.e. use strstr to search the name and not
 *			     strncmp) for execenv
 * @var processor_fuzzy_search Use the given search strings in a fuzzy search
 *			       (i.e. use strstr to search the name and not
 *			       strncmp) for processor
 *
 * @var only return when entropy source definition present
 *
 * @var submit_vsids Array of vsIds to be processed (if empty, all vsIDs are
 *		     in scope).
 * @var nr_submit_vsids Number of vsIDs that are to be searched.
 * @var submit_testids Array of testIds to be processed (if empty, all
 *		       testIDs are in scope).
 * @var nr_submit_testids Number of testIDs that are to be searched.
 */
struct acvp_search_ctx {
	char *modulename;
	char *orig_modulename;
	char *moduleversion;
	char *vendorname;
	char *execenv;
	char *processor;
	bool modulename_fuzzy_search;
	bool moduleversion_fuzzy_search;
	bool vendorname_fuzzy_search;
	bool execenv_fuzzy_search;
	bool processor_fuzzy_search;

	bool with_es_def;

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
	char *jwtcertref;
	char *messagesizeconstraint;
	char *testsession_certificate_id;
	char *testsession_certificate_info;
	char *verdictfile;
	char *processedfile;
	char *srcserver;
	char *expectedfile;
	char *esvp_statusfile;
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
	 * Certify request for ESVP proxy
	 */
	bool esv_certify;

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

	/* Disable threading */
	bool threading_disabled;

	/*
	 * Generate array with prerequisites during publication phase.
	 */
	bool no_publish_prereqs;

	/*
	 * Delete the VSID the operation applies to
	 */
	bool delete_vsid;

	/*
	 * Only register a new request without downloading the test vectors.
	 * This is intended to spend only a brief amount of time to request
	 * the generation of test vectors and obtain the test vectors at a
	 * later point in time.
	 */
	bool register_only;

	/*
	 * Only upload test responses without fetching the verdict. To
	 * fetch the verdict, simply invoke the operation to re-post the data
	 * without this flag set.
	 */
	bool upload_only;

	/*
	 * Delete an entry in the ACVP database. The ID is taken from the
	 * module's JSON configuration file.
	 */
#define ACVP_OPTS_DELUP_OE (1 << 0) /** Delete / update OE entry */
#define ACVP_OPTS_DELUP_VENDOR (1 << 1) /** Delete / update vendor entry */
#define ACVP_OPTS_DELUP_MODULE (1 << 2) /** Delete / update module entry */
#define ACVP_OPTS_DELUP_PERSON (1 << 3) /** Delete / update person entry */
#define ACVP_OPTS_DELUP_FORCE (1 << 30) /** Force a deletion operation */
	unsigned int delete_db_entry;

#define ACVP_OPTS_SHOW_OE (1 << 0) /** Show OE entries */
#define ACVP_OPTS_SHOW_VENDOR (1 << 1) /** Show vendor entries */
#define ACVP_OPTS_SHOW_MODULE (1 << 2) /** Show module entries */
#define ACVP_OPTS_SHOW_PERSON (1 << 3) /** Show person entries */
#define ACVP_OPTS_SHOW_VALIDATION (1 << 4) /** Show person entries */
	unsigned int show_db_entries;

	/*
	 * Update an entry with the ACVP database. The ID is taken from the
	 * module's JSON configuration file. The update takes only place if
	 * there is no consistency between the local configuration and the
	 * ACVP server's entry can be established.
	 */
	unsigned int update_db_entry;

	/*
	 * Fully formatted JSON request file provided by caller.
	 */
	bool caller_json_request_set;
	char caller_json_request[FILENAME_MAX];
};

/**
 * @brief Specification of information to be renamed
 *
 * @var moduleversion_new new module version string (moduleVersion)
 * @var modulename_new new module name (moduleName)
 * @var oe_env_name_new new OE name (oeEnvName)
 * @var proc_name_new new processor name (procName)
 * @var proc_series_new new processor series name (procSeries)
 * @var proc_family_new new processor family name (procFamily)
 */
struct acvp_rename_ctx {
	const char *moduleversion_new;
	const char *modulename_new;
	const char *oe_env_name_new;
	const char *proc_name_new;
	const char *proc_series_new;
	const char *proc_family_new;
};

struct acvp_ctx {
	struct acvp_modinfo_ctx modinfo;
	struct acvp_req_ctx req_details;
	struct acvp_datastore_ctx datastore;
	struct acvp_opts_ctx options;
	struct acvp_rename_ctx *rename;
	struct acvp_auth_ctx *ctx_auth; /* initial login auth token */

	void *private; /* Some private data */
};

enum acvp_protocol_type {
	unknown_protocol,
	acv_protocol,
	amv_protocol,
	esv_protocol,
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
 * @param production [in] Indicator whether it is production or demo server
 *			  access.
 * @param last_gen_cb [in] Callback to be invoked when a TOTP value is generated
 *			   to allow a framework to store the current time
 *			   for potential later initialization. This function
 *			   may be NULL if no callback is requested.
 *
 * @return 0 on success, < 0 on error
 */
int acvp_init(const uint8_t *seed, size_t seed_len, time_t last_gen,
	      bool production, void (*last_gen_cb)(const time_t now));

/**
 * @brief Load an ACVP Proxy extension
 *
 * The ACVP Proxy requires one or more module implementation definitions
 * (commonly found in lib/module_implementations/). To allow out-of-tree
 * module definition, this API allows providing a path name to a shared
 * library that contains the module implementation definition.
 *
 * The out-of-tree module implementation definition must use the macro
 * ACVP_EXTENSION to announce its data structure, i.e. provide the pointer
 * to the struct def_algo_map as the root of the module definition.
 *
 * An example Makefile for an out-of-tree compilation is provided in
 * helper/Makefile.out-of-tree.
 *
 * @param path [in] Path name of the shared library
 * @return 0 on success, < 0 on error
 */
int acvp_load_extension(const char *path);

/**
 * @brief Load all ACVP Proxy extensions found in given directory
 *
 * Invoke acvp_load_extension on all shared libraries found in the given
 * directory.
 *
 * @param dir [in] directory name holding the shared libraries
 * @return 0 on success, < 0 on error
 */
int acvp_load_extension_directory(const char *dir);

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
 * @brief Set networking protocol definition
 *
 * @param proto [in] Definition of protocol
 *
 * @return 0 on success, < 0 on error
 */
int acvp_set_proto(enum acvp_protocol_type proto);

/**
 * @brief Set networking information to reach CAVP server
 *
 * @param server_name [in] CAVP server name
 * @param port [in] CAVP server port
 * @param ca [in] CA file to support server authentication. If NULL, server
 *	     certificate is not validated.
 * @param ca_keychain_ref [in] macOS keychain reference identifier to resolve the CA certifiate
 * @param client_cert [in] TLS client cert used for client authentication
 * @param client_cert_keychain_ref [in] macOS keychain reference identifier
 *	  to resolve client certifiate and key
 * @param client_key [in] TLS client key applicable to the client certificate.
 *			  This value may be NULL (e.g. when a P12 certificate
 *			  is used which contains the private key).
 * @param passcode [in] Passcode applicable to the private key (may be NULL
 *			if no passcode is required).
 *
 * @return 0 on success, < 0 on error
 */
int acvp_set_net(const char *server_name, unsigned int port, const char *ca,
		 const char *ca_keychain_ref, const char *client_cert,
		 const char *client_cert_keychain_ref, const char *client_key,
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
 *			     implementation definition.
 * @param specific_ver [in] Provide a version number that shall be registered
 *			    with CAVP instead of moduleversion.
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
 * NOTE: When the option of ctx.req_details.download_pending_vsid is set to
 * true, this function will not submit test results, but try to download
 * yet not downloaded test vectors! This allows the restart of a download if
 * the download somehow failed before.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_respond(const struct acvp_ctx *ctx);

/**
 * @brief Fetch verdicts for all vsIDs in scope. The verdict held by the
 *	  ACVP server is downloaded irrespective whether test results
 *	  have been sent or not.
 *
 * NOTE: This operation can also be used to "refresh" a vsID to guard it
 *	 against deletion after the 30 window.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_fetch_verdicts(const struct acvp_ctx *ctx);

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
int acvp_publish(struct acvp_ctx *ctx);

/**
 * @brief Synchronize the meta data information held locally with the server.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_synchronize_metadata(const struct acvp_ctx *ctx);

/**
 * @brief List all currently pending requests for the given context, including
 *	  any applicable search criteria. The command will list all
 *	  pending requests for all modules on STDOUT.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_list_request_ids(const struct acvp_ctx *ctx);

/**
 * @brief List all currently pending requests for the given context, including
 *	  any applicable search criteria. The command will list all
 *	  pending requests on STDOUT. Duplications are not printed
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_list_request_ids_sparse(const struct acvp_ctx *ctx);

/**
 * @brief List all available IDs for the given (search) context. A test
 *	  session ID is also a certificate id.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_list_available_ids(const struct acvp_ctx *ctx);

/**
 * @brief List all test verdicts for the given (search) context.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_list_verdicts(const struct acvp_ctx *ctx);

/**
 * @brief List all test session certificate numbers
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_list_certificates(const struct acvp_ctx *ctx);

/**
 * @brief List all test session with missing certificate numbers
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_list_missing_certificates(const struct acvp_ctx *ctx);

/**
 * @brief List all vector sets with missing results
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_list_missing_results(const struct acvp_ctx *ctx);

/**
 * @brief List all certificates with their tested ciphers
 *
 * @param ctx [in] ACVP Proxy library context
 * @param req_ciphers_file [in] JSON file that contains search definitions
 *				to limit the output of the ciphers. The JSON
 *				file must be an array of cipher name as key
 *				and implementation as value. This parameter
 *				may be NULL if no search limit is requested.
 *				For example:
 * {
 *	"ECDSA": {
 *		"implementation": "vng_ltc",
 *		"mode": [ "sigVer", "sigGen" ]
 *	},
 *	"ACVP-AES-CBC": {
 *		"implementation": "c_ltc"
 *	},
 *	"SHA2-256": {
 *		"implementation": "vng_ltc"
 *	}
 * }
 *
 * @return 0 on success, < 0 on error
 */
int acvp_list_certificates_detailed(const struct acvp_ctx *ctx,
				    const char *req_ciphers_file);

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
int acvp_versionstring(char *buf, const size_t buflen);

/**
 * @brief Return version string of the ACVP Proxy library in a numeric
 * expression
 *
 * @return numeric version
 */
uint32_t acvp_versionstring_numeric(void);

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
 * caller shall invoke this function repeatedly starting with idx_ptr
 * containing a zero. Every subsequent invocation shall use the idx_ptr
 * value that was returned from the previous round. If the return code -ENOENT
 * is returned, the caller shall stop the iteration. Every recorded testid
 * is returned with testid.
 *
 * @param idx_ptr [in/out] Index pointer to obtain the testID
 * @param testid [out] TestID at the given index pointer
 *
 * @return 0 on success, -ENOENT identifies that there is no testid for given
 *	   idx_ptr, < 0 on other error
 */
int acvp_list_failed_testid(int *idx_ptr, uint32_t *testid);

/**
 * @brief List all vsIDs with a verdict provided in passed
 *
 * During the download of the vsIDs, the verdict returned from the ACVP server
 * is processed and the global verdict for the vsID is obtained. The failing
 * and passing verdicts are maintained separately.
 *
 * With the function, the caller can obtain all vsIDs with failing or passing
 * verdicts. Naturally, the data is only present after a
 *
 * @param idx_ptr [in/out] Index pointer to obtain the testID
 * @param vsid [out] VsID at the given index pointer
 * @param passed [in] Boolean whether to look for passing verdicts (true) or
 *		      failing verdicts (false).
 *
 * @return 0 on success, -ENOENT identifies that there is no testid for given
 *	   idx_ptr, < 0 on other error
 */
int acvp_list_verdict_vsid(int *idx_ptr, uint32_t *vsid, const bool passed);

/**
 * @brief Retrieve all details about cipher definitions from the ACVP server
 *	  and dump it.
 *
 * @param ctx [in] ACVP Proxy library context
 * @param ciphername [in] Array of cipher names to search for - if NULL, the
 *			  list of ciphers is provided
 * @param ciphername_arraylen [in] Number of cipher name array entries
 * @param pathname [in] Directory to write the cipher definitions to. If NULL
 *			the library writes the list of supported ciphers to
 *			STDOUT.
 *
 * @return 0 on success, < 0 on error
 */
int acvp_cipher_get(const struct acvp_ctx *ctx, const char *ciphername[],
		    const size_t ciphername_arraylen, const char *pathname);

/**
 * @brief Rename the module information
 *
 * This call assumes that ctx->rename_ctx is filled in with the information
 * to be changed.
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_rename_module(const struct acvp_ctx *ctx);

/**
 * @brief List cipher options of all ciphers in scope
 *
 * @param ctx [in] ACVP Proxy library context
 * @param list_deps [in] Shall the cipher dependencies being listed?
 * @return 0 on success, < 0 on error
 */
int acvp_list_cipher_options(const struct acvp_ctx *ctx, const bool list_deps);

/**
 * @brief List the ACVP server database entries matching the local definitions
 *
 * @param ctx [in] ACVP Proxy library context
 * @return 0 on success, < 0 on error
 */
int acvp_server_db_list(const struct acvp_ctx *ctx);

enum acvp_server_db_search_type {
	NIST_SERVER_DB_SEARCH_VENDOR = 1,
	NIST_SERVER_DB_SEARCH_ADDRESSES,
	NIST_SERVER_DB_SEARCH_PERSONS,
	NIST_SERVER_DB_SEARCH_OE,
	NIST_SERVER_DB_SEARCH_MODULE,
	NIST_SERVER_DB_SEARCH_DEPENDENCY,
	NIST_SERVER_DB_SEARCH_VALIDATION,
};

/**
 * @brief Perform a search query of the ACVP server database with the
 *	  provided search string and the object type.
 *
 * @param ctx [in] ACVP Proxy library context
 * @param search_type [in] Object type to search
 * @param searchstr [in] Search string compliant to ACVP search specification
 *
 * @return 0 on success, < 0 on error
 */
int acvp_server_db_search(struct acvp_ctx *ctx,
			  const enum acvp_server_db_search_type search_type,
			  const char *searchstr);

/**
 * @brief Fetch the ACVP DB entry for the given ID of the given ID type.
 *
 * @param ctx [in] ACVP Proxy library context
 * @param search_type [in] Object type to search
 * @param id [in] ID to search for
 *
 * @return 0 on success, < 0 on error
 */
int acvp_server_db_fetch_id(struct acvp_ctx *ctx,
			    const enum acvp_server_db_search_type search_type,
			    const uint32_t id);

/**
 * @brief Fetch the ACVP DB entries to populate a new module_definitions
 *	  specification based on the given validation ID.
 *
 * @param ctx [in] ACVP Proxy library context
 * @param id [in] validation ID
 *
 * @return 0 on success, < 0 on error
 */
int acvp_server_db_fetch_validation(struct acvp_ctx *ctx, const uint32_t id);

/**
 * @brief List all available purchase options offered by the server
 *
 * @param ctx [in] ACVP Proxy library context
 *
 * @return 0 on success, < 0 on error
 */
int acvp_purchase_get_options(const struct acvp_ctx *ctx);

/**
 * @brief List number of purchased but yet unused vector sets.
 *
 * @param ctx [in] ACVP Proxy library context
 *
 * @return 0 on success, < 0 on error
 */
int acvp_purchase_list_available_vsids(const struct acvp_ctx *ctx);

/**
 * @brief Initiate purchase of purchase option with given quantity
 *
 * @param ctx [in] ACVP Proxy library context
 * @param opt [in] ACVP purchase option number that is returned by
 *		   acvp_get_purchase_options
 * @param qty [in] Amount how many the purchase option shall be bought
 * @param ponumber [in] Purchase order number - optional field that may be
 *			sent to NIST for making the payment request
 *
 * @return 0 on success, < 0 on error
 */
int acvp_purchase(const struct acvp_ctx *ctx, uint32_t opt, uint32_t qty,
		  const char *ponumber);

#ifdef __cplusplus
}
#endif

#endif /* ACVPPROXY_H */
