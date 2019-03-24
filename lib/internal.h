/*
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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

#ifndef INTERNAL_H
#define INTERNAL_H

#include <json-c/json.h>

#include "atomic_bool.h"
#include "atomic.h"
#include "buffer.h"
#include "config.h"
#include "definition.h"
#include "ret_checkers.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MAJVERSION 0   /* API / ABI incompatible changes,
			* functional changes that require consumer
			* to be updated (as long as this number is
			* zero, the API is not considered stable
			* and can change without a bump of the
			* major version). */
#define MINVERSION 6   /* API compatible, ABI may change,
			* functional enhancements only, consumer
			* can be left unchanged if enhancements are
			* not considered. */
#define PATCHLEVEL 5   /* API / ABI compatible, no functional
			* changes, no enhancements, bug fixes
			* only. */

/*
 * Requester implementations
 */
int acvp_req_set_algo_sym(const struct def_algo_sym *sym,
			  struct json_object *entry);
int acvp_req_set_algo_sha(const struct def_algo_sha *sha,
			  struct json_object *entry);
int acvp_req_set_algo_shake(const struct def_algo_shake *shake,
			    struct json_object *entry);
int acvp_req_set_algo_hmac(const struct def_algo_hmac *hmac,
			   struct json_object *entry);
int acvp_req_set_algo_cmac(const struct def_algo_cmac *cmac,
			   struct json_object *entry);
int acvp_req_set_algo_drbg(const struct def_algo_drbg *drbg,
			   struct json_object *entry);
int acvp_req_set_algo_rsa(const struct def_algo_rsa *rsa,
			  struct json_object *entry);
int acvp_req_set_algo_ecdsa(const struct def_algo_ecdsa *ecdsa,
			    struct json_object *entry);
int acvp_req_set_algo_eddsa(const struct def_algo_eddsa *eddsa,
			    struct json_object *entry);
int acvp_req_set_algo_dsa(const struct def_algo_dsa *dsa,
			  struct json_object *entry);
int acvp_req_set_algo_kas_ecc(const struct def_algo_kas_ecc *kas_ecc,
			      struct json_object *entry);
int acvp_req_set_algo_kas_ffc(const struct def_algo_kas_ffc *kas_ffc,
			      struct json_object *entry);
int acvp_req_set_algo_kdf_ssh(const struct def_algo_kdf_ssh *kdf_ssh,
			      struct json_object *entry);
int acvp_req_set_algo_kdf_ikev1(const struct def_algo_kdf_ikev1 *kdf_ikev1,
			        struct json_object *entry);
int acvp_req_set_algo_kdf_ikev2(const struct def_algo_kdf_ikev2 *kdf_ikev2,
			        struct json_object *entry);
int acvp_req_set_algo_kdf_tls(const struct def_algo_kdf_tls *kdf_tls,
			      struct json_object *entry);
int acvp_req_set_algo_kdf_108(const struct def_algo_kdf_108 *kdf_108,
			      struct json_object *entry);

/* Data structure used to exchange information with network backend. */
struct acvp_na_ex {
	const struct acvp_net_ctx *net;
	const char *url;
	const struct acvp_auth_ctx *server_auth;
};

/**
 * Network access backend
 *
 * This backend defines callback functions to be implemented by the network
 * access backends. All callbacks must be implemented
 *
 * @acvp_http_post: The data provided in register_buf shall be sent to the
 *		    CAVP server. This callback implements the HTTP POST. The
 *		    server will reply with data that is to be stored in the
 *		    response_buf. The callback implements the allocation of the
 *		    buffer memory. The caller may set either buffer to NULL when
 *		    no data is either sent or requested. Even when the
 *		    submit_buf is NULL, the POST operation must be performed
 *		    with an empty HTTP body.
 * @acvp_http_get: Obtain data from the CAVP server using the provided URL.
 *		   The CAVP response shall be stored in the provided buffer.
 *		   This callback implements the HTTP GET of the data.
 *		   The data buffer must be allocated by the callback.
 *		   The caller may set the buffer to NULL when no data is
 *		   requested.
 * @acvp_http_put: Submit data with the HTTP PUT operation to the CAVP server.
 * @acvp_http_delete: Perform a HTTP DELETE operation on the given URL.
 * @acvp_http_interrupt: Signal handler interrupted network operation, shut down
 *			 network operation gracefully.
 */
struct acvp_netaccess_be {
	int (*acvp_http_post)(const struct acvp_na_ex *netinfo,
			      const struct acvp_buf *submit_buf,
			      struct acvp_buf *response_buf);
	int (*acvp_http_get)(const struct acvp_na_ex *netinfo,
			     struct acvp_buf *response_buf);
	int (*acvp_http_put)(const struct acvp_na_ex *netinfo,
			     const struct acvp_buf *submit_buf,
			     struct acvp_buf *response_buf);
	int (*acvp_http_delete)(const struct acvp_na_ex *netinfo);
	void (*acvp_http_interrupt)(void);
};

/**
 * @brief Register network access backend.
 */
void acvp_register_na(struct acvp_netaccess_be *netaccess);

/**
 * @brief Data structure instantiated for either request or submission with
 *	  data required for this operation only. The lifetime of an instance
 *	  of this data structure is limited to one operation only.
 */
struct acvp_testid_ctx {
	struct acvp_testid_ctx *next;
	uint32_t testid;
	struct acvp_auth_ctx *server_auth;
	const struct definition *def;
	const struct acvp_ctx *ctx;

	atomic_t vsids_to_process;
	atomic_t vsids_processed;

	struct timespec start;

	bool sig_cancel_send_delete;	/* Send a DELETE HTTP request */
};

/**
 * @brief Data structure instantiated when a vsID is to be processed for either
 *	  submission or request. The lifetime of an instance of this data
 *	  structure is limited to one vsID operation only.
 *
 * Note: albeit @param testid_ctx is constified, the parameter server_auth
 * is allowed to be updated. This is appropriate as the server_auth includes
 * proper locking to serialize write-like changes. This is achieved by
 * explicitly un-constify the @param server_auth.
 */
struct acvp_vsid_ctx {
	uint32_t vsid;
	const struct acvp_testid_ctx *testid_ctx;

	bool resubmit_result;
	bool verdict_file_present;
	bool sample_file_present;
	bool vector_file_present;

	struct timespec start;
};

/**
 * @brief Datastore backend
 *
 * This backend handles the local data store of the data fetched from the
 * CAVP server. Note, the obtained test vectors must be forwarded to the
 * parser implementing the invocation of the module.
 *
 * @acvp_datastore_find_testsession: Find a test session that shall be
 *				     processed. The found test session is
 *				     in the testids array. The found test
 *				     test sessions are limited when specifying
 *				     datastore->search->testid.
 * @acvp_datastore_find_responses: Find the test results for the given vsID and
 *				   invoke the provided callback with the data.
 *				   Note, the data parameter shall be treated as
 *				   an opaque data structure that is left
 *				   untouched and used with the callback
 *				   invocation. The buffer with the test results
 *				   is allocated by the current callback and
 *				   freed after the cb invocation. Note, the cb
 *				   is called with a NULL buffer, if the
 *				   response file and the vector file is not
 *				   found. This allows the caller re-invoke the
 *				   download operation for the vector file.
 * @acvp_datastore_write_vsid: Store generic information given with the data
 *			       buffer to the location pointed to by filename at
 *			       the vsID level.
 * @acvp_datastore_write_testid: Store generic information given with the data
 *			       	 buffer to the location pointed to by filename
 *				 at the testID level.
 * @acvp_datastore_compare: Read the generic information from the file name and
 *			    compare it with the data in the provided buffer. If
 *			    the buffers match, return true (1). If the buffers
 *			    do not match, return false (0). In case of an
 *			    error, return negative error number.
 * @acvp_datastore_write_authoken: Store the authtoken found in datastore->auth.
 * @acvp_datastore_read_authtoken: Read the authtoken from the storage location
 *				   and place it into datastore->auth.
 */
struct acvp_datastore_be {
	int (*acvp_datastore_find_testsession)(
				const struct definition *def,
				const struct acvp_ctx *ctx,
				uint32_t *testids,
				unsigned int *testid_count);
	int (*acvp_datastore_find_responses)(
		const struct acvp_testid_ctx *testid_ctx,
		int (*acvp_submit_one_response)(
			const struct acvp_vsid_ctx *vsid_ctx,
			const struct acvp_buf *buf));
	int (*acvp_datastore_write_vsid)(const struct acvp_vsid_ctx *vsid_ctx,
		const char *filename, bool secure_location,
		const struct acvp_buf *data);
	int (*acvp_datastore_write_testid)(
		const struct acvp_testid_ctx *testid_ctx,
		const char *filename, bool secure_location,
		const struct acvp_buf *data);
	int (*acvp_datastore_compare)(const struct acvp_vsid_ctx *vsid_ctx,
		const char *filename, bool secure_location,
		const struct acvp_buf *data);
	int (*acvp_datastore_write_authtoken)(
		const struct acvp_testid_ctx *testid_ctx);
	int (*acvp_datastore_read_authtoken)(
		const struct acvp_testid_ctx *testid_ctx);
};

/**
 * @brief Register datastore backend.
 */
void acvp_register_ds(struct acvp_datastore_be *datastore);

#define CKNULL_C_LOG(v, r, c, ...) {					\
	if (!v) {							\
		logger(LOGGER_ERR, c, __VA_ARGS__);			\
		ret = r;						\
		goto out;						\
	}								\
}

#define ACVP_JSON_PUT_NULL(x)						\
	if (x) {							\
		json_object_put(x);					\
		x = NULL;						\
	}

#define ACVP_PTR_FREE_NULL(x)						\
	if (x) {							\
		free(x);						\
		x = NULL;						\
	}

#define ACVP_REQ_MAX_FAILED_TESTID	512

extern struct acvp_datastore_be *ds;
extern struct acvp_netaccess_be *na;
extern atomic_t glob_vsids_to_process;
extern atomic_t glob_vsids_processed;

/************************************************************************
 * General support functions
 ************************************************************************/

/**
 * @brief Is the ACVP library initialized?
 *
 * @return: true when initialized, false if not initialized.
 */
bool acvp_library_initialized(void);

/*
 * Structure to hold the parameters that the function implement the thread
 * requires.
 */
struct acvp_thread_reqresp_ctx {
	const struct acvp_ctx *ctx;
	const struct definition *def;
	uint32_t testid;
	int (*cb)(const struct acvp_ctx *ctx, const struct definition *def,
		  uint32_t testid);
};

/**
 * @brief return network configuration
 */
int acvp_get_net(const struct acvp_net_ctx **net);

/**
 * @brief obtain the testSession URL with the test id
 */
int acvp_testid_url(const struct acvp_testid_ctx *testid,
		    char *url, uint32_t urllen);

/**
 * @brief obtain the vectorSet URL
 */
int acvp_vectorset_url(const struct acvp_testid_ctx *testid_ctx, char *url,
		       uint32_t urllen);

/**
 * @brief obtain the vsID URL
 */
int acvp_vsid_url(const struct acvp_vsid_ctx *vsid_ctx, char *url,
		  uint32_t urllen);

/**
 * @brief Convert environment ID to string.
 */
int acvp_module_oe_type(enum def_mod_type env_type, const char **out_string);

/**
 * @brief Store duration of network transaction
 */
void acvp_record_vsid_duration(const struct acvp_vsid_ctx *vsid_ctx,
			       const char *pathname);
void acvp_record_testid_duration(const struct acvp_testid_ctx *testid_ctx,
				 const char *pathname);

/************************************************************************
 * ACVP data transport support
 ************************************************************************/

/**
 * @brief Fetch data and process potential retry responses. If the server
 * responds with a retry statement, this function will wait and iterate the
 * request again.
 *
 * Note, this function iterates indefinitely. If it is invoked in a thread,
 * you have to cancel the thread to stop this retry operation.
 */
int acvp_process_retry(const struct acvp_vsid_ctx *vsid_ctx,
		       struct acvp_buf *result_data,
		       const char *url,
	int (*debug_logger)(const struct acvp_vsid_ctx *vsid_ctx,
			    const struct acvp_buf *buf, int err));

/**
 * @brief Same as _acvp_process_retry, just with struct acvp_testid_ctx
 *	  parameter
 */
int acvp_process_retry_testid(const struct acvp_testid_ctx *testid_ctx,
			      struct acvp_buf *result_data,
			      const char *url);

/************************************************************************
 * ACVP fetching of test vectors
 ************************************************************************/

/**
 * @brief Properly dispose of the testid_ctx
 */
void acvp_release_testid (struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Properly dispose of the vsid_ctx
 */
void acvp_release_vsid_ctx(struct acvp_vsid_ctx *vsid_ctx);

/**
 * @brief Download the expected test results for vsID
 */
int acvp_get_testvectors_expected(const struct acvp_vsid_ctx *vsid_ctx);

/**
 * @brief Fetch a test vector for the given vsID.
 */
int acvp_get_testvectors(const struct acvp_vsid_ctx *vsid_ctx);

/**
 * @brief interrupt outstanding operation
 */
void acvp_op_interrupt(void);

/**
 * @brief enable ACVP operations
 */
void acvp_op_enable(void);

/************************************************************************
 * ACVP publishing of data
 ************************************************************************/

/**
 * @brief Function to iterate over all test definitions and all testIDs in
 *	  those test definitions to invoke the callback with each found
 *	  testID.
 */
int acvp_process_testids(const struct acvp_ctx *ctx,
			 int (*cb)(const struct acvp_ctx *ctx,
				   const struct definition *def,
				   uint32_t testid));

/**
 * @brief Helper to register various module_definitions
 */
int acvp_def_register(const struct acvp_testid_ctx *testid_ctx,
		      struct json_object *json,
		      const char *url, uint32_t *id);
/**
 * @brief Validate and potentially register vendor definition
 */
int acvp_vendor_handle(const struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Validate and potentially register operational environment definition
 */
int acvp_oe_handle(const struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Validate and potentially register module definition
 */
int acvp_module_handle(const struct acvp_testid_ctx *testid_ctx);

/************************************************************************
 * Authentication token management
 ************************************************************************/

/**
 * @brief Initialize an authtoken. The memory must already be allocated by
 * the caller.
 */
int acvp_init_auth(struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Release the information associated with the authentication token.
 * The caller must release the memory of the pointer.
 */
void acvp_release_auth(struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Implement login processing with the TOTP logic. Note, this function
 * can be called multiple times even with a live authentication or expired
 * authentication. In this case, the function will refresh the authentication
 * token.
 */
int acvp_login(const struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Set the authtoken in the ctx data structure as needed for subsequent
 * processing, such as when HTTP requests are to be generated.
 */
int acvp_set_authtoken(const struct acvp_testid_ctx *testid_ctx,
		       const char *authtoken);

/**
 * @brief Get the maximum message size to be used with regular upload paths
 */
int acvp_get_max_msg_size(const struct acvp_testid_ctx *testid_ctx,
			  uint32_t *size);

/************************************************************************
 * Signal handler support
 ************************************************************************/

/**
 * @brief Enqueue the context into the list maintained by the signal handler
 * code to ensure that each request represented with a context can be canceled
 * when a signal arrives. The caller should only enqueue the context shortly
 * before communication with the ACVP server commences.
 */
void sig_enqueue_ctx(struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Dequeue the context from the list maintained by the signal handler
 * code. A dequeued context will not be processed for canellation when a
 * signal is received.
 */
void sig_dequeue_ctx(struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Sleep the given amount of seconds and periodically check whether
 *	  the sleep should be interrupted.
 *
 * @param sleep_time [in] Time in seconds to sleeep
 * @param interrupted [in] Pointer to boolean that shall cause an interrupt
 *
 * @return 0 on full sleep, -EINTR on interrupt, < 0 on other errors
 */
int sig_sleep_interruptible(unsigned int sleep_time,
			    atomic_bool_t *interrupted);

/**
 * @brief Start the signal handler thread
 */
int sig_install_handler(void);
void sig_uninstall_handler(void);

/*
 * Are we handling a signal?
 */
bool sig_handler_active(void);

/************************************************************************
 * Common helper support
 ************************************************************************/

int acvp_duplicate(char **dst, const char *src);
int acvp_sanitize_string(char *string);
int acvp_store_vector_status(const struct acvp_vsid_ctx *vsid_ctx,
			     const char *fmt, ...);
int acvp_store_vector_debug(const struct acvp_vsid_ctx *vsid_ctx,
			    const struct acvp_buf *buf, int err);
int acvp_store_verdict_debug(const struct acvp_vsid_ctx *vsid_ctx,
			     const struct acvp_buf *buf, int err);
int acvp_store_submit_debug(const struct acvp_vsid_ctx *vsid_ctx,
			    const struct acvp_buf *buf, int err);
int acvp_store_login_debug(const struct acvp_testid_ctx *testid_ctx,
			   const struct acvp_buf *buf, int err);
int acvp_store_register_debug(const struct acvp_testid_ctx *testid_ctx,
			      const struct acvp_buf *buf, int err);
int acvp_store_vector_request_debug(const struct acvp_testid_ctx *testid_ctx,
				    const struct acvp_buf *buf, int err);
int acvp_store_vendor_debug(const struct acvp_testid_ctx *testid_ctx,
			    const struct acvp_buf *buf, int err);
int acvp_store_oe_debug(const struct acvp_testid_ctx *testid_ctx,
			const struct acvp_buf *buf, int err);
int acvp_store_module_debug(const struct acvp_testid_ctx *testid_ctx,
			    const struct acvp_buf *buf, int err);

int acvp_req_check_string(char *string, unsigned int slen);
int acvp_req_check_filename(char *string, unsigned int slen);

/************************************************************************
 * Data storage location
 ************************************************************************/

/* Data store directory for sensitive data including debug logs */
#define ACVP_DS_CREDENTIALDIR			"secure-datastore"
/* Data store directory for testvectors and other regular data */
#define ACVP_DS_DATADIR				"testvectors"
/* File that will hold the test response data */
#define ACVP_DS_TESTRESPONSE			"testvector-response.json"
/* File that stores the test vector */
#define ACVP_DS_TESTREQUEST			"testvector-request.json"
/* Authentication token to be (re)used to authenticate with ACVP server */
#define ACVP_DS_JWTAUTHTOKEN			"jwt_authtoken.txt"
/* Message size constraint - larger messages must use the /large endpoint */
#define ACVP_DS_MESSAGESIZECONSTRAINT		"messagesizeconstraint.txt"
/* File that will hold the test verdict from the ACVP server */
#define ACVP_DS_VERDICT				"verdict.json"
/* File that contains the time stamp when the vector was uploaded */
#define ACVP_DS_PROCESSED			"processed.txt"
/* File holding the URL of the ACVP server provided the test vector */
#define ACVP_DS_SRCSERVER			"acvp_server.txt"
/* File holding the expected test results */
#define ACVP_DS_EXPECTED			"testvector-expected.json"
/* File holding the metadata about the test session provided by ACVP server */
#define ACVP_DS_TESTIDMETA			"testid_metadata.json"
/* File holding the time in seconds the testID/vsID communication took */
#define ACVP_DS_DOWNLOADDURATION		"download_duration.txt"
#define ACVP_DS_UPLOADDURATION			"upload_duration.txt"
/* File containing the version information of the data store */
#define ACVP_DS_VERSIONFILE			"datastore_version.txt"
#define ACVP_DS_VERSION				2
/* File holding the unambiguous search criteria to look up cipher definition */
#define ACVP_DS_DEF_REFERENCE			"definition_reference.json"
/* File holding the ACVP request */
#define ACVP_DS_DEF_REQUEST			"request"

/* Directories pointing to definition information */
#define ACVP_DEF_DEFAULT_CONFIG_DIR		"module_definitions"
#define ACVP_DEF_DIR_OE				"oe"
#define ACVP_DEF_DIR_VENDOR			"vendor"
#define ACVP_DEF_DIR_MODINFO			"module_info"
#define ACVP_DEF_DIR_IMPLEMENTATIONS		"implementations"
#define ACVP_DEF_CONFIG_FILE_EXTENSION		".json"

/************************************************************************
 * Auxiliary information
 ************************************************************************/

/* Max 128 MB */
#define ACVP_RESPONSE_MAXLEN	(1<<27)

#if __GNUC__ >= 4
# define DSO_PUBLIC __attribute__ ((visibility ("default")))
#else
# define DSO_PUBLIC
#endif

#ifdef __cplusplus
}
#endif

#endif /* INTERNAL_H */
