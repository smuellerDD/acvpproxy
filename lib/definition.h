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

#ifndef DEFINITION_H
#define DEFINITION_H

#include <limits.h>
#include <stdint.h>

#include <json-c/json.h>

#include "acvpproxy.h"
#include "constructor.h"
#include "definition_cipher_drbg.h"
#include "definition_cipher_hash.h"
#include "definition_cipher_mac.h"
#include "definition_cipher_sym.h"
#include "definition_cipher_rsa.h"
#include "definition_cipher_ecdsa.h"
#include "definition_cipher_eddsa.h"
#include "definition_cipher_dsa.h"
#include "definition_cipher_kas_ecc.h"
#include "definition_cipher_kas_ffc.h"
#include "definition_cipher_kdf_ssh.h"
#include "definition_cipher_kdf_ikev1.h"
#include "definition_cipher_kdf_ikev2.h"
#include "definition_cipher_kdf_tls.h"
#include "definition_cipher_kdf_108.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Operational environment type */
enum def_mod_type {
	MOD_TYPE_SOFTWARE,
	MOD_TYPE_HARDWARE,
	MOD_TYPE_FIRMWARE,
};

/**
 * @brief This data structure defines a particular cipher algorithm
 *	  definition.
 *
 * @param type Specify the cipher type.
 * @param algo Fill in the data structure corresponding to the @param type
 *	       selection.
 */
struct def_algo {
	enum def_algo_type {
		/** symmetric ciphers, incl. AEAD */
		DEF_ALG_TYPE_SYM,
		/** SHA hashes */
		DEF_ALG_TYPE_SHA,
		/** SHAKE cipher */
		DEF_ALG_TYPE_SHAKE,
		/** HMAC ciphers */
		DEF_ALG_TYPE_HMAC,
		/** CMAC ciphers */
		DEF_ALG_TYPE_CMAC,
		/** SP800-90A DRBG cipher */
		DEF_ALG_TYPE_DRBG,
		/** FIPS 186-4 RSA cipher */
		DEF_ALG_TYPE_RSA,
		/** FIPS 186-4 ECDSA cipher */
		DEF_ALG_TYPE_ECDSA,
		/** Bernstein EDDSA cipher */
		DEF_ALG_TYPE_EDDSA,
		/** FIPS 186-4 DSA cipher */
		DEF_ALG_TYPE_DSA,
		/** KAS_ECC (ECDH, ECMQV) cipher */
		DEF_ALG_TYPE_KAS_ECC,
		/** KAS_ECC (Finite Field DH, Finite Field MQV) cipher */
		DEF_ALG_TYPE_KAS_FFC,
		/** SP800-135 KDF: SSH */
		DEF_ALG_TYPE_KDF_SSH,
		/** SP800-135 KDF: IKE v1 */
		DEF_ALG_TYPE_KDF_IKEV1,
		/** SP800-135 KDF: IKE v2 */
		DEF_ALG_TYPE_KDF_IKEV2,
		/** SP800-135 KDF: TLS */
		DEF_ALG_TYPE_KDF_TLS,
		/** SP800-108 KDF */
		DEF_ALG_TYPE_KDF_108,
	} type;
	union {
		/** DEF_ALG_TYPE_SYM */
		struct def_algo_sym sym;
		/** DEF_ALG_TYPE_SHA */
		struct def_algo_sha sha;
		/** DEF_ALG_TYPE_SHAKE */
		struct def_algo_shake shake;
		/** DEF_ALG_TYPE_HMAC */
		struct def_algo_hmac hmac;
		/** DEF_ALG_TYPE_CMAC */
		struct def_algo_cmac cmac;
		/** DEF_ALG_TYPE_DRBG */
		struct def_algo_drbg drbg;
		/** DEF_ALG_TYPE_RSA */
		struct def_algo_rsa rsa;
		/** DEF_ALG_TYPE_ECDSA */
		struct def_algo_ecdsa ecdsa;
		/** DEF_ALG_TYPE_EDDSA */
		struct def_algo_eddsa eddsa;
		/** DEF_ALG_TYPE_DSA */
		struct def_algo_dsa dsa;
		/** DEF_ALG_TYPE_KAS_ECC */
		struct def_algo_kas_ecc kas_ecc;
		/** DEF_ALG_TYPE_KAS_FFC */
		struct def_algo_kas_ffc kas_ffc;
		/** DEF_ALG_TYPE_KDF_SSH */
		struct def_algo_kdf_ssh kdf_ssh;
		/** DEF_ALG_TYPE_KDF_IKEV1 */
		struct def_algo_kdf_ikev1 kdf_ikev1;
		/** DEF_ALG_TYPE_KDF_IKEV2 */
		struct def_algo_kdf_ikev2 kdf_ikev2;
		/** DEF_ALG_TYPE_KDF_TLS */
		struct def_algo_kdf_tls kdf_tls;
		/** DEF_ALG_TYPE_KDF_108 */
		struct def_algo_kdf_108 kdf_108;
	} algo;
};

struct def_algo_map {
	const struct def_algo *algos;
	unsigned int num_algos;
	const char *algo_name;
	const char *processor;
	const char *impl_name;
	struct def_algo_map *next;
};

/* Warning, we operate with a signed int, so leave the highest bit untouched */
#define ACVP_REQUEST_INITIAL	(1<<30)
#define ACVP_REQUEST_PROCESSING	(1<<29)
#define ACVP_REQUEST_MASK	(ACVP_REQUEST_INITIAL | ACVP_REQUEST_PROCESSING)

static inline bool acvp_valid_id(uint32_t id)
{
	if (id == 0 || id & ACVP_REQUEST_MASK)
		return false;
	return true;
}

/**
 * @brief This data structure defines identifiers of the cipher implementation.
 *	  Note, this information will be posted at the CAVS web site.
 *
 * @param module_name Specify the name of the cryptographic module (i.e. cipher
 *		      implementation) under test.
 * @param module_name_filesafe Same information as @param module_name except
 *			       that the string is cleared of characters
 *			       inappropriate for file names.
 * @param module_type Specify the type of the module.
 * @param module_version Specify a string representing the version of the
 *			 module.
 * @param module_version_filesafe Same information as @param module_version
 *				  except that the string is cleared of
 *				  characters inappropriate for file names.
 * @param module_description Provide a brief description of the module.
 * @param def_module_file Configuration file holding the information
 * @param acvp_vendor_id Identifier assigned by the ACVP server to vendor
 *			 information.
 * @param acvp_person_id Identifier assigned by the ACVP server to person /
 *			 contact information.
 * @param acvp_addr_id Identifier assigned by the ACVP server to address
 *		       information.
 * @param acvp_module_id Identifier assigned by the ACVP server to module
 *			 information.
 */
struct def_info {
	char *module_name;
	char *module_name_filesafe;
	enum def_mod_type module_type;
	char *module_version;
	char *module_version_filesafe;
	char *module_description;

	char *def_module_file;
	uint32_t acvp_vendor_id;
	uint32_t acvp_person_id;
	uint32_t acvp_addr_id;
	uint32_t acvp_module_id;
};

/**
 * @brief This data structure contains the required details about the vendor
 *	  of the cipher implementation. Note, this information will be posted
 *	  at the CAVS web site.
 *
 * @param vendor_name Specify the name of the vendor.
 * @param vendor_name_filesafe Same information as @param vendor_name except
 *			       that the string is cleared of characters
 *			       inappropriate for file names.
 * @param vendor_url Specify the homepage of the vendor.
 * @param acvp_vendor_id Identifier assigned by the ACVP server to vendor
 *			 information.
 *
 * @param contact_name Specify the contact person responsible for the CAVS
 *		       test request.
 * @param contact_email Specify the contact email of the person responsible for
 *			the CAVS test request.
 * @param contact_phone Specify the contact telephone number
 * @param acvp_person_id Identifier assigned by the ACVP server to person /
 *			 contact information.
 *
 * @param addr_street Address: Street
 * @param addr_locality Address: City
 * @param addr_region Address: State
 * @param addr_country: Address Country
 * @param addr_zipcode: Address: Zip code
 * @param acvp_addr_id Identifier assigned by the ACVP server to address
 *		       information.
 *
 * @param def_vendor_file Configuration file holding the information
 */
struct def_vendor {
	char *vendor_name;
	char *vendor_name_filesafe;
	char *vendor_url;
	uint32_t acvp_vendor_id;

	char *contact_name;
	char *contact_email;
	char *contact_phone;
	uint32_t acvp_person_id;

	char *addr_street;
	char *addr_locality;
	char *addr_region;
	char *addr_country;
	char *addr_zipcode;
	uint32_t acvp_addr_id;

	char *def_vendor_file;
};

/**
 * @brief Specify operational environment information of the hosting execution
 *	 environment where the module is tested
 *
 * @param env_type Environment type
 * @param oe_env_name Name of the execution environment (e.g. operating
 *		     system or SoC)
 * @param cpe UNKNOWN
 *
 * @param manufacturer Processor manufacturer (e.g. "Intel")
 * @param proc_family Processor family (e.g. "X86")
 * @param proc_name Processor name (e.g. "Intel(R) Core(TM) i7-5557U")
 * @param proc_series Processor series (e.g. "Broadwell")
 * @param features Specify features of the CPU that are used by the module
 * @param def_oe_file Configuration file holding the information
 * @param acvp_oe_id Identifier assigned by the ACVP server to OE information.
 * @param acvp_oe_dep_sw_id Identifier assigned by the ACVP server to software
 *			    dependency information, if there is any.
 * @param acvp_oe_dep_proc_id Identifier assigned by the ACVP server to
 *			      processor dependency information, if there is any.
 */
/* Operational environment processor features */
#define OE_PROC_X86_RDRAND	(1<<0)
#define OE_PROC_X86_AESNI	(1<<1)
#define OE_PROC_X86_CLMULNI	(1<<2)
#define OE_PROC_S390_CPACF	(1<<3)
#define OE_PROC_ARM_AES		(1<<4)
struct def_oe {
	enum def_mod_type env_type;
	char *oe_env_name;
	char *cpe;
	char *swid;
	char *oe_description;

	char *manufacturer;
	char *proc_family;
	char *proc_name;
	char *proc_series;
	uint64_t features;

	char *def_oe_file;
	uint32_t acvp_oe_id;
	uint32_t acvp_oe_dep_sw_id;
	uint32_t acvp_oe_dep_proc_id;
};

static const struct acvp_feature {
	uint64_t feature;
	const char *name;
} acvp_features[] = {
	{ OE_PROC_X86_RDRAND,	"rdrand" },
	{ OE_PROC_X86_AESNI,	"aes-ni" },
	{ OE_PROC_X86_CLMULNI,	"clmulni" },
	{ OE_PROC_S390_CPACF,	"cpacf" },
	{ OE_PROC_ARM_AES,	"aes" },
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define SET_IMPLEMENTATION(impl)					\
	.algos = impl, .num_algos = ARRAY_SIZE(impl)

/**
 * @brief This data structure is the root of a cipher definition. It is made
 *	 known to the library using the acvp_req_register_def function call
 *	 which should be invoked during the initialization time of the
 *	 library.
 *
 * @param info This pointer provides generic information about the module.
 * @param algos This pointer refers to the cipher specific information. It is
 *	       	permissible to register multiple algorithm specifications with
 *	       	multiple instances of the data structure. However, all instances
 *	       	of the data structure must be adjacent in memory to allow
 *	       	iterating over it.
 * @param num_algos The number of algorithm definitions is specified here.
 *		    Commonly ARRAY_SIZE(algos) would be used here.
 * @param next This pointer is internal to the library and MUST NOT be used.
 */
struct definition {
	struct def_info *info;
	const struct def_algo *algos;
	unsigned int num_algos;
	struct def_vendor *vendor;
	struct def_oe *oe;
	struct definition *next;
};

/**
 * @brief Register uninstantiated algorithm definitions (i.e. definitions
 *	  without meta data of module information, operational environment,
 *	  and vendor information).
 *
 * @param curr_map Pointer to the uninstantiated algorithm definition.
 * @param nrmaps Number of map definitions pointed to by @param curr_map
 */
void acvp_register_algo_map(struct def_algo_map *curr_map, unsigned int nrmaps);

/**
 * @brief Iterate over all definitions and return when one match is found.
 *	  The processed_ptr can be used to indicate the entry in the linked list
 *	  that is used as a start point but what was already processed. I.e. the
 *	  search will continue with the entry following the processed_ptr.
 *
 *	  If processed_ptr is NULL, the head of the list is used.
 *
 * @param search Search definition
 * @param processed_ptr Starting point in linked list
 *
 * @return Found definition or NULL if no entry found.
 */
struct definition *acvp_find_def(const struct acvp_search_ctx *search,
				 struct definition *processed_ptr);

/**
 * @brief Apply the definition database search criteria found in the provided
 *	  JSON object to find the corresponding cipher definition. Match the
 *	  found cipher definition with the one registered in @param testid_ctx.
 *
 *	  NOTE: Only the first matching definition is checked, since this
 *	  function expects the search criteria to be specific enough to refer
 *	  to only one definition.
 *
 * @param testid_ctx [in] TestID context whose definition that shall be
 *			  obtained.
 * @param def_config [in] JSON object holding the search criteria
 *
 * @return: 0 on success, < 0 on errors
 */
struct acvp_testid_ctx;
int acvp_match_def(const struct acvp_testid_ctx *testid_ctx,
		   struct json_object *def_config);

/**
 * @brief Convert the provided definition into an unambiguous search criteria
 *	  catalog that can readily be stored.
 *
 * @param testid_ctx [in] TestID context holding the definition that shall
 *			  be unambiguously found again.
 */
int acvp_export_def_search(struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Update the vendor / OE / module ID in the configuration files
 */
int acvp_def_update_vendor_id(struct def_vendor *def_vendor);
int acvp_def_update_person_id(struct def_vendor *def_vendor);
int acvp_def_update_oe_id(struct def_oe *def_oe);
int acvp_def_update_module_id(struct def_info *def_info);
void acvp_def_release_all(void);

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_H */
