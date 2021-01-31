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

#ifndef DEFINITION_INTERNAL_H
#define DEFINITION_INTERNAL_H

#include <limits.h>
#include <stdint.h>

#include <json-c/json.h>

#include "acvpproxy.h"
#include "atomic.h"
#include "constructor.h"
#include "definition.h"
#include "esvp_definition.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Operational environment type */
enum def_mod_type {
	MOD_TYPE_SOFTWARE,
	MOD_TYPE_HARDWARE,
	MOD_TYPE_FIRMWARE,
};

static const struct def_mod_type_conversion {
	enum def_mod_type type;
	char *type_name;
} def_mod_type_conversion[] = { { MOD_TYPE_SOFTWARE, "Software" },
				{ MOD_TYPE_HARDWARE, "Hardware" },
				{ MOD_TYPE_FIRMWARE, "Firmware" } };

/* Warning, we operate with a signed int, so leave the highest bit untouched */
#define ACVP_REQUEST_INITIAL (1 << 30)
#define ACVP_REQUEST_PROCESSING (1 << 29)
#define ACVP_REQUEST_REJECTED (1 << 28)
#define ACVP_REQUEST_MASK                                                      \
	(ACVP_REQUEST_INITIAL | ACVP_REQUEST_PROCESSING | ACVP_REQUEST_REJECTED)

static inline uint32_t acvp_id(uint32_t id)
{
	return (id & ~(uint32_t)ACVP_REQUEST_MASK);
}

static inline bool acvp_valid_id(uint32_t id)
{
	if (id == 0 || id & ACVP_REQUEST_MASK)
		return false;
	return true;
}

static inline bool acvp_request_id(uint32_t id)
{
	if (id & ACVP_REQUEST_MASK)
		return true;
	return false;
}

struct def_lock {
	mutex_t lock;
	atomic_t refcnt;
};

/**
 * @brief This data structure defines identifiers of the cipher implementation.
 *	  Note, this information will be posted at the CAVS web site.
 *
 * @var module_name Specify the name of the cryptographic module (i.e. cipher
 *		    implementation) under test.
 * @var impl_name Implementation name of module
 * @var impl_description Description of the module implementation (may be NULL)
 * @var orig_module_name Original module name without the implementation name
 * @var module_name_filesafe Same information as @var module_name except
 *			     that the string is cleared of characters
 *			     inappropriate for file names.
 * @var module_name_internal If this is set, this name is used to map to
 *			     uninstantiated definitions. This name is not
 *			     used for external reference.
 * @var module_type Specify the type of the module.
 * @var module_version Specify a string representing the version of the module.
 * @var module_version_filesafe Same information as @var module_version
 *				except that the string is cleared of
 *				characters inappropriate for file names.
 * @var module_description Provide a brief description of the module.
 * @var def_module_file Configuration file holding the information
 * @var acvp_vendor_id Identifier assigned by the ACVP server to vendor
 *		       information.
 * @var acvp_person_id Identifier assigned by the ACVP server to person /
 *		       contact information.
 * @var acvp_addr_id Identifier assigned by the ACVP server to address
 *		     information.
 * @var acvp_module_id Identifier assigned by the ACVP server to module
 *		       information.
 */
struct def_info {
	char *module_name;
	char *impl_name;
	char *impl_description;
	char *orig_module_name;
	char *module_name_filesafe;
	char *module_name_internal;
	enum def_mod_type module_type;
	char *module_version;
	char *module_version_filesafe;
	char *module_description;

	char *def_module_file;
	uint32_t acvp_vendor_id;
	uint32_t acvp_person_id;
	uint32_t acvp_addr_id;
	uint32_t acvp_module_id;

	struct def_lock *def_lock;
};

/**
 * @brief This data structure contains the required details about the vendor
 *	  of the cipher implementation. Note, this information will be posted
 *	  at the CAVS web site.
 *
 * @var vendor_name Specify the name of the vendor.
 * @var vendor_name_filesafe Same information as @var vendor_name except
 *			     that the string is cleared of characters
 *			     inappropriate for file names.
 * @var vendor_url Specify the homepage of the vendor.
 * @var acvp_vendor_id Identifier assigned by the ACVP server to vendor
 *		       information.
 *
 * @var contact_name Specify the contact person responsible for the CAVS
 *		     test request.
 * @var contact_email Specify the contact email of the person responsible for
 *		      the CAVS test request.
 * @var contact_phone Specify the contact telephone number
 * @var acvp_person_id Identifier assigned by the ACVP server to person /
 *		       contact information.
 *
 * @var addr_street Address: Street
 * @var addr_locality Address: City
 * @var addr_region Address: State
 * @var addr_country: Address Country
 * @var addr_zipcode: Address: Zip code
 * @var acvp_addr_id Identifier assigned by the ACVP server to address
 *		     information.
 *
 * @var def_vendor_file Configuration file holding the information
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

	struct def_lock *def_lock;
};

enum def_dependency_type {
	def_dependency_os,
	def_dependency_hardware,
	def_dependency_software,
	def_dependency_firmware,
};

/* Operational environment processor features */
#define OE_PROC_X86_RDRAND (1 << 0)
#define OE_PROC_X86_AESNI (1 << 1)
#define OE_PROC_X86_CLMULNI (1 << 2)
#define OE_PROC_S390_CPACF (1 << 3)
#define OE_PROC_ARM_AES (1 << 4)

/**
 * @brief Specify one dependency
 *
 * @var acvp_dep_id Identifier assigned by the ACVP server to dependency
 *		    information, if there is any.
 * @var def_dependency_type Type of the dependency
 *
 * The following are usually for all types of dependencies (except CPU)
 * @var name Name of the dependency (e.g. operating system or SoC)
 * @var description Description of the dependency (e.g. operating system or SoC)
 * @var cpe CPE string of module (may be NULL)
 * @var swid SWID string of module (may be NULL)
 *
 * The following are usually for CPUs
 * @var manufacturer Processor manufacturer (e.g. "Intel")
 * @var proc_family Processor family (e.g. "X86")
 * @var proc_family_internal Processor family used for internal definition
 *	resolving
 * @var proc_name Processor name (e.g. "Intel(R) Core(TM) i7-5557U")
 * @var proc_series Processor series (e.g. "Broadwell")
 * @var features Specify features of the CPU that are used by the module
 */
struct def_dependency {
	uint32_t acvp_dep_id;
	enum def_dependency_type def_dependency_type;

	/* software */
	char *name;
	char *description;
	char *cpe;
	char *swid;

	/* cpu */
	char *manufacturer;
	char *proc_family;
	char *proc_family_internal;
	char *proc_name;
	char *proc_series;
	uint64_t features;

	struct def_dependency *next;
};

/**
 * @brief Specify operational environment information of the hosting execution
 *	  environment where the module is tested
 *
 * @var def_oe_file Configuration file holding the information
 * @var acvp_oe_id Identifier assigned by the ACVP server to OE information.
 * @var config_file_version Version of configuration file:
 *	v0 == v1: one processor ID and one SW dependency defined in flat JSON
 *	structure
 *	v2: dependencies are defined array of separate objects - each array
 *	member will internally be represented with one struct def_dependency
 *	representation in the same order as found in the JSON file
 * @var def_dep reference to all dependencies applicable to this OE.
 */
struct def_oe {
	char *def_oe_file;
	uint32_t acvp_oe_id;

	uint32_t config_file_version;
	struct def_dependency *def_dep;

	struct def_lock *def_lock;
};

static const struct acvp_feature {
	uint64_t feature;
	const char *name;
} acvp_features[] = {
	{ OE_PROC_X86_RDRAND, "rdrand" },   { OE_PROC_X86_AESNI, "aes-ni" },
	{ OE_PROC_X86_CLMULNI, "clmulni" }, { OE_PROC_S390_CPACF, "cpacf" },
	{ OE_PROC_ARM_AES, "aes" },
};

#define ACVP_DEF_PRODUCTION_ID(x)                                              \
	(acvp_req_is_production() ? x "Production" : x)

enum acvp_deps_type {
	acvp_deps_automated_resolution,
	acvp_deps_manual_resolution
};

/**
 * @brief Data structure holding cipher dependencies read from the configuration
 *	  file and the resolution of the dependency pointer.
 *
 * @var dep_cipher Cipher name for which the dependency applies to
 * @var dep_name Name of dependency
 * 		 (automated dependency handling: implementation name of
 *						 referenced definition
 *		  manual dependency handling: certificate)
 * @var deps_type Type of dependency: internal or external
 * @var dependency Pointer to the cipher definition that satisfies the
 *		   dependency
 * @var next This pointer is internal to the library and MUST NOT be used.
 */
struct def_deps {
	char *dep_cipher;
	char *dep_name;
	enum acvp_deps_type deps_type;
	const struct definition *dependency;
	struct def_deps *next;
};

/**
 * @brief This data structure is the root of a cipher definition. It is made
 *	 known to the library using the acvp_req_register_def function call
 *	 which should be invoked during the initialization time of the
 *	 library.
 *
 * @var info This pointer provides generic information about the module.
 * @var algos This pointer refers to the cipher specific information. It is
 *	      permissible to register multiple algorithm specifications with
 *	      multiple instances of the data structure. However, all instances
 *	      of the data structure must be adjacent in memory to allow
 *	      iterating over it.
 * @var num_algos The number of algorithm definitions is specified here.
 *		  Commonly ARRAY_SIZE(algos) would be used here.
 * @var es The entropy source definitions
 * @var uninstantiated_def Reference to uninstantiated algorithm definition
 * @var deps Dependencies - if NULL then no dependencies
 * @var next This pointer is internal to the library and MUST NOT be used.
 */
struct definition {
	struct def_info *info;
	const struct def_algo *algos;
	unsigned int num_algos;
	struct def_vendor *vendor;
	struct def_oe *oe;
	struct esvp_es_def *es;
	struct def_algo_map *uninstantiated_def;
	struct def_deps *deps;
	struct definition *next;
};

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
const struct definition *acvp_find_def(const struct acvp_search_ctx *search,
				       const struct definition *processed_ptr);

struct acvp_testid_ctx;
/**
 * @brief Apply the definition database search criteria found in the provided
 *	  JSON object to find the corresponding cipher definition. Match the
 *	  found cipher definition with the one registered in testid_ctx.
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
int acvp_match_def(const struct acvp_testid_ctx *testid_ctx,
		   const struct json_object *def_config);

/**
 * @brief Convert the provided definition into an unambiguous search criteria
 *	  catalog that can readily be stored.
 *
 * @param testid_ctx [in] TestID context holding the definition that shall
 *			  be unambiguously found again.
 */
int acvp_export_def_search(const struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Convert module name and implementation name into new string
 *	  to uniquely identify module.
 *
 * @newname [out] Newly allocated buffer with new name (caller must free)
 *		  buffer.
 * @module_name [in] Existing module name
 * @impl_name [in] Implementation name of module
 */
int acvp_def_module_name(char **newname, const char *module_name,
			 const char *impl_name);

int acvp_dep_name2type(const char *name, enum def_dependency_type *type);
int acvp_dep_type2name(enum def_dependency_type type, const char **name);

/**
 * @brief Update the vendor / OE / module ID in the configuration files
 *
 * The *_get_* functions obtain the current IDs and lock the respective
 * context. The *_put_* functions write the IDs to disk and unlock the
 * context.
 *
 * @return: 0 on success, < 0 on error (when the *_get_* functions return an
 *	    error, the lock is not taken).
 */
int acvp_def_get_vendor_id(struct def_vendor *def_vendor);
int acvp_def_put_vendor_id(const struct def_vendor *def_vendor);

int acvp_def_get_person_id(struct def_vendor *def_vendor);
int acvp_def_put_person_id(const struct def_vendor *def_vendor);

int acvp_def_get_oe_id(struct def_oe *def_oe);
int acvp_def_put_oe_id(const struct def_oe *def_oe);

int acvp_def_get_module_id(struct def_info *def_info);
int acvp_def_put_module_id(struct def_info *def_info);

void acvp_def_release_all(void);
void acvp_def_free_info(struct def_info *info);
void acvp_def_free_vendor(struct def_vendor *vendor);
void acvp_def_free_oe(struct def_oe *oe);
int acvp_def_alloc_lock(struct def_lock **lock);

/**
 * @brief write any updates of the definitions to the corresponding JSON
 * configuration files
 */
int acvp_def_update_oe_config(const struct def_oe *def_oe);
int acvp_def_update_module_config(const struct def_info *def_info);

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_INTERNAL_H */
