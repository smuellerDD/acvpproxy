/*
* Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

#ifndef REQUEST_HELPER_H
#define REQUEST_HELPER_H

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Match a particular cipher definition given with @param single whether
 * it is found in an ORed set of ciphers.
 *
 * This operation is needed because one particular cipher consists of
 * multiple flags. First, clear the ORed definition of all bits that are
 * not in the single cipher definition and then see whether all bits of
 * the single cipher definition are set.
 */
static inline bool acvp_match_cipher(cipher_t combination, cipher_t single)
{
	return ((combination &~ ~single) == single);
}

/*
 * Check that one given length definition is larger than the minimum
 * and smaller than a given maximum
 */
int acvp_req_valid_range_one(unsigned int min, unsigned int max,
			     unsigned int step, int supported_length);

/*
 * Check that a supported length definition is larger than the minimum
 * and smaller than a given maximum
 */
int acvp_req_valid_range(unsigned int min, unsigned int max, unsigned int step,
			 const int supported_lengths[]);
/*
 * Check whether a value is in a supported length definition.
 *
 * @param val [in] Value to be checked
 * @param supported_lengths [in] Range domain or list of integers defining the
 *				 range of allowed parameters.
 *
 * return 0 if value is within the range. < 0 on error
 */
int acvp_req_in_range(unsigned int val, const int supported_lengths[]);

/*
 * Add a domain specification with min/max/increment to entry at keyword
 * key.
 */
int acvp_req_algo_domain(struct json_object *entry,
			 unsigned int min, unsigned int max, unsigned int inc,
			 const char *key);

/*
 * Always create a JSON array even when there are no entries.
 * Note the caller must initialize entry as an array.
 */
int acvp_req_algo_int_array_always(struct json_object *entry,
				   const int vals[], const char *key);

/*
 * Only create a JSON array when there are entries to be added to the array.
 * Note the caller must initialize entry as an array.
 */
int acvp_req_algo_int_array(struct json_object *entry, const int vals[],
			    const char *key);
int acvp_req_algo_int_array_len(struct json_object *entry, const int vals[],
				unsigned int numvals, const char *key);

/*
 * Generate the prerequisite entry
 */
int acvp_req_gen_prereq(const struct def_algo_prereqs *in_prereqs,
			unsigned int num,
			const struct acvp_test_deps *deps,
			struct json_object *entry,
			bool publish);

/*
 * Add keyLen array for symmetric ciphers
 */
int acvp_req_sym_keylen(struct json_object *entry, unsigned int keyflags);
int acvp_set_sym_keylen(cipher_t keylen[DEF_ALG_MAX_INT],
			unsigned int keyflags);

/*
 * Add flag for TDES keying option
 */
int acvp_req_tdes_keyopt(struct json_object *entry, cipher_t algorithm);

/*
 * Convert an internal representation of the cipher reference to a string
 */
int acvp_req_cipher_to_name(cipher_t cipher, cipher_t cipher_type_mask,
			    const char **name);

/*
 * Convert an internal representation of the cipher reference to a JSON string
 *
 * Using the cipher_type_mask, the caller can narrow the search to only
 * the ciphers with this type mask. It is permissible to use 0 as mask.
 */
int acvp_req_cipher_to_string(struct json_object *entry, cipher_t cipher,
			      cipher_t cipher_type_mask, const char *key);

/*
 * Convert an internal representation of the cipher reference to a JSON array.
 *
 * Using the cipher_type_mask, the caller can narrow the search to only
 * the ciphers with this type mask. It is permissible to use 0 as mask.
 */
int acvp_req_cipher_to_array(struct json_object *entry, cipher_t cipher,
			     cipher_t cipher_type_mask, const char *key);

/*
 * Convert an internal representation of the cipher reference to an array
 * of cipher_t entries. I.e. if multiple definitions are found in
 * the cipher parameter, they are separated into individual entries
 *
 * Using the cipher_type_mask, the caller can narrow the search to only
 * the ciphers with this type mask. It is permissible to use 0 as mask.
 */
int acvp_req_cipher_to_intarray(cipher_t cipher,
				cipher_t cipher_type_mask,
				cipher_t array[DEF_ALG_MAX_INT]);

/*
 * Convert an internal representation of the cipher reference to a
 * comma-delimited string.
 */
int acvp_req_cipher_to_stringarray(cipher_t cipher,
				   cipher_t cipher_type_mask,
				   char **str);

/*
 * Add request revision number.
 */
int acvp_req_add_revision(struct json_object *entry, const char *str);

/**
 * Construct the ACVP URL for the given path
 * @param path [in] Path name of the URL
 * @param url [out] URL buffer allocated by caller
 * @param urllen [in] Length of the URL buffer allocated by caller
 */
int acvp_create_url(const char *path, char *url, uint32_t urllen);

/**
 * Construct the ACVP URL path (URL excluding host and prefix) for the given
 * path
 * @param path [in] Path name of the URL
 * @param url [out] URL buffer allocated by caller
 * @param urllen [in] Length of the URL buffer allocated by caller
 */
int acvp_create_urlpath(const char *path, char *url, uint32_t urllen);

/**
 * Append HTTP options to an URL - the options must be given without HTTP
 * option delimiter (i.e. the question mark or the ampersand)
 * @param options [in] HTTP options to add
 * @param url [out] URL buffer allocated by caller
 * @param urllen [in] Length of the URL buffer allocated by caller
 */
int acvp_append_urloptions(const char *options, char *url, uint32_t urllen);

/**
 * Replace any potentially existing HTTP options of a URL - the new options must
 * be given with the initial option delimiter (i.e. the question mark)
 * @param options [in] HTTP options to add
 * @param url [out] URL buffer allocated by caller
 * @param urllen [in] Length of the URL buffer allocated by caller
 */
int acvp_replace_urloptions(const char *options, char *url, uint32_t urllen);

/*
 * Duplicate string
 */
int acvp_duplicate_string(char **dst, const char *src);

/**
 * Extend character string whose buffer by given vargs
 * @param string [in/out] String to be extended
 * @param stringmaxlen [in] Buffer size of string
 * @param fmt [in] Format string of the data to append
 */
int acvp_extend_string(char *string, size_t stringmaxlen,
		       const char *fmt, ...);

/**
 * @brief Get the trailing number from a string. A lot of ACVP URLs have an
 *	  ID as the last pathname component which is obtained by this helper.
 */
int acvp_get_trailing_number(const char *string, uint32_t *number);

/**
 * Perform an exact or fuzzy match between two search strings.
 * @param searchstr needle
 * @param defstr haystack
 * @param fuzzy_search If true, perform a substring search, otherwise an
 *		       exact search is performed.
 *
 * @return true for match, false for no match
 */
bool acvp_find_match(const char *searchstr, const char *defstr,
		     bool fuzzy_search);


#ifdef __cplusplus
}
#endif

#endif /* REQUEST_HELPER_H */
