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
 * Generate a JSON object of type range
 * Note the caller must initialize entry as an object.
 */
int acvp_req_gen_range(struct json_object *entry,
		       const struct def_algo_range *range, const char *key);

/*
 * Generate a JSON object of type range
 * Note the caller must initialize entry as an object.
 */
int acvp_req_gen_domain(struct json_object *entry,
			const struct def_algo_range *range, const char *key);

/*
 * Generate the prerequisite entry
 */
int acvp_req_gen_prereq(const struct def_algo_prereqs *in_prereqs,
			unsigned int num, struct json_object *entry);

/*
 * Add keyLen array for symmetric ciphers
 */
int acvp_req_sym_keylen(struct json_object *entry, unsigned int keyflags);

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

/**
 * Construct the ACVP URL for the given path
 * @param path [in] Path name of the URL
 * @param url [out] URL buffer allocated by caller
 * @param urllen [in] Length of the URL buffer allocated by caller
 */
int acvp_create_url(const char *path, char *url, uint32_t urllen);

/**
 * Construct the ACVP URL path (URL excluding host) for the given path
 * @param path [in] Path name of the URL
 * @param url [out] URL buffer allocated by caller
 * @param urllen [in] Length of the URL buffer allocated by caller
 */
int acvp_create_urlpath(const char *path, char *url, uint32_t urllen);

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
int acvp_extend_string(char *string, unsigned int stringmaxlen,
		       const char *fmt, ...);

/**
 * @brief Get the trailing number from a string. A lot of ACVP URLs have an
 *	  ID as the last pathname component which is obtained by this helper.
 */
int acvp_get_trailing_number(const char *string, uint32_t *number);


#ifdef __cplusplus
}
#endif

#endif /* REQUEST_HELPER_H */
