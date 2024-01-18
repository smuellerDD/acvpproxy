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

#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief base64 encode of arbitrary data
 *
 * @param idata [in] Binary data to encode
 * @param ilen [in] Length of the binary data
 * @param odata [out] Buffer holding the base64 encoded data. The caller must
 *		      free the buffer.
 * @param olen [out] Length of the output data
 *
 * @return 0 on success, < 0 on error
 */
int base64_encode(const uint8_t *idata, size_t ilen, char **odata,
		  size_t *olen);

/**
 * @brief base64 encode of arbitrary data with a URL/filename-safe output
 *	  alphabet
 *
 * @param idata [in] Binary data to encode
 * @param ilen [in] Length of the binary data
 * @param odata [out] Buffer holding the base64 encoded data. The caller must
 *		      free the buffer.
 * @param olen [out] Length of the output data
 *
 * @return 0 on success, < 0 on error
 */
int base64_encode_safe(const uint8_t *idata, size_t ilen, char **odata,
		       size_t *olen);

/**
 * @brief base64 decoding of arbitrary data
 *
 * @param idata [in] Buffer holding the base64 encoded data.
 * @param ilen [in] Length of the output data
 * @param odata [out] Binary data holding the decoded data. The caller must
 *		      free the buffer.
 * @param olen [out] Length of the binary data
 *
 * @return 0 on success, < 0 on error
 */
int base64_decode(const char *idata, size_t ilen, uint8_t **odata,
		  size_t *olen);

/**
 * @brief base64 decoding of arbitrary data with a URL/filename-safe input
 *	  alphabet
 *
 * @param idata [in] Buffer holding the base64 encoded data.
 * @param ilen [in] Length of the output data
 * @param odata [out] Binary data holding the decoded data. The caller must
 *		      free the buffer.
 * @param olen [out] Length of the binary data
 *
 * @return 0 on success, < 0 on error
 */
int base64_decode_safe(const char *idata, size_t ilen, uint8_t **odata,
		       size_t *olen);

#ifdef __cplusplus
}
#endif

#endif /* BASE64_H */
