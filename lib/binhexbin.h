/*
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file
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

#ifndef _BINHEXBIN_H
#define _BINHEXBIN_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

void hex2bin(const char *hex, uint32_t hexlen,
	     uint8_t *bin, uint32_t binlen);
int hex2bin_alloc(const char *hex, uint32_t hexlen,
		  uint8_t **bin, uint32_t *binlen);
int bin2hex_alloc(const uint8_t *bin, uint32_t binlen,
		  char **hex, uint32_t *hexlen);
void bin2print(const unsigned char *bin, uint32_t binlen,
	       FILE *out, const char *explanation);
void bin2hex(const uint8_t *bin, uint32_t binlen,
	     char *hex, uint32_t hexlen, int u);

int bin2hex_html(const char *str, uint32_t strlen,
		 char *html, uint32_t htmllen);
int bin2hex_html_alloc(const char *str, uint32_t strlen,
		       char **html, uint32_t *htmllen);

#ifdef __cplusplus
}
#endif

#endif /* _BINHEXBIN_H */
