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

#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct acvp_buf {
	uint32_t len;
	uint8_t *buf;
};

struct acvp_ext_buf {
	uint32_t len;
	uint8_t *buf;
	char *filename;
	char *data_type;
	struct acvp_ext_buf *next;
};

#define ACVP_BUFFER_INIT(buffer) struct acvp_buf buffer = { 0, NULL }

#define ACVP_EXT_BUFFER_INIT(buffer)                                           \
	struct acvp_ext_buf buffer = { 0, NULL, NULL, NULL, NULL }

void acvp_free_buf(struct acvp_buf *buf);
int acvp_alloc_buf(uint32_t size, struct acvp_buf *buf);

#ifdef __cplusplus
}
#endif

#endif /* BUFFER_H */
