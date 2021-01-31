/* ACVP buffer handling handler
 *
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "buffer.h"
#include "logger.h"

/*****************************************************************************
 * Code for releasing memory
 *****************************************************************************/
int acvp_alloc_buf(uint32_t size, struct acvp_buf *buf)
{
	if (buf->buf) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Allocate an already allocated buffer!\n");
		return -EFAULT;
	}
	if (!size)
		return 0;

	buf->buf = calloc(1, size);
	if (!buf->buf)
		return -ENOMEM;

	buf->len = size;

	return 0;
}

void acvp_free_buf(struct acvp_buf *buf)
{
	if (!buf)
		return;
	if (buf->buf)
		free(buf->buf);
	buf->buf = NULL;
	buf->len = 0;
}

void acvp_free_ext_buf(struct acvp_ext_buf *buf)
{
	if (!buf)
		return;
	if (buf->buf)
		free(buf->buf);
	if (buf->data_type)
		free(buf->data_type);
	buf->data_type = NULL;
	buf->buf = NULL;
	buf->len = 0;

	/* leave the next buffer untouched to not leak memory */
}
