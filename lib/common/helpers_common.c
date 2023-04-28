/*
 * Copyright (C) 2019 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "binhexbin.h"
#include "hash/sha512.h"
#include "internal.h"
#include "term_colors.h"

/* remove wrong characters */
int acvp_req_check_string(char *string, size_t slen)
{
	if (!string || !slen)
		return 0;

	while (slen) {
		if (!isalnum(*string) && *string != '_' && *string != '-' &&
		    *string != '/' && *string != '.')
			*string = '_';

		string++;
		slen--;
	}

	return 0;
}

int acvp_req_check_filename(char *string, size_t slen)
{
	if (!string || !slen)
		return 0;

	if (!string || !slen)
		return 0;

	while (slen) {
		if (!isalnum(*string) && *string != '_' && *string != '-' &&
		    *string != '.')
			*string = '_';

		string++;
		slen--;
	}

	return 0;
}

void acvp_print_expiry(FILE *stream, time_t expiry)
{
	time_t now = time(NULL);

	if (now == (time_t)-1)
		fprintf(stream, "%lu", expiry);

	if (expiry < now)
		fprintf_blue(stream, "expired %lu days ago",
			     (now - expiry) / 86400);
	else if (now > (expiry - 2 * 86400))
		fprintf_red(stream, "in %lu days", (expiry - now) / 86400);
	else if (now > (expiry - 7 * 86400))
		fprintf_yellow(stream, "in %lu days", (expiry - now) / 86400);
	else
		fprintf_green(stream, "in %lu days", (expiry - now) / 86400);
}

int acvp_hash_file(const char *pathname, const struct hash *hash,
		   struct acvp_buf *md)
{
	struct stat statbuf;
	HASH_CTX_ON_STACK(ctx);
	ACVP_EXT_BUFFER_INIT(data);
	int ret, fd;

	if (stat(pathname, &statbuf)) {
		ret = -errno;
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "File name %s does not exist\n", pathname);
		return ret;
	}

	if (!S_ISREG(statbuf.st_mode)) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "%s is not a regular file\n",
		       pathname);
		return -EINVAL;
	}

	CKINT(acvp_alloc_buf(hash->digestsize, md));

	fd = open(pathname, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;

		logger(LOGGER_WARN, LOGGER_C_DS_FILE,
		       "Cannot open file %s (%d)\n", pathname, ret);
		goto out;
	}

	data.buf = mmap(NULL, (size_t)statbuf.st_size, PROT_READ, MAP_SHARED,
			fd, 0);
	if (data.buf == MAP_FAILED) {
		logger(LOGGER_WARN, LOGGER_C_DS_FILE, "Cannot mmap file %s\n",
		       pathname);
		ret = -ENOMEM;
		goto out;
	}

	data.len = (uint32_t)statbuf.st_size;

	hash->init(ctx);
	hash->update(ctx, data.buf, data.len);
	hash->final(ctx, md->buf);

	munmap(data.buf, (size_t)statbuf.st_size);
	close(fd);

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Hashing of file %s completed\n",
	       pathname);
	logger_binary(LOGGER_DEBUG, LOGGER_C_ANY, md->buf, md->len,
		      "Message digest of file");

out:
	return ret;
}

int acvp_cert_ref(struct acvp_buf *buf)
{
	const struct acvp_net_ctx *net;
	int ret;

	/* Write JWT certificate reference */
	CKINT(acvp_get_net(&net));
	if (net->certs_clnt_macos_keychain_ref) {
		CKINT(acvp_duplicate((char **)&buf->buf,
				     net->certs_clnt_macos_keychain_ref));
		buf->len = (uint32_t)strlen(net->certs_clnt_macos_keychain_ref);
	} else {
		ACVP_BUFFER_INIT(bin);
		char digest_hex[129];

		CKINT(acvp_hash_file(net->certs_clnt_file, sha512, &bin));
		memset(digest_hex, 0, sizeof(digest_hex));
		bin2hex(bin.buf, bin.len, digest_hex, sizeof(digest_hex) - 1,
			0);
		acvp_free_buf(&bin);

		CKINT(acvp_duplicate((char **)&buf->buf, digest_hex));
		buf->len = (uint32_t)strlen(digest_hex);
	}

out:
	return ret;
}
