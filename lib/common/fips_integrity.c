/*
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include "binhexbin.h"
#include "compiler.h"
#include "config.h"
#include "fips.h"
#include "hash/hmac.h"
#include "hash/sha256.h"

static const char fipscheck_hmackey[] = "orboDeJITITejsirpADONivirpUkvarP";
#define FIPS_INTEGRITY_LOGGER_PREFIX "FIPS Integrity POST: "

/*
 * GCC v8.1.0 introduced -Wstringop-truncation but it is not smart enough to
 * find that cursor string will be NULL-terminated after all paste() calls and
 * warns with:
 * error: 'strncpy' destination unchanged after copying no bytes [-Werror=stringop-truncation]
 * error: 'strncpy' output truncated before terminating nul copying 5 bytes from a string of the same length [-Werror=stringop-truncation]
 */
#pragma GCC diagnostic push
#if GCC_VERSION >= 80100
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
static char *paste(char *dst, const char *src, size_t size)
{
	strncpy(dst, src, size);
	return dst + size;
}

/*
 * Convert a given file name into its respective HMAC file name
 *
 * return: NULL when malloc failed, a pointer that the caller must free
 * otherwise.
 */
#define CHECK_PREFIX "."
#define CHECK_SUFFIX "hmac"
static char *get_hmac_file(const char *filename)
{
	size_t i, filelen, pathlen, namelen, basenamestart = 0;
	size_t prefixlen = strlen(CHECK_PREFIX);
	size_t suffixlen = strlen(CHECK_SUFFIX);
	char *cursor, *checkfile = NULL;

	filelen = strlen(filename);
	if (filelen > FILENAME_MAX) {
		fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX "File too long\n");
		return NULL;
	}
	for (i = 0; i < filelen; i++) {
		if (!strncmp(filename + i, "/", 1))
			basenamestart = i + 1;
	}

	namelen = filelen - basenamestart;
	pathlen = basenamestart;

	checkfile = malloc(pathlen + namelen + prefixlen + 1 /* "." */ +
			   suffixlen + 1 /* null character */);
	if (!checkfile)
		return NULL;

	cursor = checkfile;
	if (pathlen > 0)
		cursor = paste(cursor, filename, pathlen);
	cursor = paste(cursor, CHECK_PREFIX, prefixlen);
	cursor = paste(cursor, filename + basenamestart, namelen);
	cursor = paste(cursor, "." CHECK_SUFFIX, 1 + suffixlen);
	strncpy(cursor, "\0", 1);
	return checkfile;
}
#pragma GCC diagnostic pop /* -Wstringop-truncation */

static int check_filetype(int fd, struct stat *sb)
{
	int ret = fstat(fd, sb);

	if (ret)
		return -errno;

	/* Do not return an error in case we cannot validate the data. */
	if ((sb->st_mode & S_IFMT) != S_IFREG &&
	    (sb->st_mode & S_IFMT) != S_IFLNK) {
		return -EINVAL;
	}

	return 0;
}

static int mmap_file(const char *filename, uint8_t **memory, uint32_t *size)
{
	int fd = -1;
	int ret = 0;
	struct stat sb;

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr,
			FIPS_INTEGRITY_LOGGER_PREFIX
			"Cannot open file %s: %s\n",
			filename, strerror(errno));
		return -EIO;
	}

	ret = check_filetype(fd, &sb);
	if (ret)
		goto out;

	*memory = NULL;
	*size = (uint32_t)sb.st_size;

	if (sb.st_size) {
		*memory = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED,
			       fd, 0);
		if (*memory == MAP_FAILED) {
			*memory = NULL;
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Use of mmap failed\n");
			ret = -ENOMEM;
			goto out;
		}
	}
out:
	close(fd);
	return ret;
}

static int process_checkfile(const char *checkfile, const char *targetfile)
{
	FILE *file = NULL;
	int ret = 0, checked_any = 0;
	uint32_t size = 0;
	uint8_t *memblock = NULL;
	int create_checkfile = 0;

	/*
	 * A file can have up to 4096 characters, so a complete line has at most
	 * 4096 bytes (file name) + 128 bytes (SHA512 hex value) + 2 spaces +
	 * one byte for the CR.
	 */
	char buf[(4096 + 128 + 2 + 1)];

	file = strcmp(checkfile, "-") ? fopen(checkfile, "r") : stdin;
	if (!file) {
		fprintf(stderr,
			FIPS_INTEGRITY_LOGGER_PREFIX
			"Cannot open file %s, creating it\n",
			checkfile);
		create_checkfile = 1;

		file = fopen(checkfile, "w");
		if (!file) {
			ret = -errno;
			fprintf(stderr,
				FIPS_INTEGRITY_LOGGER_PREFIX
				"Cannot create file %s\n",
				checkfile);
			goto out;
		}
	}

	ret = mmap_file(targetfile, &memblock, &size);
	if (ret)
		goto out;

	if (create_checkfile) {
		char *hexhash = NULL;
		uint32_t hexhashlen = 0;
		uint8_t calculated[SHA_MAX_SIZE_DIGEST];
		size_t written;

		hmac(sha256, (uint8_t *)fipscheck_hmackey,
		     sizeof(fipscheck_hmackey) - 1, memblock, size, calculated);

		ret = bin2hex_alloc(calculated, sha256->digestsize, &hexhash,
				    &hexhashlen);
		if (ret)
			goto out;

		written = fwrite(hexhash, 1, hexhashlen, file);
		free(hexhash);
		fwrite("\n", 1, 1, file);

		if (written != hexhashlen) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Failed to write hash to HMAC control file\n");
			ret = -EFAULT;
			goto out;
		}

		ret = 0;
		goto out;
	}

	while (fgets(buf, sizeof(buf), file)) {
		char *hexhash = NULL; // parsed hex value of hash
		uint8_t *binhash = NULL;
		uint32_t binhashlen;
		uint32_t hexhashlen = 0; // length of hash hex value
		uint32_t linelen = (uint32_t)strlen(buf);
		uint32_t i;
		unsigned char calculated[SHA_MAX_SIZE_DIGEST];

		if (linelen == 0)
			break;

		/* remove trailing CR and reduce buffer length */
		for (i = linelen - 1; i > 0; i--) {
			if (!isprint(buf[i])) {
				buf[i] = '\0';
				linelen--;
			} else
				break;
		}

		hexhash = buf;
		hexhashlen = linelen;

		if (!hexhash || !hexhashlen) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Invalid checkfile format\n");
			ret = -EINVAL;
			goto out;
		}

		ret = hex2bin_alloc(hexhash, hexhashlen, &binhash, &binhashlen);
		if (ret < 0)
			goto out;

		hmac(sha256, (uint8_t *)fipscheck_hmackey,
		     sizeof(fipscheck_hmackey) - 1, memblock, size, calculated);

		if (sha256->digestsize != binhashlen) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Calculated MAC length has unexpected length - integrity violation\n");
			free(binhash);
			ret = -EINVAL;
			goto out;
		}

		if (memcmp(calculated, binhash, sizeof(calculated))) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Message mismatch - integrity violation\n");
			free(binhash);
			ret = -EBADMSG;
			goto out;
		}

		free(binhash);

		checked_any = 1;
	}

	if (!checked_any)
		ret = -EBADF;

out:
	if (file)
		fclose(file);
	if (memblock)
		munmap(memblock, size);

	return ret;
}

int fips_post_integrity(const char *pathname)
{
	char *checkfile = NULL;
	size_t n = 0;
	int ret = -EINVAL;
	static char fipsflag[1] = { 'A' };
#define BUFSIZE 4096
	char selfname[BUFSIZE];
	const char *selfname_p;
	ssize_t selfnamesize = 0;

	if (fipsflag[0] == 'A') {
#ifdef HAVE_SECURE_GETENV
		if (secure_getenv("ACVPPROXY_FORCE_FIPS")) {
#else
		if (getenv("ACVPPROXY_FORCE_FIPS")) {
#endif
			fipsflag[0] = 1;
		} else {
			FILE *fipsfile = NULL;

			fipsfile = fopen("/proc/sys/crypto/fips_enabled", "r");
			if (!fipsfile) {
				if (errno == ENOENT) {
					/* FIPS support not enabled in kernel */
					return 0;
				} else {
					fprintf(stderr,
						FIPS_INTEGRITY_LOGGER_PREFIX
						"Cannot open fips_enabled file: %s\n",
						strerror(errno));
					return -EIO;
				}
			}

			n = fread((void *)fipsflag, 1, 1, fipsfile);
			fclose(fipsfile);
			if (n != 1) {
				fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
					"Cannot read FIPS flag\n");
				goto out;
			}
		}
	}

	if (fipsflag[0] == '0') {
		ret = 0;
		goto out;
	}

	if (pathname) {
		selfname_p = pathname;
	} else {
		/* Integrity check of our application. */
		memset(selfname, 0, sizeof(selfname));

		/*
		* Some OS-specific interfaces:
		* Mac OS X: _NSGetExecutablePath() (man 3 dyld)
		* Linux: readlink /proc/self/exe
		* Solaris: getexecname()
		* FreeBSD: sysctl CTL_KERN KERN_PROC KERN_PROC_PATHNAME -1
		* FreeBSD if it has procfs: readlink /proc/curproc/file
		* (FreeBSD doesn't have procfs by default)
		* NetBSD: readlink /proc/curproc/exe
		* DragonFly BSD: readlink /proc/curproc/file
		* Windows: GetModuleFileName() with hModule = NULL
		*/

#ifdef __linux__
		selfnamesize =
			readlink("/proc/self/exe", selfname, BUFSIZE - 1);
#elif __APPLE__
		selfnamesize = BUFSIZE - 1;
		if (_NSGetExecutablePath(selfname, (uint32_t *)&selfnamesize)) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Buffer for executable too small\n");
			ret = -ENAMETOOLONG;
			goto out;
		}
#else
	selfnamesize = -1;
#endif

		if (selfnamesize >= BUFSIZE || selfnamesize < 0) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Cannot obtain my filename\n");
			ret = -EFAULT;
			goto out;
		}

		selfname_p = selfname;
	}

	checkfile = get_hmac_file(selfname_p);
	if (!checkfile) {
		ret = -ENOMEM;
		goto out;
	}

	ret = process_checkfile(checkfile, selfname_p);

out:
	if (checkfile)
		free(checkfile);
	return ret;
}
