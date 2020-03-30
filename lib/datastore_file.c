/* Datastore backend storing files
 *
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

#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "acvpproxy.h"
#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"
#include "threading_support.h"

struct acvp_datastore_thread_ctx {
	struct acvp_vsid_ctx *vsid_ctx;
	const char *datastore_base;
	const char *secure_base;
	int (*cb)(const struct acvp_vsid_ctx *vsid_ctx,
		  const struct acvp_buf *buf);
};

static int
acvp_datastore_write_data(const struct acvp_buf *data, const char *filename)
{
	FILE *file;
	size_t written;
	int ret = 0;

	if (!data || !data->buf)
		return 0;

	file = fopen(filename, "w");
	CKNULL(file, -errno);

	written = fwrite(data->buf, 1, data->len, file);
	if (written != data->len)
		logger(LOGGER_WARN, LOGGER_C_DS_FILE,
		       "data written (%u) mismatch with data available (%u)\n",
		       written, data->len);
	fclose(file);

out:
	return ret;
}

static int
acvp_datastore_read_data(uint8_t **buf, size_t *buflen, const char *filename)
{
	FILE *file;
	struct stat statbuf;
	uint8_t *l_buf = NULL, *ptr;
	size_t read, l_buflen, len;
	int ret = 0;

	/* Prevent memleak */
	if (buf && *buf)
		return -EINVAL;

	ret = stat(filename, &statbuf);
	if (ret)
		return -errno;

	if (!statbuf.st_size || statbuf.st_size > ACVP_JWT_TOKEN_MAX) {
		logger(LOGGER_WARN, LOGGER_C_DS_FILE,
		       "File %s is too large for reading (%lu bytes)",
		       filename, statbuf.st_size);
		return -ERANGE;
	}

	logger(LOGGER_DEBUG, LOGGER_C_DS_FILE, "Reading file %s\n", filename);
	l_buflen = (size_t)statbuf.st_size;
	l_buf = calloc(1, l_buflen + 1);
	CKNULL(l_buf, -ENOMEM);

	file = fopen(filename, "r");
	CKNULL_C_LOG(file, -ENOMEM, LOGGER_C_DS_FILE, "Cannot open file\n");

	ptr = l_buf;
	len = l_buflen;
	do {
		read = fread(ptr, 1, len, file);
		if (read > 0) {
			len -= read;
			ptr += read;
		}
	} while ((ret > 0 || EINTR == errno) && len);

	fclose(file);

	if (buf)
		*buf = l_buf;
	if (buflen)
		*buflen = l_buflen;

	ret = 0;

out:
	if (ret && l_buf)
		free(l_buf);
	return ret;
}

static int acvp_datastore_file_dir(char *dirname, bool createdir)
{
	struct stat statbuf;
	int ret;

	CKINT(acvp_req_check_string(dirname, strlen(dirname)));
	logger(LOGGER_DEBUG, LOGGER_C_DS_FILE, "Processing directory %s\n",
	       dirname);

	if (stat(dirname, &statbuf)) {
		int errsv = errno;

		if (errsv == ENOENT && createdir) {
			if (mkdir(dirname, 0777))
				return -errno;
			logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
			       "directory %s created\n", dirname);
		} else {
			logger(LOGGER_DEBUG,
			       LOGGER_C_DS_FILE, "Directory %s not created\n",
			       dirname);
			return -errsv;
		}
	}

out:
	return ret;
}

static int acvp_datastore_check_version(char *basedir, bool createdir)
{
	struct stat statbuf;
	size_t readbuflen;
	unsigned long readversion;
	int ret = 0;
	char verfile[5100];
	uint8_t *readbuf = NULL;

	CKINT(acvp_datastore_file_dir(basedir, createdir));

	snprintf(verfile, sizeof(verfile), "%s/%s", basedir,
		 ACVP_DS_VERSIONFILE);

	if (stat(verfile, &statbuf)) {
		ACVP_BUFFER_INIT(writebuf);
		char version[3];
		int errsv = errno;

		if (errsv != ENOENT)
			return -errsv;

		snprintf(version, sizeof(version), "%d", ACVP_DS_VERSION);
		writebuf.buf = (uint8_t *)version;
		writebuf.len = (uint32_t)strlen(version);
		CKINT(acvp_datastore_write_data(&writebuf, verfile));

		return 0;
	}

	CKINT(acvp_datastore_read_data(&readbuf, &readbuflen, verfile));
	CKNULL(readbuf, -ENOMEM);

	readversion = strtoul((char *)readbuf, NULL, 10);
	if (readversion >= ULONG_MAX) {
		ret = -ERANGE;
		goto out;
	}

	if (readversion != ACVP_DS_VERSION) {
		logger(LOGGER_ERR, LOGGER_C_DS_FILE, "Datastore at %s is old!\n",
		       basedir);
		return -ETIME;
	}

	logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
	       "Version of datastore %s is appropriate\n",
	       basedir);

out:
	if (readbuf)
		free(readbuf);
	return ret;
}

static int
acvp_datastore_file_target_dir(const struct acvp_testid_ctx *testid_ctx,
			       char *pathname, size_t pathnamelen,
			       bool createdir, bool secure_location)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	int ret;
	static atomic_t ds_ver_checked = ATOMIC_INIT(0);
	static atomic_t ds_secure_ver_checked = ATOMIC_INIT(0);

	if (!datastore || !datastore->secure_basedir || !datastore->basedir)
		return 0;

	if (secure_location) {
		snprintf(pathname, pathnamelen, "%s/",
			 datastore->secure_basedir);

		if (!atomic_read(&ds_secure_ver_checked)) {
			CKINT(acvp_datastore_check_version(pathname,
							   createdir));
			atomic_inc(&ds_secure_ver_checked);
			chmod(pathname, 0700);
		}
	} else {
		snprintf(pathname, pathnamelen, "%s", datastore->basedir);

		if (!atomic_read(&ds_ver_checked)) {
			CKINT(acvp_datastore_check_version(pathname,
							   createdir));
			atomic_inc(&ds_ver_checked);
		}
	}

	CKINT(acvp_datastore_file_dir(pathname, createdir));

out:
	return ret;
}

static int
acvp_datastore_file_testsessiondir(const struct acvp_testid_ctx *testid_ctx,
				   char *pathname, size_t pathnamelen,
				   bool createdir, bool secure_location)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_modinfo_ctx *modinfo = &ctx->modinfo;
	const struct definition *def = testid_ctx->def;
	const struct def_vendor *vendor = def->vendor;
	const struct def_info *info = def->info;
	const char *specificver = modinfo->specificver_filesafe;
	int ret;

	CKINT(acvp_datastore_file_target_dir(testid_ctx, pathname,
					     pathnamelen, createdir,
					     secure_location));

	if (vendor->vendor_name_filesafe) {
		CKINT(acvp_extend_string(pathname, pathnamelen, "/%s",
					 vendor->vendor_name_filesafe));
		CKINT(acvp_datastore_file_dir(pathname, createdir));
	}

	if (info->module_name_filesafe) {
		CKINT(acvp_extend_string(pathname, pathnamelen, "/%s",
					 info->module_name_filesafe));
		CKINT(acvp_datastore_file_dir(pathname, createdir));
	}

	if (info->module_version_filesafe) {
		CKINT(acvp_extend_string(pathname, pathnamelen, "/%s",
					 specificver ? specificver :
					 info->module_version_filesafe));
		CKINT(acvp_datastore_file_dir(pathname, createdir));
	}

out:
	return ret;
}

static int
acvp_datastore_file_vectordir(const struct acvp_testid_ctx *testid_ctx,
			      char *pathname, size_t pathnamelen,
			      bool createdir, bool secure_location)
{
	int ret;

	CKINT(acvp_datastore_file_testsessiondir(testid_ctx, pathname,
						 pathnamelen, createdir,
						 secure_location));

	CKINT(acvp_extend_string(pathname, pathnamelen, "/%u",
				 testid_ctx->testid));
	CKINT(acvp_datastore_file_dir(pathname, createdir));

out:
	return ret;
}

static int
acvp_datastore_file_rename_version(const struct acvp_testid_ctx *testid_ctx,
				   char *newversion)
{
	const struct definition *def = testid_ctx->def;
	struct def_info *info = def->info;
	char *currver = info->module_version_filesafe;
	char pathname[FILENAME_MAX];
	char newpathname[FILENAME_MAX];
	int ret;

	if (acvp_op_get_interrupted())
		return 0;

	if (!info->module_version_filesafe)
		return -EINVAL;

	/* rename secure location */
	CKINT(acvp_datastore_file_vectordir(testid_ctx, pathname,
					    sizeof(pathname), false, true));
	info->module_version_filesafe = newversion;
	CKINT(acvp_datastore_file_vectordir(testid_ctx, newpathname,
					    sizeof(pathname), true, true));
	info->module_version_filesafe = currver;
	ret = rename(pathname, newpathname);
	if (ret) {
		ret = -errno;
		goto out;
	}

	/* rename regular location */
	CKINT(acvp_datastore_file_vectordir(testid_ctx, pathname,
					    sizeof(pathname), false, false));
	info->module_version_filesafe = newversion;
	CKINT(acvp_datastore_file_vectordir(testid_ctx, newpathname,
					    sizeof(pathname), true, false));
	info->module_version_filesafe = currver;
	ret = rename(pathname, newpathname);
	if (ret) {
		ret = -errno;
		goto out;
	}


out:
	info->module_version_filesafe = currver;
	return ret;
}

static int
acvp_datastore_file_rename_name(const struct acvp_testid_ctx *testid_ctx,
				char *newname)
{
	const struct definition *def = testid_ctx->def;
	struct def_info *info = def->info;
	char *currname = info->module_name_filesafe;
	char pathname[FILENAME_MAX];
	char newpathname[FILENAME_MAX];
	int ret;

	if (acvp_op_get_interrupted())
		return 0;

	if (!info->module_name_filesafe)
		return -EINVAL;

	/* rename secure location */
	CKINT(acvp_datastore_file_vectordir(testid_ctx, pathname,
					    sizeof(pathname), false, true));
	info->module_name_filesafe = newname;
	CKINT(acvp_datastore_file_vectordir(testid_ctx, newpathname,
					    sizeof(pathname), true, true));
	info->module_name_filesafe = currname;
	ret = rename(pathname, newpathname);
	if (ret) {
		ret = -errno;
		goto out;
	}

	/* rename regular location */
	CKINT(acvp_datastore_file_vectordir(testid_ctx, pathname,
					    sizeof(pathname), false, false));
	info->module_name_filesafe = newname;
	CKINT(acvp_datastore_file_vectordir(testid_ctx, newpathname,
					    sizeof(pathname), true, false));
	info->module_name_filesafe = currname;
	ret = rename(pathname, newpathname);
	if (ret) {
		ret = -errno;
		goto out;
	}


out:
	info->module_name_filesafe = currname;
	return ret;
}

static int
acvp_datastore_file_vectordir_vsid(const struct acvp_vsid_ctx *vsid_ctx,
				   char *pathname, size_t pathnamelen,
				   bool createdir, bool secure_location)
{
	int ret;

	CKINT(acvp_datastore_file_vectordir(vsid_ctx->testid_ctx, pathname,
					    pathnamelen, createdir,
					    secure_location));

	CKINT(acvp_extend_string(pathname, pathnamelen, "/%u",
				 vsid_ctx->vsid));
	CKINT(acvp_datastore_file_dir(pathname, createdir));

out:
	return ret;
}

static int
acvp_datastore_file_write_authtoken(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_auth_ctx *auth;
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	const struct definition *def;
	struct acvp_buf tmp;
	char pathname[FILENAME_MAX / 2];
	char file[FILENAME_MAX], msgsize[12];
	int ret;

	CKNULL_C_LOG(testid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	if (acvp_op_get_interrupted())
		return 0;

	auth = testid_ctx->server_auth;
	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;
	def = testid_ctx->def;

	CKNULL_C_LOG(datastore, -EINVAL, LOGGER_C_DS_FILE,
		     "Datastore context missing\n");
	CKNULL_C_LOG(def, -EINVAL, LOGGER_C_DS_FILE,
		     "Module definition context missing\n");
	CKNULL_C_LOG(auth, -EINVAL, LOGGER_C_DS_FILE,
		     "Authentication context missing\n");

	CKINT(acvp_datastore_file_vectordir(testid_ctx, pathname,
					    sizeof(pathname), true, true));

	/* Write JWT access token */
	snprintf(file, sizeof(file), "%s/%s",
		 pathname, datastore->jwttokenfile);
	tmp.buf = (uint8_t *)auth->jwt_token;
	tmp.len = (uint32_t)auth->jwt_token_len;
	ret = acvp_datastore_write_data(&tmp, file);
	if (ret) {
		/*
		 * As a safety-measure, unlink the file to avoid somebody
		 * seeing or using a stale auth token.
		 *
		 * We do not care about the error code as we cannot do
		 * anything else here.
		 */
		unlink(file);
	} else {
		/*
		 * Ensure that nobody except the ACVP Proxy can access the
		 * token.
		 *
		 * Yes, there is a small time window in which the file may be
		 * world-readable (between the fopen/fwrite of
		 * acvp_datastore_write_data and the chmod). We accept that
		 * risk considering that there is a 2nd factor in addition
		 * to the JWT token: the TLS key for TLS client authentication.
		 * Thus even when somebody is able to obtain the JWT token
		 * in that brief moment, he cannot do anything with it (it is
		 * even bound to the TLS key that was used during the JWT
		 * token creation).
		 *
		 * We do not care about the error code as we cannot do
		 * anything else here. The likelihood of an error is very
		 * slim, as we just created and wrote the file.
		 */
		chmod(file, S_IRUSR | S_IWUSR);
	}

	logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
	       "JWT access token stored in %s\n", file);

	/* Write message size constraint information */
	snprintf(file, sizeof(file), "%s/%s",
		 pathname, datastore->messagesizeconstraint);
	snprintf(msgsize, sizeof(msgsize), "%u", auth->max_reg_msg_size);
	tmp.buf = (uint8_t *)msgsize;
	tmp.len = (uint32_t)strlen(msgsize);
	CKINT(acvp_datastore_write_data(&tmp, file));

out:
	return ret;
}

static int
acvp_datastore_file_uint(const char *pathname, const char *filename,
			 uint32_t *id)
{
	struct stat statbuf;
	int ret = 0;
	char file[FILENAME_MAX];

	/* Get message size */
	snprintf(file, sizeof(file), "%s/%s", pathname, filename);

	if (!stat(file, &statbuf) && statbuf.st_size) {
		size_t msgsize_len;
		unsigned long msgsize_int;
		char *msgsize = NULL;

		logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
		       "Try to read integer value from file %s\n", file);
		CKINT(acvp_datastore_read_data((uint8_t **)&msgsize,
					       &msgsize_len, file));

		msgsize_int = strtoul(msgsize, NULL, 10);
		free(msgsize);

		/* do not throw an error */
		if (msgsize_int >= UINT_MAX)
			*id = UINT_MAX;
		else
			*id = (uint32_t)msgsize_int;
	}

out:
	return ret;
}

static int
acvp_datastore_process_certinfo(const char *pathname, const char *filename,
				char **cert_no)
{
	struct stat statbuf;
	struct json_object *certinfo = NULL;
	int ret = 0;
	char file[FILENAME_MAX];

	snprintf(file, sizeof(file), "%s/%s", pathname, filename);
	if (!stat(file, &statbuf) && statbuf.st_size) {
		struct json_object *certdata, *certversion;
		const char *valId;

		CKINT(json_read_data(file, &certinfo));
		CKINT(json_split_version(certinfo, &certdata,
					 &certversion));
		CKINT(json_get_string(certdata, "validationId", &valId));
		CKINT(acvp_duplicate(cert_no, valId));
	}

out:
	if (certinfo)
		json_object_put(certinfo);
	return ret;
}

static int
acvp_datastore_file_read_authtoken(const struct acvp_testid_ctx *testid_ctx)
{
	struct acvp_auth_ctx *auth;
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	const struct definition *def;
	struct stat statbuf;
	int ret = 0;
	char pathname[FILENAME_MAX / 2];
	char file[FILENAME_MAX];

	CKNULL_C_LOG(testid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	if (acvp_op_get_interrupted())
		return 0;

	auth = testid_ctx->server_auth;
	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;
	def = testid_ctx->def;

	CKNULL_C_LOG(datastore, -EINVAL, LOGGER_C_DS_FILE,
		     "Datastore context missing\n");
	CKNULL_C_LOG(def, -EINVAL, LOGGER_C_DS_FILE,
		     "Module definition context missing\n");
	CKNULL_C_LOG(auth, -EINVAL, LOGGER_C_DS_FILE,
		     "Authentication context missing\n");

	ret = acvp_datastore_file_vectordir(testid_ctx, pathname,
					    sizeof(pathname), false, true);
	if (ret == -ENOENT)
		return 0;
	else if (ret)
		return ret;

	/* Get JWT token file */
	snprintf(file, sizeof(file), "%s/%s",
		 pathname, datastore->jwttokenfile);
	if (!stat(file, &statbuf) && statbuf.st_size) {
		logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
		       "Try to read auth token from file %s\n", file);

		if (auth->jwt_token) {
			free(auth->jwt_token);
			auth->jwt_token = NULL;
			auth->jwt_token_len = 0;
		}

		CKINT(acvp_datastore_read_data((uint8_t **)&auth->jwt_token,
					       &auth->jwt_token_len,
					       file));

#ifdef __APPLE__
		auth->jwt_token_generated = statbuf.st_mtimespec.tv_sec;
#else
		auth->jwt_token_generated = statbuf.st_mtim.tv_sec;
#endif

		logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
		       "Got authorization token %s\n", auth->jwt_token);
	}

	/* Get message size */
	auth->max_reg_msg_size = UINT_MAX;
	CKINT(acvp_datastore_file_uint(pathname,
				       datastore->messagesizeconstraint,
				       &auth->max_reg_msg_size));
	logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
	       "Maximum file size constraint %u\n",
	       auth->max_reg_msg_size);

	/* Get testsession certificate request ID */
	auth->testsession_certificate_id = 0;
	CKINT(acvp_datastore_file_uint(pathname,
				       datastore->testsession_certificate_id,
				       &auth->testsession_certificate_id));
	logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
	       "Test session certificate ID: %u\n",
	       auth->testsession_certificate_id);

	/* Get testsession certificate number */
	auth->testsession_certificate_number = NULL;
	CKINT(acvp_datastore_process_certinfo(pathname,
				datastore->testsession_certificate_info,
				&auth->testsession_certificate_number));

out:
	return ret;
}

static int
acvp_datastore_file_write_vsid(const struct acvp_vsid_ctx *vsid_ctx,
			       const char *filename, bool secure_location,
			       const struct acvp_buf *data)
{
	const struct acvp_testid_ctx *testid_ctx;
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	const struct definition *def;
	char pathname[FILENAME_MAX];
	int ret;

	CKNULL_C_LOG(vsid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	if (acvp_op_get_interrupted())
		return 0;

	testid_ctx = vsid_ctx->testid_ctx;
	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;
	def = testid_ctx->def;

	CKNULL_C_LOG(datastore, -EINVAL, LOGGER_C_DS_FILE,
		     "Datastore context missing\n");
	CKNULL_C_LOG(def, -EINVAL, LOGGER_C_DS_FILE,
		     "Module definition context missing\n");
	CKNULL_C_LOG(filename, -EINVAL, LOGGER_C_DS_FILE,
		     "Filename missing\n");
	CKNULL_C_LOG(data, -EINVAL, LOGGER_C_DS_FILE,
		     "Data buffer to be written missing\n");

	CKINT(acvp_datastore_file_vectordir_vsid(vsid_ctx, pathname,
						 sizeof(pathname), true,
						 secure_location));
	CKINT(acvp_extend_string(pathname, sizeof(pathname), "/%s",
				 filename));

	CKINT(acvp_datastore_write_data(data, pathname));

	logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
	       "data written for testID %u / vsID %u to file %s\n",
	       testid_ctx->testid, vsid_ctx->vsid, filename);

out:
	return ret;
}

static int
acvp_datastore_file_write_testid(const struct acvp_testid_ctx *testid_ctx,
				 const char *filename, bool secure_location,
				 const struct acvp_buf *data)
{
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	const struct definition *def;
	char pathname[FILENAME_MAX];
	int ret;

	CKNULL_C_LOG(testid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	if (acvp_op_get_interrupted())
		return 0;

	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;
	def = testid_ctx->def;

	CKNULL_C_LOG(datastore, -EINVAL, LOGGER_C_DS_FILE,
		     "Datastore context missing\n");
	CKNULL_C_LOG(def, -EINVAL, LOGGER_C_DS_FILE,
		     "Module definition context missing\n");
	CKNULL_C_LOG(filename, -EINVAL, LOGGER_C_DS_FILE,
		     "Filename missing\n");
	CKNULL_C_LOG(data, -EINVAL, LOGGER_C_DS_FILE,
		     "Data buffer to be written missing\n");

	CKINT(acvp_datastore_file_vectordir(testid_ctx, pathname,
					    sizeof(pathname), true,
					    secure_location));
	CKINT(acvp_extend_string(pathname, sizeof(pathname), "/%s",
				 filename));

	CKINT(acvp_datastore_write_data(data, pathname));

	logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
	       "data written for testID %u to file %s\n",
	       testid_ctx->testid, filename);

out:
	return ret;
}

static int
acvp_datastore_file_compare(const struct acvp_vsid_ctx *vsid_ctx,
			    const char *filename, bool secure_location,
			    const struct acvp_buf *data)
{
	const struct acvp_testid_ctx *testid_ctx;
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	const struct definition *def;
	char pathname[FILENAME_MAX];
	int ret;
	size_t buflen = 0;
	uint8_t *buf = NULL;

	CKNULL_C_LOG(vsid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	if (acvp_op_get_interrupted())
		return 0;

	testid_ctx = vsid_ctx->testid_ctx;
	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;
	def = testid_ctx->def;

	CKNULL_C_LOG(datastore, -EINVAL, LOGGER_C_DS_FILE,
		     "Datastore context missing\n");
	CKNULL_C_LOG(def, -EINVAL, LOGGER_C_DS_FILE,
		     "Module definition context missing\n");
	CKNULL_C_LOG(filename, -EINVAL, LOGGER_C_DS_FILE,
		     "Filename missing\n");
	CKNULL_C_LOG(data, -EINVAL, LOGGER_C_DS_FILE,
		     "Data buffer to be compared missing\n");
	CKNULL_C_LOG(data->buf, -EINVAL, LOGGER_C_DS_FILE,
		     "Data buffer to be compared missing\n");

	CKINT(acvp_datastore_file_vectordir_vsid(vsid_ctx, pathname,
						 sizeof(pathname), false,
						 secure_location));
	CKINT(acvp_extend_string(pathname, sizeof(pathname), "/%s",
				 filename));

	CKINT(acvp_datastore_read_data(&buf, &buflen, pathname));
	CKNULL(buf, -EFAULT);

	if ((size_t)data->len != buflen) {
		logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
		       "Datastore compare: string lengths do not match (requested length %u, found length %u)\n",
		       data->len, buflen);

		ret = 0;
		goto out;
	}
	if (memcmp(data->buf, buf, data->len)) {
		logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
		       "Datastore compare: strings do not match\n");
		ret = 0;
	} else {
		ret = 1;
	}

out:
	if (buf)
		free(buf);
	return ret;
}

static int
acvp_datastore_find_verdict(const struct acvp_datastore_ctx *datastore,
			    struct acvp_test_verdict_status *verdict,
			    char *verdict_dir, size_t verdict_dir_len)
{
	struct stat statbuf;
	int ret;

	CKINT(acvp_extend_string(verdict_dir, verdict_dir_len,
				 "/%s", datastore->verdictfile));

	/* Verdict file exists, return information to  */
	if (!stat(verdict_dir, &statbuf)) {
		ACVP_BUFFER_INIT(verdict_buf);
		int fd;

		/* Positive return code as this is no error */
		if (!verdict)
			return EEXIST;

		fd = open(verdict_dir, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			ret = -errno;

			logger(LOGGER_WARN, LOGGER_C_DS_FILE,
			       "Cannot open file %s (%d)\n", verdict_dir, ret);
			goto out;
		}

		verdict_buf.buf = mmap(NULL, (size_t)statbuf.st_size, PROT_READ,
				       MAP_SHARED, fd, 0);
		if (verdict_buf.buf == MAP_FAILED) {
			logger(LOGGER_WARN, LOGGER_C_DS_FILE,
			       "Cannot mmap file %s\n", verdict_dir);
			ret = -ENOMEM;
			goto out;
		}

		verdict_buf.len = (uint32_t)statbuf.st_size;
		ret = acvp_get_verdict_json(&verdict_buf, &verdict->verdict);

		munmap(verdict_buf.buf, (size_t)statbuf.st_size);
		close(fd);

		if (ret) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "File %s does not contain valid verdict\n",
			       verdict_dir);
			/*
			 * We are not stopping here and will not goto out,
			 * since we will report that the ID is unverified.
			 */
		}

		return 0;
	}

	/*
	 * If we have a verdict to fill and we reach here, we have no verdict
	 * file.
	 */
	if (verdict)
		verdict->verdict = acvp_verdict_unknown;

out:
	return ret;
}

static int
acvp_datastore_find_modinfo(const struct acvp_datastore_ctx *datastore,
			    struct acvp_test_verdict_status *verdict,
			    char *dir, size_t dir_len)
{
	struct stat statbuf;
	int ret;

	CKINT(acvp_extend_string(dir, dir_len, "/%s", datastore->vectorfile));

	/* Verdict file exists, return information to  */
	if (!stat(dir, &statbuf)) {
		ACVP_BUFFER_INIT(buf);
		int fd;

		/* Positive return code as this is no error */
		if (!verdict)
			return EEXIST;

		fd = open(dir, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			ret = -errno;

			logger(LOGGER_WARN, LOGGER_C_DS_FILE,
			       "Cannot open file %s (%d)\n", dir, ret);
			goto out;
		}

		buf.buf = mmap(NULL, (size_t)statbuf.st_size, PROT_READ,
			       MAP_SHARED, fd, 0);
		if (buf.buf == MAP_FAILED) {
			logger(LOGGER_WARN, LOGGER_C_DS_FILE,
			       "Cannot mmap file %s\n", buf);
			ret = -ENOMEM;
			goto out;
		}

		buf.len = (uint32_t)statbuf.st_size;
		ret = acvp_get_algoinfo_json(&buf, verdict);

		munmap(buf.buf, (size_t)statbuf.st_size);
		close(fd);

		if (ret) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "File %s does not contain valid cipher information\n",
			       dir);
			/*
			 * We are not stopping here and will not goto out,
			 * since we will report that the ID is unverified.
			 */
		}

		return 0;
	}

out:
	return ret;
}

static int
acvp_datastore_find_testid_verdict(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	char verdict_file[FILENAME_MAX];
	int ret;

	CKNULL_C_LOG(testid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;

	ret = acvp_datastore_file_vectordir(testid_ctx, verdict_file,
					    sizeof(verdict_file), false,
					    false);
	if (ret) {
		/* If pathname does not exist, we ignore it. */
		return 0;
	} else {
		CKINT(acvp_datastore_find_verdict(datastore, NULL, verdict_file,
						  sizeof(verdict_file)));
	}

out:
	return ret;
}

static int
acvp_datastore_get_testid_verdict(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	char vector_dir[FILENAME_MAX];
	int ret;

	CKNULL_C_LOG(testid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	if (acvp_op_get_interrupted())
		return 0;

	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;

	ret = acvp_datastore_file_vectordir(testid_ctx, vector_dir,
					    sizeof(vector_dir), false,
					    false);
	if (ret) {
		/* If pathname does not exist, we ignore it. */
		return 0;
	} else {
		CKINT(acvp_datastore_find_verdict(datastore,
						  &testid_ctx->verdict,
						  vector_dir,
						  sizeof(vector_dir)));

		CKINT(acvp_datastore_file_vectordir(testid_ctx, vector_dir,
						    sizeof(vector_dir), false,
						    false));
		CKINT(acvp_datastore_find_modinfo(datastore,
						  &testid_ctx->verdict,
						  vector_dir,
						  sizeof(vector_dir)));
	}

out:
	return ret;
}

static int
acvp_datastore_find_vsid_verdict(struct acvp_vsid_ctx *vsid_ctx)
{
	const struct acvp_testid_ctx *testid_ctx;
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	char vector_dir[FILENAME_MAX];
	int ret;

	CKNULL_C_LOG(vsid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");
	testid_ctx = vsid_ctx->testid_ctx;

	CKNULL_C_LOG(testid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;

	ret = acvp_datastore_file_vectordir_vsid(vsid_ctx, vector_dir,
						 sizeof(vector_dir), false,
						 false);
	if (ret) {
		/* If pathname does not exist, we ignore it. */
		return 0;
	} else {
		CKINT(acvp_datastore_find_verdict(datastore, NULL, vector_dir,
						  sizeof(vector_dir)));

		CKINT(acvp_datastore_file_vectordir_vsid(vsid_ctx, vector_dir,
							 sizeof(vector_dir),
							 false, false));
		CKINT(acvp_datastore_find_modinfo(datastore,
						  &vsid_ctx->verdict,
						  vector_dir,
						  sizeof(vector_dir)));
	}

out:
	return ret;
}

static int
acvp_datastore_get_vsid_verdict(struct acvp_vsid_ctx *vsid_ctx)
{
	const struct acvp_testid_ctx *testid_ctx;
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	char verdict_file[FILENAME_MAX];
	int ret;

	CKNULL_C_LOG(vsid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");
	testid_ctx = vsid_ctx->testid_ctx;

	CKNULL_C_LOG(testid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	if (acvp_op_get_interrupted())
		return 0;

	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;

	ret = acvp_datastore_file_vectordir_vsid(vsid_ctx, verdict_file,
						 sizeof(verdict_file), false,
						 false);
	if (ret) {
		/* If pathname does not exist, we ignore it. */
		return 0;
	} else {
		CKINT(acvp_datastore_find_verdict(datastore, &vsid_ctx->verdict,
						  verdict_file,
						  sizeof(verdict_file)));
	}

out:
	return ret;
}

static int acvp_datastore_process_vsid(struct acvp_vsid_ctx *vsid_ctx,
				       const char *datastore_base,
				       const char *secure_base,
		int (*cb)(const struct acvp_vsid_ctx *vsid_ctx,
			  const struct acvp_buf *buf))
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	FILE *file;
	struct stat statbuf;
	struct acvp_buf buf;
	time_t now;
	struct tm now_detail;
	uint8_t *resp_buf;
	int fd = -1, ret = 0;
	char resppath[FILENAME_MAX], processedpath[FILENAME_MAX],
	     vectorfile[FILENAME_MAX], expected[FILENAME_MAX], now_buf[30];

	CKNULL_C_LOG(datastore_base, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store base missing\n");
	CKNULL_C_LOG(secure_base, -EINVAL, LOGGER_C_DS_FILE,
		     "Secure data store base missing\n");

	/*
	 * The vsID of 0 is special as it contains status information for the
	 * test session authentication where no vsID exists yet.
	 */
	if (!vsid_ctx->vsid) {
		logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
		       "Skipping special vsID directory without any test data of %s/0\n",
		       datastore_base);
		return 0;
	}

	/* Create path names */
	CKINT(acvp_datastore_file_vectordir_vsid(vsid_ctx, resppath,
						 sizeof(resppath), false,
						 false));
	CKINT(acvp_extend_string(resppath, sizeof(resppath), "/%s",
				 datastore->resultsfile));

	ret = acvp_datastore_file_vectordir_vsid(vsid_ctx, processedpath,
						 sizeof(processedpath), false,
						 true);
	/*
	 * It is permissible to have a non-existing path here, we check it
	 * further down with stat anyway.
	 */
	if (ret && ret != -ENOENT)
		goto out;
	CKINT(acvp_extend_string(processedpath, sizeof(processedpath), "/%s",
				 datastore->processedfile));

	CKINT(acvp_datastore_file_vectordir_vsid(vsid_ctx, vectorfile,
						 sizeof(vectorfile), false,
						 false));
	CKINT(acvp_extend_string(vectorfile, sizeof(vectorfile), "/%s",
				 datastore->vectorfile));

	CKINT(acvp_datastore_file_vectordir_vsid(vsid_ctx, expected,
						 sizeof(expected), false,
						 false));
	CKINT(acvp_extend_string(expected, sizeof(expected), "/%s",
				 datastore->expectedfile));

	logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
	       "Read response from %s and processed file from %s\n",
	       resppath, processedpath);

	/*
	 * If we have an expected result on file, we cannot submit real results
	 * any more - the ACVP server will reject it.
	 */
	if (!stat(expected, &statbuf)) {
		logger_status(LOGGER_C_DS_FILE,
			      "Skipping submission for vsID %u since expected results are present (%s exists)\n",
			      vsid_ctx->vsid, expected);
		logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
		       "Skipping submission for vsID %u since expected results are present (%s exists)\n",
		       vsid_ctx->vsid, expected);
		vsid_ctx->sample_file_present = true;

		return 0;
	}

	/* If there is already a processed file, do a resubmit */
	if (!stat(processedpath, &statbuf)) {
		if (!ctx_opts->resubmit_result) {
			char verdict_file[FILENAME_MAX];

			CKINT(acvp_datastore_file_vectordir_vsid(vsid_ctx,
				verdict_file, sizeof(verdict_file), false,
				false));
			CKINT(acvp_extend_string(verdict_file,
						 sizeof(verdict_file),
						"/%s", datastore->verdictfile));
			if (stat(verdict_file, &statbuf)) {
				logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
				       "Skipping submission for vsID %u since it was submitted already, but fetching verdict\n",
				       vsid_ctx->vsid);

				/*
				 * Tell the callback to only download the
				 * verdict file but not process any results.
				 *
				 * This may happen if we uploaded a result, but
				 * the verdict download got interrupted and
				 * we want to retry to download the result.
				 */
				vsid_ctx->fetch_verdict = true;
				return cb(vsid_ctx, NULL);
			} else {
				CKINT(acvp_datastore_get_vsid_verdict(vsid_ctx));

				/*
				 * If we have a verdict which shows
				 * acvp_verdict_unreceived, then resubmit
				 * as POST operation.
				 */
				if (vsid_ctx->verdict.verdict !=
				    acvp_verdict_unreceived) {
					logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
					       "Skipping submission for vsID %u since it was submitted already (%s exists)\n",
					       vsid_ctx->vsid, processedpath);

					return 0;
				}
			}
		}
	}

	/* Get response file */
	if (stat(resppath, &statbuf)) {
		int errsv = errno;

		if (errsv != ENOENT) {
			ret = -errsv;
			goto out;
		}

		logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
		       "No response file for vsID %u found (%s not found)\n",
		       vsid_ctx->vsid, resppath);

		/*
		 * Download pending vsID requests (do not try to submit
		 * responses).
		 */
		if (stat(vectorfile, &statbuf)) {
			logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
			       "No request file for vsID %u found\n",
			       vsid_ctx->vsid);
			vsid_ctx->vector_file_present = false;
		} else {
			vsid_ctx->vector_file_present = true;
		}

		vsid_ctx->sample_file_present = false;

		CKINT(cb(vsid_ctx, NULL));

		ret = 0;
		goto out;
	} else {
		if (!statbuf.st_size) {
			logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
				"Skipping submission for vsID %u since response file not found (%s empty)\n",
				vsid_ctx->vsid, resppath);
			ret = 0;
			goto out;
		}
		if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
			logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
			       "Skipping directory entry %s which is no regular file\n",
			       resppath);
			ret = 0;
			goto out;
		}

		fd = open(resppath, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			ret = -errno;

			logger(LOGGER_WARN, LOGGER_C_DS_FILE,
			       "Cannot open file %s (%d)\n", resppath, ret);
			goto out;
		}

		resp_buf = mmap(NULL, (size_t)statbuf.st_size, PROT_READ,
				MAP_SHARED, fd, 0);
		if (resp_buf == MAP_FAILED) {
			logger(LOGGER_WARN, LOGGER_C_DS_FILE,
			       "Cannot mmap file %s\n", resppath);
			close(fd);
			ret = -ENOMEM;
			goto out;
		}

		buf.buf = resp_buf;
		buf.len = (uint32_t)statbuf.st_size;

		/* Process response file */
		ret = cb(vsid_ctx, &buf);
		munmap(resp_buf, (size_t)statbuf.st_size);
		close(fd);

		if (ret < 0)
			goto out;

		/* Create processed file */
		now = time(NULL);
		if (now == (time_t)-1) {
			ret = -errno;
			logger(LOGGER_WARN, LOGGER_C_DS_FILE,
				"Cannot obtain local time\n");
			goto out;
		}
		localtime_r(&now, &now_detail);

		snprintf(now_buf, sizeof(now_buf), "%d%.2d%.2d %.2d:%.2d:%.2d",
			 now_detail.tm_year + 1900,
			 now_detail.tm_mon + 1,
			 now_detail.tm_mday,
			 now_detail.tm_hour,
			 now_detail.tm_min,
			 now_detail.tm_sec);

		file = fopen(processedpath, "w");
		CKNULL(file, -errno);
		fwrite(now_buf, 1, strlen(now_buf), file);
		fclose(file);
	}

out:
	return ret;
}

#ifdef ACVP_USE_PTHREAD
static int acvp_datastore_file_find_responses_thread(void *arg)
{
	struct acvp_datastore_thread_ctx *tdata =
				(struct acvp_datastore_thread_ctx *)arg;
	struct acvp_vsid_ctx *vsid_ctx = tdata->vsid_ctx;
	const char *datastore_base = tdata->datastore_base;
	const char *secure_base = tdata->secure_base;
	int (*cb)(const struct acvp_vsid_ctx *vsid_ctx,
		  const struct acvp_buf *buf) = tdata->cb;
	int ret;

	free(tdata);

	thread_set_name(acvp_vsid, vsid_ctx->vsid);

	ret = acvp_datastore_process_vsid(vsid_ctx, datastore_base, secure_base,
					  cb);

	acvp_release_vsid_ctx(vsid_ctx);

	return ret;
}
#endif

/*
 * The function is a safety measure to ensure there is no mismatch between
 * the module definition used to download the test vectors compared to the
 * module definition when uploading the responses and getting the verdict.
 *
 * If there is a mismatch, the caller should refine his search string for
 * the module when uploading the responses (or he messed with the module
 * definition between the vector fetching and the response submission).
 */
static int acvp_def_check(const struct acvp_testid_ctx *testid_ctx,
			  const char *dir)
{
	struct json_object *def_config = NULL;
	int ret;
	char defpath[FILENAME_MAX];

	CKNULL_C_LOG(testid_ctx->def, -EFAULT, LOGGER_C_DS_FILE,
		     "Module definition context missing\n");

	snprintf(defpath, sizeof(defpath), "%s/%s", dir, ACVP_DS_DEF_REFERENCE);

	/* Do not do anyting if we did not find a definition search file */
	def_config = json_object_from_file(defpath);
	if (!def_config)
		return 0;

	CKINT(acvp_match_def(testid_ctx, def_config));

out:
	ACVP_JSON_PUT_NULL(def_config);
	return ret;
}

static int
acvp_datastore_file_find_responses(const struct acvp_testid_ctx *testid_ctx,
	int (*cb)(const struct acvp_vsid_ctx *vsid_ctx,
		  const struct acvp_buf *buf))
{
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	const struct acvp_opts_ctx *opts;
	const struct definition *def;
	struct dirent *dirent;
	DIR *dir = NULL;
	char datastore_base[FILENAME_MAX - 100];
	char base[FILENAME_MAX - 100];
	char secure_base[FILENAME_MAX - 100];
	int ret;

	CKNULL_C_LOG(testid_ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	if (acvp_op_get_interrupted())
		return 0;

	ctx = testid_ctx->ctx;
	datastore = &ctx->datastore;
	opts = &ctx->options;
	def = testid_ctx->def;

	CKNULL_C_LOG(datastore, -EINVAL, LOGGER_C_DS_FILE,
		     "Datastore context missing\n");
	/*
	 * Although not needed in this function, we check for the presence as
	 * later functions may require its presence.
	 */
	CKNULL_C_LOG(def, -EINVAL, LOGGER_C_DS_FILE,
		     "Module definition context missing\n");
	CKNULL_C_LOG(cb, -EINVAL, LOGGER_C_DS_FILE,
		     "Callback function missing\n");

	ret = acvp_datastore_file_vectordir(testid_ctx, datastore_base,
					    sizeof(datastore_base), false,
					    false);
	if (ret == -ENOENT)
		return 0;
	else if (ret)
		return ret;

	ret = acvp_datastore_file_vectordir(testid_ctx, base, sizeof(base),
					    false, false);
	if (ret == -ENOENT)
		return 0;
	else if (ret)
		return ret;

	ret = acvp_datastore_file_vectordir(testid_ctx, secure_base,
					    sizeof(secure_base),
					    true, false);
	if (ret == -ENOENT)
		return 0;
	else if (ret)
		return ret;

	logger(LOGGER_DEBUG, LOGGER_C_DS_FILE, "Read results directory %s\n",
	       datastore_base);

	/*
	 * Update testid_ctx:
	 * In case a specific cipher definition is stored there, use it.
	 *
	 * In case we do not find a match, just disregard the current testID.
	 */
	if (acvp_def_check(testid_ctx, base))
		return 0;

	dir = opendir(datastore_base);
	CKNULL(dir, -errno);

	while ((dirent = readdir(dir)) != NULL) {
		const struct acvp_search_ctx *search = &datastore->search;
		struct acvp_vsid_ctx *vsid_ctx = NULL;
		unsigned long vsid_val;
		unsigned int i, skip = 0;

		if (!strncmp(dirent->d_name, ".", 1))
			continue;

		for (i = 0; i < strlen(dirent->d_name); i++) {
			if (!isdigit(dirent->d_name[i])) {
				skip = 1;
				break;
			}
		}
		if (skip)
			continue;

		logger(LOGGER_VERBOSE, LOGGER_C_DS_FILE,
		       "Process results directory %s\n",
		       dirent->d_name);

		vsid_val = strtoul(dirent->d_name, NULL, 10);
		if (vsid_val == ULONG_MAX) {
			ret = -errno;
			goto out;
		}

		/*
		 * If specific vsID is requested, only return requested vsID.
		 * If there is no vsID search criteria, all vsIDs will be used.
		 */
		if (search->nr_submit_vsid) {
			unsigned int j, found = 0;

			for (j = 0; j < search->nr_submit_vsid; j++) {
				if (search->submit_vsid[i] == vsid_val) {
					found = 1;
					break;
				}
			}

			if (!found) {
				logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
				       "Skipping test results dir %u\n",
				       vsid_val);
				continue;
			}
		}

		vsid_ctx = calloc(1, sizeof(*vsid_ctx));
		CKNULL(vsid_ctx, -ENOMEM);

		vsid_ctx->vsid = (uint32_t)vsid_val;
		vsid_ctx->testid_ctx = testid_ctx;
		if (clock_gettime(CLOCK_REALTIME, &vsid_ctx->start)) {
			ret = -errno;
			acvp_release_vsid_ctx(vsid_ctx);
			goto out;
		}

		ret = acvp_datastore_find_vsid_verdict(vsid_ctx);
		if (ret < 0) {
			acvp_release_vsid_ctx(vsid_ctx);
			goto out;
		}
		if (ret == EEXIST)
			vsid_ctx->verdict_file_present = true;

		/*
		 * If the testid_ctx contains a test verdict retrieval,
		 * we only try to invoke the callback as our invocation
		 * is only intended to retrieve the test verdict.
		 */
		if (testid_ctx->verdict.verdict) {
			ret = cb(vsid_ctx, NULL);
			acvp_release_vsid_ctx(vsid_ctx);

			if (ret < 0)
				goto out;

			continue;
		}

#ifdef ACVP_USE_PTHREAD
		/* Disable threading in DEBUG mode */
		if (opts->threading_disabled) {
			logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
			       "Disable threading support\n");
			ret = acvp_datastore_process_vsid(vsid_ctx,
							  datastore_base,
							  secure_base,
							  cb);
			acvp_release_vsid_ctx(vsid_ctx);
			if (ret)
				goto out;
		} else {
			struct acvp_datastore_thread_ctx *tdata;
			int ret_ancestor;

			tdata = calloc(1, sizeof(*tdata));
			if (!tdata) {
				acvp_release_vsid_ctx(vsid_ctx);
				ret = -ENOMEM;
				goto out;
			}
			tdata->vsid_ctx = vsid_ctx;
			tdata->datastore_base = datastore_base;
			tdata->secure_base = secure_base;
			tdata->cb = cb;
			CKINT(thread_start(
				acvp_datastore_file_find_responses_thread,
				tdata, 1, &ret_ancestor));
			ret |= ret_ancestor;
		}
#else
		ret = acvp_datastore_process_vsid(vsid_ctx, datastore_base,
						  secure_base, cb);
		acvp_release_vsid_ctx(vsid_ctx);
		if (ret)
			goto out;
#endif
	}

	if (ret)
		goto out;

	CKINT(acvp_datastore_find_testid_verdict(testid_ctx));

out:

#ifdef ACVP_USE_PTHREAD
	ret |= thread_wait();
#endif

	if (dir)
		closedir(dir);

	return ret;
}

static int
acvp_datastore_file_find_testsession(const struct definition *def,
				     const struct acvp_ctx *ctx,
				     uint32_t *testids,
				     unsigned int *testid_count)
{
	const struct acvp_datastore_ctx *datastore;
	struct acvp_testid_ctx testid_ctx;
	struct dirent *dirent;
	DIR *dir = NULL;
	char pathname[FILENAME_MAX - 100];
	char base[FILENAME_MAX - 100];
	unsigned int tcount = 0;
	int ret;

	CKNULL_C_LOG(ctx, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");
	CKNULL_C_LOG(def, -EINVAL, LOGGER_C_DS_FILE,
		     "Data store backend exchange info missing\n");

	if (acvp_op_get_interrupted())
		return 0;

	memset(&testid_ctx, 0, sizeof(testid_ctx));
	testid_ctx.def = def;
	testid_ctx.ctx = ctx;

	datastore = &ctx->datastore;

	CKNULL_C_LOG(datastore, -EINVAL, LOGGER_C_DS_FILE,
		     "Datastore context missing\n");

	/* Get reference to test session directory without creating it */
	ret = acvp_datastore_file_testsessiondir(&testid_ctx, pathname,
						 sizeof(pathname), false,
						 false);
	if (ret) {
		*testid_count = 0;

		if (ret == -ENOENT)
			return 0;
		else
			return ret;
	}

	logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
	       "Read test session directory %s\n", pathname);

	dir = opendir(pathname);
	CKNULL(dir, -errno);

	/* Iterate through test session directory and process files */
	while ((tcount < *testid_count) &&
	       (dirent = readdir(dir)) != NULL) {
		const struct acvp_search_ctx *search = &datastore->search;
		unsigned long testid = strtoul(dirent->d_name, NULL, 10);

		if (testid >= UINT_MAX) {
			ret = -errno;
			goto out;
		}

		/* Skip the special purpose dir of zero */
		if (!testid)
			continue;

		/* Fudge the testid_ctx */
		testid_ctx.testid = (uint32_t)testid;

		/*
		 * If specific testID is requested, only return requested
		 * testID. If there is no testID search criteria, all testIDs
		 * will be used.
		 */
		if (search->nr_submit_testid) {
			unsigned int i, found = 0;

			for (i = 0; i < search->nr_submit_testid; i++) {
				if (search->submit_testid[i] == testid ||
				    search->submit_testid[i] == UINT_MAX) {
					found = 1;
					break;
				}
			}

			if (!found) {
				logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
				       "Skipping test session dir %u\n",
				       testid);
				continue;
			}
		}

		/* Search for vsIDs */
		if (search->nr_submit_vsid) {
			struct acvp_vsid_ctx vsid_ctx;
			unsigned int i, found = 0;
			char pathname2[FILENAME_MAX];

			/* Fudge the vsid_ctx */
			memset(&vsid_ctx, 0, sizeof(vsid_ctx));
			vsid_ctx.testid_ctx = &testid_ctx;

			for (i = 0; i < search->nr_submit_vsid; i++) {
				vsid_ctx.vsid = search->submit_vsid[i];

				/* If vsID dir exists, function returns 0 */
				if (!acvp_datastore_file_vectordir_vsid(
					&vsid_ctx, pathname2, sizeof(pathname2),
					false, false)) {
					found = 1;
					break;
				}
			}

			if (!found) {
				logger(LOGGER_DEBUG, LOGGER_C_DS_FILE,
				       "Skipping test session dir %u\n",
				       testid);
				continue;
			}
		}

		/*
		 * Check any potentially existing definition stored in
		 * the secure database with the current module definition.
		 * Skip the current definition if the stored definition does
		 * not match.
		 *
		 * This is necessary if, for example we have one module with
		 * two OE JSON definitions. If you perform a search with
		 * the testid pointing to one of the two OEs, still both
		 * OEs would be returned if this check is not made.
		 */
		ret = acvp_datastore_file_vectordir(&testid_ctx, base,
						    sizeof(base), false,
						    false);
		if (!ret) {
			if (acvp_def_check(&testid_ctx, base))
				continue;
		}
		ret = 0;

		testids[tcount] = (uint32_t)testid;
		tcount++;
	}

	*testid_count = tcount;

out:
	if (dir)
		closedir(dir);
	return ret;
}

static struct acvp_datastore_be acvp_datastore_file = {
	&acvp_datastore_file_find_testsession,
	&acvp_datastore_file_find_responses,
	&acvp_datastore_file_write_vsid,
	&acvp_datastore_file_write_testid,
	&acvp_datastore_file_compare,
	&acvp_datastore_file_write_authtoken,
	&acvp_datastore_file_read_authtoken,
	&acvp_datastore_get_testid_verdict,
	&acvp_datastore_get_vsid_verdict,
	&acvp_datastore_file_rename_version,
	&acvp_datastore_file_rename_name,
};

ACVP_DEFINE_CONSTRUCTOR(acvp_datastore_init)
static void acvp_datastore_init(void)
{
	acvp_register_ds(&acvp_datastore_file);
}
