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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "acvpproxy.h"
#include "base64.h"
#include "bool.h"
#include "credentials.h"
#include "logger.h"
#include "memset_secure.h"
#include "ret_checkers.h"

#define OPT_STR_TOTPLASTGEN "totpLastGen"
#define OPT_STR_TLSKEYFILE "tlsKeyFile"
#define OPT_STR_TLSCERTFILE "tlsCertFile"
#define OPT_STR_TLSCERTKEYCHAIN "tlsCertMacOSKeyChainRef"
#define OPT_STR_TLSKEYPASSCODE "tlsKeyPasscode"
#define OPT_STR_TLSCABUNDLE "tlsCaBundle"
#define OPT_STR_TLSCAKEYCHAIN "tlsCaMacOSKeyChainRef"
#define OPT_STR_TOTPSEEDFILE "totpSeedFile"

/*
 * Pointer to parsed options. This pointer is only to be used by the async
 * callback function of last_gen_cb.
 */
static struct opt_cred *global_cred = NULL;

static int json_find_key(const struct json_object *inobj, const char *name,
			 struct json_object **out, enum json_type type)
{
	if (!json_object_object_get_ex(inobj, name, out)) {
		/*
		 * Use debug level only as optional fields may be searched
		 * for.
		 */
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "JSON field %s does not exist\n", name);
		return -ENOENT;
	}

	if (!json_object_is_type(*out, type)) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "JSON data type %s does not match expected type %s for field %s\n",
		       json_type_to_name(json_object_get_type(*out)),
		       json_type_to_name(type), name);
		return -EINVAL;
	}

	return 0;
}

static int json_get_uint64(struct json_object *obj, const char *name,
			   uint64_t *integer)
{
	struct json_object *o = NULL;
	int64_t tmp;
	int ret = json_find_key(obj, name, &o, json_type_int);

	if (ret)
		return ret;

	tmp = json_object_get_int64(o);

	*integer = (uint64_t)tmp;

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Found integer %s with value %" PRIu64 "\n", name, *integer);

	return 0;
}

static int json_get_string(struct json_object *obj, const char *name,
			   const char **outbuf, bool nodebug)
{
	struct json_object *o = NULL;
	const char *string;
	int ret = json_find_key(obj, name, &o, json_type_string);

	if (ret)
		return ret;

	string = json_object_get_string(o);

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Found string data %s with value %s\n", name,
	       nodebug ? "HIDDEN" : string);

	*outbuf = string;

	return 0;
}

static int read_complete(int fd, char *buf, uint32_t buflen)
{
	ssize_t ret;

	if (buflen > INT_MAX)
		return -EINVAL;

	do {
		ret = read(fd, buf, buflen);
		if (0 < ret) {
			buflen -= (uint32_t)ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno) && buflen);

	if (buflen == 0)
		return 0;
	return -EFAULT;
}

int load_config(struct opt_cred *cred)
{
	struct flock lock;
	int ret;
	int fd;

	global_cred = cred;

	fd = open(global_cred->configfile, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		logger(LOGGER_ERR, LOGGER_C_ANY, "Cannot open config file %s\n",
		       cred->configfile);
		return ret;
	}

	memset(&lock, 0, sizeof(lock));

	/*
	 * Place a write lock on the file. This call will put us to sleep if
	 * there is another lock.
	 */
	fcntl(fd, F_SETLKW, &lock);

	cred->config = json_object_from_fd(fd);

	/* Release the lock. */
	lock.l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, &lock);

	close(fd);

	if (!cred->config) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cannot parse config file %s\n", cred->configfile);
		return -EFAULT;
	}

	/* Allow an empty key file */
	ret = json_get_string(cred->config, OPT_STR_TLSKEYFILE, &cred->tlskey,
			      false);
	if (ret)
		cred->tlskey = NULL;

	/* Allow an empty passcode entry */
	ret = json_get_string(cred->config, OPT_STR_TLSKEYPASSCODE,
			      &cred->tlspasscode, true);
	if (ret)
		cred->tlspasscode = NULL;

	ret = json_get_string(cred->config, OPT_STR_TLSCERTFILE, &cred->tlscert,
			      false);
	if (ret)
		cred->tlscert = NULL;

	ret = json_get_string(cred->config, OPT_STR_TLSCERTKEYCHAIN,
			      &cred->tlscertkeychainref, false);
	if (ret)
		cred->tlscertkeychainref = NULL;
	if (!cred->tlscert && !cred->tlscertkeychainref) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Neither client certificate key file nor macOS keychain reference provided - no authentication credential available\n");
		ret = -EINVAL;
		goto out;
	}

	ret = json_get_string(cred->config, OPT_STR_TLSCABUNDLE,
			      &cred->tlscabundle, false);
	if (ret)
		cred->tlscabundle = NULL;
	ret = json_get_string(cred->config, OPT_STR_TLSCAKEYCHAIN,
			      &cred->tlscakeychainref, false);
	if (ret)
		cred->tlscakeychainref = NULL;

	CKINT(json_get_string(cred->config, OPT_STR_TOTPSEEDFILE,
			      &cred->seedfile, false));

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

static int load_totp_seed(struct opt_cred *cred, char **seed_base64,
			  uint32_t *seed_base64_len)
{
	struct stat statbuf;
	char *seed = NULL;
	uint32_t len = 0;
	int ret;
	int fd = -1;

	if (stat(cred->seedfile, &statbuf)) {
		ret = -errno;
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Error accessing seed file %s (%d)\n", cred->seedfile,
		       ret);
		goto out;
	}

	if (!statbuf.st_size) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "Seed file %s empty\n",
		       cred->seedfile);
		ret = -EINVAL;
		goto out;
	}

	fd = open(cred->seedfile, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cannot open seed file %s (%d)\n", cred->seedfile, ret);
		goto out;
	}

	len = (uint32_t)statbuf.st_size;
	seed = malloc((size_t)statbuf.st_size);
	if (!seed) {
		ret = -ENOMEM;
		goto out;
	}

	CKINT(read_complete(fd, seed, len));

	while (isspace(seed[len - 1]))
		len--;

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "TOTP seed file %s read into memory\n", cred->seedfile);

	*seed_base64 = seed;
	*seed_base64_len = len;
	seed = NULL;

out:
	if (fd >= 0)
		close(fd);

	if (seed) {
		memset_secure(seed, 0, len);
		free(seed);
	}
	return ret;
}

static int get_totp_seed(struct opt_cred *cred, uint8_t **seed,
			 size_t *seed_len, uint64_t *totp_last_gen)
{
	int ret;
	char *seed_base64 = NULL;
	uint32_t seed_base64_len = 0;

	CKINT(load_totp_seed(cred, &seed_base64, &seed_base64_len));

	CKINT_LOG(base64_decode(seed_base64, seed_base64_len, seed, seed_len),
		  "Base64 decoding failed\n");

	ret = json_get_uint64(cred->config, OPT_STR_TOTPLASTGEN, totp_last_gen);
	if (ret)
		*totp_last_gen = 0;
	ret = 0;

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "TOTP base64 seed converted into binary and applied\n");

out:
	/* securely dispose of the seed */
	if (seed_base64) {
		memset_secure(seed_base64, 0, seed_base64_len);
		free(seed_base64);
	}
	return ret;
}

int set_totp_seed(struct opt_cred *cred, const bool official_testing,
		  const bool enable_net)
{
	int ret;
	uint8_t *seed = NULL;
	size_t seed_len = 0;
	uint64_t totp_last_gen = 0;

	if (!enable_net) {
		return acvp_init(NULL, 0, 0, false, NULL);
	}

	CKINT(get_totp_seed(cred, &seed, &seed_len, &totp_last_gen));

	CKINT(acvp_init(seed, seed_len, (time_t)totp_last_gen, official_testing,
			&last_gen_cb));

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "TOTP base64 seed converted into binary and applied\n");

out:
	if (seed) {
		memset_secure(seed, 0, seed_len);
		free(seed);
	}
	return ret;
}

void cred_free(struct opt_cred *cred)
{
	if (cred->configfile)
		free(cred->configfile);
	json_object_put(cred->config);
}

void last_gen_cb(const time_t now)
{
	struct json_object *totp_val;
	struct flock lock;
	int ret;
	int fd;

	if (!global_cred || !global_cred->configfile)
		return;

	ret = json_find_key(global_cred->config, OPT_STR_TOTPLASTGEN, &totp_val,
			    json_type_int);
	if (ret) {
		json_object_object_add(global_cred->config, OPT_STR_TOTPLASTGEN,
				       json_object_new_int64(now));
	} else {
		json_object_set_int64(totp_val, now);
	}

	fd = open(global_cred->configfile, O_WRONLY | O_TRUNC);
	if (fd < 0)
		return;

	memset(&lock, 0, sizeof(lock));

	/*
	 * Place a write lock on the file. This call will put us to sleep if
	 * there is another lock.
	 */
	fcntl(fd, F_SETLKW, &lock);

	json_object_to_fd(fd, global_cred->config,
			  JSON_C_TO_STRING_PRETTY |
				  JSON_C_TO_STRING_NOSLASHESCAPE);

	/* Release the lock. */
	lock.l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, &lock);

	close(fd);

	return;
}
