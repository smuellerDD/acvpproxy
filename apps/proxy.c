/* ACVP Proxy application
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
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <json-c/json.h>

#include "acvpproxy.h"
#include "base64.h"
#include "logger.h"
#include "ret_checkers.h"
#include "term_colors.h"

#include "macos.h"

#define OPT_STR_TOTPLASTGEN		"totpLastGen"
#define OPT_STR_TLSKEYFILE		"tlsKeyFile"
#define OPT_STR_TLSCERTFILE		"tlsCertFile"
#define OPT_STR_TLSCERTKEYCHAIN		"tlsCertMacOSKeyChainRef"
#define OPT_STR_TLSKEYPASSCODE		"tlsKeyPasscode"
#define OPT_STR_TLSCABUNDLE		"tlsCaBundle"
#define OPT_STR_TLSCAKEYCHAIN		"tlsCaMacOSKeyChainRef"
#define OPT_STR_TOTPSEEDFILE		"totpSeedFile"

#define OPT_CIPHER_OPTIONS_MAX		512

struct opt_data {
	struct acvp_search_ctx search;
	struct acvp_opts_ctx acvp_ctx_options;
	struct acvp_rename_ctx rename_ctx;
	char *specific_modversion;

	char *configfile;
	struct json_object *config;
	const char *tlskey;
	const char *tlspasscode;
	const char *tlscert;
	const char *tlscertkeychainref;
	const char *tlscabundle;
	const char *tlscakeychainref;
	const char *seedfile;
	char *basedir;
	char *secure_basedir;
	char *definition_basedir;
	char *cipher_options_file;
	char *cipher_options_algo[OPT_CIPHER_OPTIONS_MAX];
	size_t cipher_options_algo_idx;
	bool cipher_list;

	bool rename;
	bool request;
	bool publish;
	bool list_available_ids;
	bool list_pending_request_ids;
	bool list_pending_request_ids_sparse;
	bool list_verdicts;
	bool list_certificates;
	bool list_certificates_detailed;
	bool list_cipher_options;
	bool list_cipher_options_deps;
	bool dump_register;
	bool request_sample;
	bool official_testing;
};

/*
 * Pointer to parsed options. This pointer is only to be used by the async
 * callback function of last_gen_cb.
 */
static struct opt_data *global_opts = NULL;

static int json_find_key(struct json_object *inobj, const char *name,
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

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Found integer %s with value %lu\n",
	       name, *integer);

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

static int load_config(struct opt_data *opts)
{
	struct flock lock;
	int ret;
	int fd;

	fd = open(global_opts->configfile, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		logger(LOGGER_ERR, LOGGER_C_ANY, "Cannot open config file %s\n",
		       opts->configfile);
		return ret;
	}

	memset (&lock, 0, sizeof(lock));

	/*
	 * Place a write lock on the file. This call will put us to sleep if
	 * there is another lock.
	 */
	fcntl(fd, F_SETLKW, &lock);

	opts->config = json_object_from_fd(fd);

	/* Release the lock. */
	lock.l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, &lock);

	close(fd);

	if (!opts->config) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cannot parse config file %s\n", opts->configfile);
		return -EFAULT;
	}

	/* Allow an empty key file */
	ret = json_get_string(opts->config, OPT_STR_TLSKEYFILE, &opts->tlskey,
			      false);
	if (ret)
		opts->tlskey = NULL;

	/* Allow an empty passcode entry */
	ret = json_get_string(opts->config, OPT_STR_TLSKEYPASSCODE,
			      &opts->tlspasscode, true);
	if (ret)
		opts->tlspasscode = NULL;

	ret = json_get_string(opts->config, OPT_STR_TLSCERTFILE,
			      &opts->tlscert, false);
	if (ret)
		opts->tlscert = NULL;

	ret = json_get_string(opts->config, OPT_STR_TLSCERTKEYCHAIN,
			      &opts->tlscertkeychainref, false);
	if (ret)
		opts->tlscertkeychainref = NULL;
	if (!opts->tlscert && !opts->tlscertkeychainref) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Neither client certificate key file nor macOS keychain reference provided - no authentication credential available\n");
		ret = -EINVAL;
		goto out;
	}

	ret = json_get_string(opts->config, OPT_STR_TLSCABUNDLE,
			      &opts->tlscabundle, false);
	if (ret)
		opts->tlscabundle = NULL;
	ret = json_get_string(opts->config, OPT_STR_TLSCAKEYCHAIN,
			      &opts->tlscakeychainref, false);
	if (ret)
		opts->tlscakeychainref = NULL;

	CKINT(json_get_string(opts->config, OPT_STR_TOTPSEEDFILE,
			      &opts->seedfile, false));

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

static int load_totp_seed(struct opt_data *opts, char **seed_base64,
			  uint32_t *seed_base64_len)
{
	struct stat statbuf;
	char *seed;
	uint32_t len;
	int ret;
	int fd = -1;

	if (stat(opts->seedfile, &statbuf)) {
		ret = -errno;
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Error accessing seed file %s (%d)\n", opts->seedfile,
		       ret);
		goto out;
	}

	if (!statbuf.st_size) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "Seed file %s empty\n",
		       opts->seedfile);
		ret = -EINVAL;
		goto out;
	}

	fd = open(opts->seedfile, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cannot open seed file %s (%d)\n", opts->seedfile, ret);
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
	       "TOTP seed file %s read into memory\n", opts->seedfile);

	*seed_base64 = seed;
	*seed_base64_len = len;

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

static void usage(void)
{
	char version[200];

	acvp_versionstring(version, sizeof(version));

	fprintf(stderr, "\nACVP Test Vector And Test Verdict Proxy\n");
	fprintf(stderr, "\nACVP proxy library version: %s\n\n", version);
	fprintf(stderr, "Register module and fetch test vectors:\n");
	fprintf(stderr, "  acvp-proxy [-mrnepf MODULE_SEARCH_CRITERIA] --request\n\n");
	fprintf(stderr, "Continue download interrupted fetch of test vectors:\n");
	fprintf(stderr, "  acvp-proxy [-mrnepf MODULE_SEARCH_CRITERIA] --request [--testid|--vsid ID]\n\n");
	fprintf(stderr, "Upload test responses and (continue to) fetch verdict:\n");
	fprintf(stderr, "  acvp-proxy [-mrnepf MODULE_SEARCH_CRITERIA] [--testid|--vsid ID]\n\n");

	//TODO issue #518: remove caveat once issue is cleared
	fprintf(stderr, "Download samples after vectors are obtained (CURRENTLY NOT SUPPORTED BY ACVP SERVER):\n");
	fprintf(stderr, "  acvp-proxy [-mrnepf MODULE_SEARCH_CRITERIA] --request [--testid|--vsid ID] --sample\n\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\tModule search criteria limiting the scope of processed modules:\n");
	fprintf(stderr, "\t-m --module <NAME>\t\tDefinition search criteria: Name of\n");
	fprintf(stderr, "\t\t\t\t\tcrypto module to process\n");
	fprintf(stderr, "\t-r --releaseversion <VERSION>\tDefinition search criteria: Version\n");
	fprintf(stderr, "\t\t\t\t\tof crypto module to process\n");
	fprintf(stderr, "\t-n --vendorname <NAME>\t\tDefinition search criteria: Name of\n");
	fprintf(stderr, "\t\t\t\t\tvendor of crypto module to process\n");
	fprintf(stderr, "\t-e --execenv <NAME>\t\tDefinition search criteria: Name of \n");
	fprintf(stderr, "\t\t\t\t\texecution environment of crypto module\n");
	fprintf(stderr, "\t\t\t\t\tto process\n");
	fprintf(stderr, "\t-p --processor <NAME>\t\tDefinition search criteria: Name of \n");
	fprintf(stderr, "\t\t\t\t\tprocessor executing crypto module\n");
	fprintf(stderr, "\t-f --fuzzy\t\t\tPerform a fuzzy search for all search \n");
	fprintf(stderr, "\t\t\t\t\tcriteria (perform a substring search)\n");
	fprintf(stderr, "\n\tNote: The search critera allow narrowing the processed module\n");
	fprintf(stderr, "\tdefinitions found with the list operation. The less search criteria are\n");
	fprintf(stderr, "\tprovided, the broader the scope is. If no search critera are provided,\n");
	fprintf(stderr, "\tall module definitions are in scope. For example, using --request with\n");
	fprintf(stderr, "\tno search criteria implies that test vectors for all module\n");
	fprintf(stderr, "\timplementations known to the library are requested.\n\n");
	fprintf(stderr, "\tNote 2: Prepending the search strings with \"f:\" requests a fuzzy search\n");
	fprintf(stderr, "\tfor only that particular search criteria.\n\n");

	fprintf(stderr, "\t-c --config\t\t\tConfiguration file\n");
	fprintf(stderr, "\t-l --list\t\t\tList supported crypto modules\n");
	fprintf(stderr, "\t-u --unregistered\t\tList unregistered crypto definitions\n");
	fprintf(stderr, "\t   --modversion <VERSION>\tSpecific module version to send to ACVP\n");
	fprintf(stderr, "\t   --vsid <VSID>\t\tSubmit response for given vsID\n");
	fprintf(stderr, "\t\t\t\t\tOption can be specified up to %d times\n",
		MAX_SUBMIT_ID);
	fprintf(stderr, "\t   --testid <TESTID>\t\tSubmit response for given testID\n");
	fprintf(stderr, "\t\t\t\t\t(use -1 to download all pending testIDs)\n");
	fprintf(stderr, "\t\t\t\t\tOption can be specified up to %d times\n",
		MAX_SUBMIT_ID);
	fprintf(stderr, "\t   --request\t\t\tRequest new test vector set\n");
	fprintf(stderr, "\n\tNote: If the caller provides --testid or --vsid together with\n");
	fprintf(stderr, "\t--request, the application assumes that pending vector sets shall\n");
	fprintf(stderr, "\tbe downloaded again (e.g. in case prior download attempts failed).\n\n");
	fprintf(stderr, "\t   --publish\t\t\tPublish test verdicts\n");
	fprintf(stderr, "\n\tNote: You can use --testid or --vsid together with\n");
	fprintf(stderr, "\t--publish to limit the scope.\n\n");

	fprintf(stderr, "\t   --dump-register\t\tDump register JSON request to stdout\n");
	fprintf(stderr, "\t   --sample\t\t\tRequest a test sample with expected\n");
	fprintf(stderr, "\t\t\t\t\tresults\n");
	fprintf(stderr, "\t-d --definitions\t\tDirectory holding the module definitions\n");
	fprintf(stderr, "\t\t\t\t\tfor one specific module\n");
	fprintf(stderr, "\t   --official\t\t\tPerform an official testing to get\n");
	fprintf(stderr, "\t\t\t\t\tcertificates (use official NIST servers)\n");
	fprintf(stderr, "\t-b --basedir\t\t\tBase directory for test data\n");
	fprintf(stderr, "\t-s --secure-basedir\t\tBase directory for sensitive data\n");
	fprintf(stderr, "\t   --definition-basedir\t\tBase directory for module definition\n\n");

	fprintf(stderr, "\t   --resubmit-result\t\tIn case test results were already\n");
	fprintf(stderr, "\t\t\t\t\tsubmitted for a vsID, resubmit the\n");
	fprintf(stderr, "\t\t\t\t\tcurrent results on file to update the\n");
	fprintf(stderr, "\t\t\t\t\tresults on the ACVP server\n\n");

	fprintf(stderr, "\t   --delete-test\t\tDelete all vsIds in scope which\n");
	fprintf(stderr, "\t\t\t\t\tare part of the registration - this\n");
	fprintf(stderr, "\t\t\t\t\toption is only applicable during\n");
	fprintf(stderr, "\t\t\t\t\tsubmitting responses to the ACVP server\n\n");

	fprintf(stderr, "\tUpdate ACVP database with content from JSON configuration files:\n");
	fprintf(stderr, "\t   --nopublish-prereqs\t\tRemove prerequisites from publication\n");
	fprintf(stderr, "\t\t\t\t\trequest\n");
	fprintf(stderr, "\t   --register-definition\tRegister pending definitions with ACVP\n");
	fprintf(stderr, "\t   --delete-definition <TYPE>\tDelete definition at ACVP server\n");
	fprintf(stderr, "\t   --update-definition <TYPE>\tUpdate definition at ACVP server\n");
	fprintf(stderr, "\t\t\t\t\tTYPE: [oe|vendor|module|person|force]\n");
	fprintf(stderr, "\t\t\t\t\tNote: Force implies that even when no\n");
	fprintf(stderr, "\t\t\t\t\t      consistency is established between\n");
	fprintf(stderr, "\t\t\t\t\t      the ACVP server and the local\n");
	fprintf(stderr, "\t\t\t\t\t      definition selected with the TYPE,\n");
	fprintf(stderr, "\t\t\t\t\t      it is deleted from the ACVP\n");
	fprintf(stderr, "\t\t\t\t\t      server.\n\n");

	fprintf(stderr, "\tList of IDs and verdicts:\n");
	fprintf(stderr, "\t   --list-request-ids\t\tList all pending request IDs\n");
	fprintf(stderr, "\t   --list-request-ids-sparse\tList all pending request IDs\n");
	fprintf(stderr, "\t\t\t\t\twithout duplicates\n");
	fprintf(stderr, "\t   --list-available-ids\t\tList all available IDs\n");
	fprintf(stderr, "\t   --list-verdicts\t\tList all verdicts\n\n");
	fprintf(stderr, "\t   --list-certificates\t\tList all certificates\n");
	fprintf(stderr, "\t   --list-cert-details\t\tList all certificate details for\n");
	fprintf(stderr, "\t\t\t\t\tTE.01.12.01\n");
	fprintf(stderr, "\t   --list-cipher-options\tList all cipher options\n");
	fprintf(stderr, "\t   --list-cipher-options-deps\tList all cipher options with\n");
	fprintf(stderr, "\t\t\t\t\tcipher dependencies\n\n");

	fprintf(stderr, "\tGathering cipher definitions from ACVP server:\n");
	fprintf(stderr, "\t   --cipher-list\t\tList all ciphers supported by ACVP\n");
	fprintf(stderr, "\t\t\t\t\tserver\n");
	fprintf(stderr, "\t   --cipher-options <DIR>\tGet cipher options from ACVP server\n");
	fprintf(stderr, "\t\t\t\t\tand store them in <DIR>\n");
	fprintf(stderr, "\t   --cipher-algo <ALGO>\t\tGet cipher options particular cipher\n\n");

	fprintf(stderr, "\tAuxiliary options:\n");
	fprintf(stderr, "\t   --proxy-extension <SO-FILE>\tShared library of ACVP Proxy extension\n");
	fprintf(stderr, "\t\t\t\t\tZero or more extensions can be provided.\n");
	fprintf(stderr, "\t   --proxy-extension-dir <DIR>\tDirectory with ACVP Proxy extensions\n");
	fprintf(stderr, "\t   --rename-version <NEW>\tRename version of definition\n");
	fprintf(stderr, "\t\t\t\t\t(moduleVersion)\n");
	fprintf(stderr, "\t   --rename-name <NEW>\t\tRename name of definition (moduleName)\n");
	fprintf(stderr, "\t   --rename-oename <NEW>\tRename OE name of definition (oeEnvName)\n");
	fprintf(stderr, "\t   --rename-procname <NEW>\tRename processor name of definition \n");
	fprintf(stderr, "\t\t\t\t\t(procName)\n");
	fprintf(stderr, "\t   --rename-procseries <NEW>\tRename processor series of definition \n");
	fprintf(stderr, "\t\t\t\t\t(procSeries)\n");
	fprintf(stderr, "\t   --rename-procfamily <NEW>\tRename processor family of definition \n");
	fprintf(stderr, "\t\t\t\t\t(procFamily)\n");
	fprintf(stderr, "\t   --register-only\t\tOnly register tests without downloading\n");
	fprintf(stderr, "\t\t\t\t\ttest vectors\n");
	fprintf(stderr, "\t-v --verbose\t\t\tVerbose logging, multiple options\n");
	fprintf(stderr, "\t\t\t\t\tincrease verbosity\n");
	fprintf(stderr, "\t\t\t\t\tNote: In debug mode (3 or more -v),\n");
	fprintf(stderr, "\t\t\t\t\t      threading is disabled.\n");
	fprintf(stderr, "\t   --logger-class <NUM>\t\tLimit logging to given class\n");
	fprintf(stderr, "\t\t\t\t\t(-1 lists all logging classes)\n");
	fprintf(stderr, "\t   --logfile <FILE>\t\tFile to write logs to\n");
	fprintf(stderr, "\t-q --quiet\t\t\tNo output - quiet operation\n");
	fprintf(stderr, "\t   --version\t\t\tVersion of ACVP proxy\n");
	fprintf(stderr, "\t   --version-numeric\t\tNumeric version of ACVP proxy\n");
	fprintf(stderr, "\t-h --help\t\t\tPrint this help information\n");
}

static void free_opts(struct opt_data *opts)
{
	struct acvp_search_ctx *search = &opts->search;
	size_t i;

	if (search->modulename)
		free(search->modulename);
	if (search->vendorname)
		free(search->vendorname);
	if (search->moduleversion)
		free(search->moduleversion);
	if (search->execenv)
		free(search->execenv);
	if (search->processor)
		free(search->processor);
	if (opts->specific_modversion)
		free(opts->specific_modversion);
	if (opts->configfile)
		free(opts->configfile);
	if (opts->basedir)
		free(opts->basedir);
	if (opts->secure_basedir)
		free(opts->secure_basedir);
	if (opts->definition_basedir)
		free(opts->definition_basedir);
	if (opts->cipher_options_file)
		free(opts->cipher_options_file);
	for (i = 0; i < opts->cipher_options_algo_idx; i++)
		free(opts->cipher_options_algo[i]);
	json_object_put(opts->config);
}

static int duplicate_string(char **dst, const char *src)
{
	if (*dst)
		free(*dst);
	if (src) {
		*dst = strdup(src);
		if (!(*dst)) {
			logger(LOGGER_ERR, LOGGER_C_ANY, "Out of memory\n");
			return -ENOMEM;
		}
	} else {
		*dst = NULL;
	}

	return 0;
}

static bool ask_yes(const char *question)
{
	unsigned char answer;

	fprintf_red(stdout, "%s (Y/N)? ", question);

	while (1) {
		answer = (unsigned char)fgetc(stdin);

		switch (answer) {
		case 'y':
		case 'Y':
		case 'j':
		case 'J':
			return true;
		case 'n':
		case 'N':
			return false;
		default:
			if (answer < 127 && answer > 31)
				fprintf_red(stdout, "%s (Y/N)? ", question);
			break;
		}
	}

	return false;
}

static int convert_update_delete_type(const char *string, unsigned int *option)
{
	if (!strncmp(string, "oe", 2)) {
		*option |= ACVP_OPTS_DELUP_OE;
	} else if (!strncmp(string, "vendor", 6)) {
		*option |= ACVP_OPTS_DELUP_VENDOR;
	} else if (!strncmp(string, "person", 6)) {
		*option |= ACVP_OPTS_DELUP_PERSON;
	} else if (!strncmp(string, "module", 6)) {
		*option |= ACVP_OPTS_DELUP_MODULE;
	} else if (!strncmp(string, "force", 5)) {
		*option |= ACVP_OPTS_DELUP_FORCE;
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		"Unknown delete type %s\n", string);
		return -EINVAL;
	}

	return 0;
}

static int parse_fuzzy_flag(bool *fuzzy_search_flag, char **dst,
			    const char *src)
{
	int ret;
	char *fuzzing_request;

	if (!src) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Empty string for fuzzy search provided\n");
		return -EINVAL;
	}

	fuzzing_request = strstr(src, "f:");

	/*
	 * Only honor the fuzzing request string if placed at the beginning
	 * of the string.
	 */
	if (fuzzing_request && fuzzing_request == src) {
		*fuzzy_search_flag = true;
		src += 2;
	}

	/*
	 * In case no fuzzy search flag is provided, we do NOT set the
	 * *fuzzy_search_flag to false, because the caller may have provided
	 * the -f command line option.
	 */

	CKINT(duplicate_string(dst, src));

out:
	return ret;
}

static int parse_opts(int argc, char *argv[], struct opt_data *opts)
{
	struct acvp_search_ctx *search = &opts->search;
	struct acvp_rename_ctx *rename = &opts->rename_ctx;
	int c = 0, ret;
	char version[200] = { 0 };
	unsigned long val = 0;
	long lval;
	unsigned int dolist = 0, listunregistered = 0, modconf_loaded = 0;
	bool logger_force_threading = false;

	memset(opts, 0, sizeof(*opts));

	while (1) {
		int opt_index = 0;
		static struct option options[] = {
			{"verbose",		no_argument,		0, 'v'},
			{"logger-class",	required_argument,	0, 0},
			{"logfile",		required_argument,	0, 0},
			{"quiet",		no_argument,		0, 'q'},
			{"version",		no_argument,		0, 0},
			{"version-numeric",	no_argument,		0, 0},
			{"help",		no_argument,		0, 'h'},

			{"module",		required_argument,	0, 'm'},
			{"vendorname",		required_argument,	0, 'n'},
			{"execenv",		required_argument,	0, 'e'},
			{"releaseversion",	required_argument,	0, 'r'},
			{"processor",		required_argument,	0, 'p'},
			{"fuzzy",		required_argument,	0, 'f'},

			{"list",		no_argument,		0, 'l'},
			{"unregistered",	no_argument,		0, 'u'},
			{"modversion",		required_argument,	0, 0},
			{"vsid",		required_argument,	0, 0},
			{"testid",		required_argument,	0, 0},
			{"request",		no_argument,		0, 0},
			{"publish",		no_argument,		0, 0},
			{"dump-register", 	no_argument, 		0, 0},
			{"sample",	 	no_argument, 		0, 0},
			{"config",	 	required_argument,	0, 'c'},
			{"definitions", 	required_argument,	0, 'd'},

			{"official",	 	no_argument, 		0, 'o'},
			{"basedir",	 	required_argument,	0, 'b'},
			{"secure-basedir",	required_argument,	0, 's'},
			{"definition-basedir",	required_argument,	0, 0},

			{"resubmit-result",	no_argument,		0, 0},
			{"delete-test",		no_argument,		0, 0},
			{"register-definition",	no_argument,		0, 0},
			{"delete-definition",	required_argument,	0, 0},
			{"update-definition",	required_argument,	0, 0},
			{"nopublish-prereqs",	required_argument,	0, 0},

			{"list-request-ids",	no_argument,		0, 0},
			{"list-request-ids-sparse",no_argument,		0, 0},
			{"list-available-ids",	no_argument,		0, 0},
			{"list-verdicts",	no_argument,		0, 0},
			{"list-certificates",	no_argument,		0, 0},
			{"list-cert-details",	no_argument,		0, 0},
			{"list-cipher-options",	no_argument,		0, 0},
			{"list-cipher-options-deps",no_argument,	0, 0},

			{"cipher-options",	required_argument,	0, 0},
			{"cipher-algo",		required_argument,	0, 0},
			{"cipher-list",		no_argument,		0, 0},

			{"proxy-extension",	required_argument,	0, 0},
			{"proxy-extension-dir",	required_argument,	0, 0},
			{"rename-version",	required_argument,	0, 0},
			{"rename-name",		required_argument,	0, 0},
			{"rename-oename",	required_argument,	0, 0},
			{"rename-procname",	required_argument,	0, 0},
			{"rename-procseries",	required_argument,	0, 0},
			{"rename-procfamily",	required_argument,	0, 0},

			{"register-only",	no_argument,		0, 0},

			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "m:n:e:r:p:fluc:d:ob:s:vqh", options,
				&opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* verbose */
				logger_inc_verbosity();
				if (logger_get_verbosity(LOGGER_C_ANY) >=
				    LOGGER_DEBUG && !logger_force_threading)
					opts->acvp_ctx_options.threading_disabled = true;
				break;
			case 1:
				/* logger-class */
				lval = strtol(optarg, NULL, 10);
				if (lval == LONG_MAX) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "undefined logging class value\n");
					usage();
					ret = -EINVAL;
					goto out;
				}
				if (lval < 0) {
					logger_get_class(0);
					ret = 0;
					goto out;
				}
				ret = logger_set_class((uint32_t)lval);
				if (ret) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "Failed to set logger class %lu\n", val);
					goto out;
				}
				break;
			case 2:
				/* logfile */
				CKINT(logger_set_file(optarg));
				logger_force_threading = true;
				opts->acvp_ctx_options.threading_disabled = false;
				break;
			case 3:
				/* quiet */
				logger_set_verbosity(LOGGER_NONE);
				break;
			case 4:
				/* version */
				acvp_versionstring(version, sizeof(version));
				fprintf(stderr, "Version %s\n", version);
				ret = 0;
				goto out;
				break;
			case 5:
				/* version-numeric */
				fprintf(stderr, "%u\n",
					acvp_versionstring_numeric());
				ret = 0;
				goto out;
				break;
			case 6:
				/* help */
				usage();
				ret = 0;
				goto out;
				break;

			case 7:
				/* module */
				CKINT(parse_fuzzy_flag(
					&search->modulename_fuzzy_search,
					&search->modulename, optarg));
				break;
			case 8:
				/* vendorname */
				CKINT(parse_fuzzy_flag(
					&search->vendorname_fuzzy_search,
					&search->vendorname, optarg));
				break;
			case 9:
				/* execenv */
				CKINT(parse_fuzzy_flag(
					&search->execenv_fuzzy_search,
					&search->execenv, optarg));
				break;
			case 10:
				/* releaseversion */
				CKINT(parse_fuzzy_flag(
					&search->moduleversion_fuzzy_search,
					&search->moduleversion, optarg));
				break;
			case 11:
				/* processor */
				CKINT(parse_fuzzy_flag(
					&search->processor_fuzzy_search,
					&search->processor, optarg));
				break;
			case 12:
				/* fuzzy */
				search->modulename_fuzzy_search = true;
				search->moduleversion_fuzzy_search = true;
				search->vendorname_fuzzy_search = true;
				search->execenv_fuzzy_search = true;
				search->processor_fuzzy_search = true;
				break;

			case 13:
				/* list */
				dolist = 1;
				break;
			case 14:
				/* unregistered */
				listunregistered = 1;
				break;
			case 15:
				/* modversion */
				CKINT(duplicate_string(&opts->specific_modversion,
						       optarg));
				break;
			case 16:
				/* vsid */
				if (search->nr_submit_vsid >= MAX_SUBMIT_ID) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "%u --submit options are allowed at maximum\n",
					       MAX_SUBMIT_ID);
					ret = -EINVAL;
					goto out;
				}
				lval = strtol(optarg, NULL, 10);
				if (lval == UINT_MAX || lval < -2) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "vsID too big\n");
					usage();
					ret = -EINVAL;
					goto out;
				}
				/* Download all pending testIDs */
				if (lval == -1)
					search->submit_vsid[search->nr_submit_vsid++] = UINT_MAX;
				else
					search->submit_vsid[search->nr_submit_vsid++] = (unsigned int)lval;
				break;
			case 17:
				/* testid */
				if (search->nr_submit_testid >= MAX_SUBMIT_ID) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "%u --session options are allowed at maximum\n",
					       MAX_SUBMIT_ID);
					ret = -EINVAL;
					goto out;
				}
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "testID too big\n");
					usage();
					ret = -EINVAL;
					goto out;
				}
				search->submit_testid[search->nr_submit_testid++] = (unsigned int)val;
				break;
			case 18:
				/* request */
				opts->request = true;
				break;
			case 19:
				/* publish */
				opts->publish = true;
				break;

			case 20:
				/* dump-register */
				opts->dump_register = true;
				break;
			case 21:
				/* sample */
				opts->request_sample = true;
				break;
			case 22:
				/* config */
				CKINT(duplicate_string(&opts->configfile,
						       optarg));
				break;
			case 23:
				/* definitions */
				CKINT(acvp_def_config(optarg));
				modconf_loaded = 1;
				break;

			case 24:
				/* official */
				opts->official_testing = true;
				break;
			case 25:
				/* basedir */
				CKINT(duplicate_string(&opts->basedir, optarg));
				break;
			case 26:
				/* secure-basedir */
				CKINT(duplicate_string(&opts->secure_basedir,
						       optarg));
				break;
			case 27:
				/* definition-basedir */
				CKINT(duplicate_string(&opts->definition_basedir,
						       optarg));
				break;

			case 28:
				/* resubmit-result */
				opts->acvp_ctx_options.resubmit_result = true;
				break;
			case 29:
				/* delete-test */
				opts->acvp_ctx_options.delete_vsid = true;
				break;
			case 30:
				/* register-definition */
				opts->acvp_ctx_options.register_new_module = true;
				opts->acvp_ctx_options.register_new_vendor = true;
				opts->acvp_ctx_options.register_new_oe = true;
				break;
			case 31:
				/* delete-definition */
				CKINT(convert_update_delete_type(optarg,
				      &opts->acvp_ctx_options.delete_db_entry));
				/* This operation must use the publish path */
				opts->publish = true;
				break;
			case 32:
				/* update-definition */
				CKINT(convert_update_delete_type(optarg,
				  &opts->acvp_ctx_options.update_db_entry));
				/* This operation must use the publish path */
				opts->publish = true;
				break;
			case 33:
				/* nopublish-prereqs */
				opts->acvp_ctx_options.no_publish_prereqs = true;
				break;

			case 34:
				/* list-request-ids */
				opts->list_pending_request_ids = true;
				opts->acvp_ctx_options.threading_disabled = true;
				break;
			case 35:
				/* list-request-ids-sparse */
				opts->list_pending_request_ids_sparse = true;
				opts->acvp_ctx_options.threading_disabled = true;
				break;
			case 36:
				/* list-available-ids */
				opts->list_available_ids = true;
				opts->acvp_ctx_options.threading_disabled = true;
				break;
			case 37:
				/* list-verdicts */
				opts->list_verdicts = true;
				opts->acvp_ctx_options.threading_disabled = true;
				break;
			case 38:
				/* list-certificates */
				opts->list_certificates = true;
				opts->acvp_ctx_options.threading_disabled = true;
				break;
			case 39:
				/* list-cert-details */
				opts->list_certificates_detailed = true;
				opts->acvp_ctx_options.threading_disabled = true;
				break;
			case 40:
				/* list-cipher-options */
				opts->list_cipher_options = true;
				opts->acvp_ctx_options.threading_disabled = true;
				break;
			case 41:
				/* list-cipher-options-deps */
				opts->list_cipher_options_deps = true;
				opts->acvp_ctx_options.threading_disabled = true;
				break;

			case 42:
				/* cipher-options */
				CKINT(duplicate_string(&opts->cipher_options_file,
						       optarg));
				break;
			case 43:
				/* cipher-algo */
				CKINT(duplicate_string(&opts->cipher_options_algo[opts->cipher_options_algo_idx],
						       optarg));
				opts->cipher_options_algo_idx++;
				if (opts->cipher_options_algo_idx >=
				    OPT_CIPHER_OPTIONS_MAX) {
					ret = -EOVERFLOW;
					goto out;
				}
				break;
			case 44:
				/* cipher-list */
				opts->cipher_list = true;
				break;

			case 45:
				/* proxy-extension */
				CKINT(acvp_load_extension(optarg));
				break;
			case 46:
				/* proxy-extension-dir */
				CKINT(acvp_load_extension_directory(optarg));
				break;
			case 47:
				/* rename-version */
				rename->moduleversion_new = optarg;
				opts->acvp_ctx_options.threading_disabled = true;
				opts->rename = true;
				break;
			case 48:
				/* rename-name */
				rename->modulename_new = optarg;
				opts->acvp_ctx_options.threading_disabled = true;
				opts->rename = true;
				break;
			case 49:
				/* rename-oename */
				rename->oe_env_name_new = optarg;
				opts->acvp_ctx_options.threading_disabled = true;
				opts->rename = true;
				break;
			case 50:
				/* rename-procname */
				rename->proc_name_new = optarg;
				opts->acvp_ctx_options.threading_disabled = true;
				opts->rename = true;
				break;
			case 51:
				/* rename-procseries */
				rename->proc_series_new = optarg;
				opts->acvp_ctx_options.threading_disabled = true;
				opts->rename = true;
				break;
			case 52:
				/* rename-procfamily */
				rename->proc_family_new = optarg;
				opts->acvp_ctx_options.threading_disabled = true;
				opts->rename = true;
				break;

			case 53:
				/* register-only */
				opts->acvp_ctx_options.register_only = true;
				break;

			default:
				usage();
				ret = -EINVAL;
				goto out;
				break;
			}
			break;

		case 'm':
			CKINT(parse_fuzzy_flag(&search->modulename_fuzzy_search,
					       &search->modulename, optarg));
			break;
		case 'n':
			CKINT(parse_fuzzy_flag(&search->vendorname_fuzzy_search,
					       &search->vendorname, optarg));
			break;
		case 'e':
			CKINT(parse_fuzzy_flag(&search->execenv_fuzzy_search,
					       &search->execenv, optarg));
			break;
		case 'r':
			CKINT(parse_fuzzy_flag(
					&search->moduleversion_fuzzy_search,
					&search->moduleversion, optarg));
			break;
		case 'p':
			CKINT(parse_fuzzy_flag(&search->processor_fuzzy_search,
					       &search->processor, optarg));
			break;
		case 'f':
			search->modulename_fuzzy_search = true;
			search->moduleversion_fuzzy_search = true;
			search->vendorname_fuzzy_search = true;
			search->execenv_fuzzy_search = true;
			search->processor_fuzzy_search = true;
			break;

		case 'l':
			dolist = 1;
			break;
		case 'u':
			listunregistered = 1;
			break;
		case 'c':
			CKINT(duplicate_string(&opts->configfile, optarg));
			break;
		case 'd':
			CKINT(acvp_def_config(optarg));
			modconf_loaded = 1;
			break;
		case 'o':
			opts->official_testing = true;
			break;
		case 'b':
			CKINT(duplicate_string(&opts->basedir, optarg));
			break;
		case 's':
			CKINT(duplicate_string(&opts->secure_basedir, optarg));
			break;

		case 'v':
			logger_inc_verbosity();
			if (logger_get_verbosity(LOGGER_C_ANY) >=
						 LOGGER_DEBUG)
				opts->acvp_ctx_options.threading_disabled = true;
			break;
		case 'q':
			logger_set_verbosity(LOGGER_NONE);
			break;
		case 'h':
			usage();
			ret = 0;
			goto out;
			break;
		default:
			usage();
			ret = -EINVAL;
			goto out;
			break;
		}
	}

	if (opts->acvp_ctx_options.delete_db_entry == ACVP_OPTS_DELUP_FORCE) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Forcing a deletion without specifying the definition type to delete is useless, use --delete-definition once or more with an option of [oe|vendor|module|person]\n");
		ret = -EINVAL;
		goto out;
	}

	if ((logger_get_verbosity(LOGGER_C_ANY) > LOGGER_NONE) &&
	    opts->acvp_ctx_options.delete_db_entry) {
		if (!ask_yes("Are you sure to perform a deletion operation")) {
			ret = -EINVAL;
			goto out;
		}

		if ((opts->acvp_ctx_options.delete_db_entry &
		     ACVP_OPTS_DELUP_FORCE) &&
		    !ask_yes("Are you sure to perform a forced deletion operation")) {
			ret = -EINVAL;
			goto out;
		}
	}

	if ((logger_get_verbosity(LOGGER_C_ANY) > LOGGER_NONE) &&
	    opts->acvp_ctx_options.update_db_entry) {
		if (!ask_yes("Are you sure to perform an update operation")) {
			ret = -EINVAL;
			goto out;
		}
	}

	if (!modconf_loaded)
		CKINT(acvp_def_default_config(opts->definition_basedir));

	if (listunregistered) {
		ret = acvp_list_unregistered_definitions();
		acvp_release();
		goto out;
	}

	if (dolist) {
		ret = acvp_list_registered_definitions(search);
		acvp_release();
		goto out;
	}

	if (!opts->configfile) {
		if (opts->official_testing)
			opts->configfile = strdup("acvpproxy_conf_production.json");
		else
			opts->configfile = strdup("acvpproxy_conf.json");
		CKNULL(opts->configfile, -ENOMEM);
	}

	CKINT(load_config(opts));

	return ret;

out:
	free_opts(opts);
	exit(-ret);
}

static void memset_secure(void *s, int c, uint32_t n)
{
	memset(s, c, n);
	__asm__ __volatile__("" : : "r" (s) : "memory");
}

static void last_gen_cb(time_t now)
{
	struct json_object *totp_val;
	struct flock lock;
	int ret;
	int fd;

	if (!global_opts || !global_opts->configfile)
		return;

	ret = json_find_key(global_opts->config, OPT_STR_TOTPLASTGEN, &totp_val,
			    json_type_int);
	if (ret) {
		json_object_object_add(global_opts->config, OPT_STR_TOTPLASTGEN,
				       json_object_new_int64(now));
	} else {
		json_object_set_int64(totp_val, now);
	}

	fd = open(global_opts->configfile, O_WRONLY | O_TRUNC);
	if (fd < 0)
		return;

	memset (&lock, 0, sizeof(lock));

	/*
	 * Place a write lock on the file. This call will put us to sleep if
	 * there is another lock.
	 */
	fcntl(fd, F_SETLKW, &lock);

	json_object_to_fd(fd, global_opts->config, JSON_C_TO_STRING_PRETTY |
			  JSON_C_TO_STRING_NOSLASHESCAPE);

	/* Release the lock. */
	lock.l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, &lock);

	close(fd);

	return;
}

static int set_totp_seed(struct opt_data *opts, bool enable_net)
{
	int ret;
	char *seed_base64 = NULL;
	uint32_t seed_base64_len = 0;
	uint8_t *seed = NULL;
	uint32_t seed_len;
	uint64_t totp_last_gen;

	if (!enable_net) {
		return acvp_init(NULL, 0, 0, false, NULL);
	}

	CKINT(load_totp_seed(opts, &seed_base64, &seed_base64_len));

	CKINT_LOG(base64_decode(seed_base64, seed_base64_len,
			        &seed, &seed_len),
		  "Base64 decoding failed\n");

	ret = json_get_uint64(opts->config, OPT_STR_TOTPLASTGEN,
			      &totp_last_gen);
	if (ret)
		totp_last_gen = 0;

	CKINT(acvp_init(seed, seed_len, (time_t)totp_last_gen,
			opts->official_testing, &last_gen_cb));

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "TOTP base64 seed converted into binary and applied\n");

out:
	/* securely dispose of the seed */
	if (seed_base64) {
		memset_secure(seed_base64, 0, seed_base64_len);
		free(seed_base64);
	}
	if (seed) {
		memset_secure(seed, 0, seed_len);
		free(seed);
	}
	return ret;
}

static int initialize_ctx(struct acvp_ctx **ctx, struct opt_data *opts,
			  bool enable_net)
{
	int ret;

	CKINT(set_totp_seed(opts, enable_net));

	CKINT(acvp_ctx_init(ctx, opts->basedir, opts->secure_basedir));

	/* Official testing */
	if (opts->official_testing) {
		CKINT(acvp_req_production(*ctx));
		if (enable_net)
			CKINT(acvp_set_net(NIST_DEFAULT_SERVER,
					   NIST_DEFAULT_SERVER_PORT,
				   opts->tlscabundle, opts->tlscakeychainref,
				   opts->tlscert, opts->tlscertkeychainref,
				   opts->tlskey, opts->tlspasscode));
	} else if (enable_net) {
		CKINT(acvp_set_net(NIST_TEST_SERVER,
				   NIST_DEFAULT_SERVER_PORT,
				   opts->tlscabundle, opts->tlscakeychainref,
				   opts->tlscert, opts->tlscertkeychainref,
				   opts->tlskey, opts->tlspasscode));
	}

	/* Submit requests and retrieve test vectors */
	CKINT(acvp_set_module(*ctx, &opts->search, opts->specific_modversion));

	CKINT(acvp_set_options(*ctx, &opts->acvp_ctx_options));

out:
	return ret;
}

static int do_register(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	uint32_t testid;
	int ret, idx = 0;
	bool printed = false;

	CKINT(initialize_ctx(&ctx, opts, true));

	ctx->req_details.dump_register = opts->dump_register;
	ctx->req_details.request_sample = opts->request_sample;

	if (opts->search.nr_submit_testid || opts->search.nr_submit_vsid) {
		/*
		 * If the caller provides particular vsIDs or testIDs to
		 * register, we implicitly assume that the caller wants to
		 * re-download the test vectors (how else would a caller know
		 * particular testIDs or vsIDs?).
		 */
		ctx->req_details.download_pending_vsid = true;
		CKINT(acvp_respond(ctx));
	} else {
		CKINT(acvp_register(ctx));
	}

	/* Fetch testID whose download failed */
	// TODO: Maybe store that data for automated resumption of download?
	while (!(ret = acvp_list_failed_testid(&idx, &testid))) {
		if (!printed) {
			fprintf(stderr, "Not all testIDs were downloaded cleanly. Invoke ACVP Proxy with the following options to download the remaining test vectors:\n");

			/* log to STDOUT to allow capturing apart from the log data */
			printf("--request ");
			printed = true;
		}
		printf("--testid %u ", testid);
	}

	if (printed)
		printf("\n");

	if (ret == -ENOENT)
		ret = 0;

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_submit(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	uint32_t vsid;
	int ret, ret2, idx = 0;
	bool printed = false;

	CKINT(initialize_ctx(&ctx, opts, true));

	ctx->req_details.request_sample = opts->request_sample;

	/*
	 * We want to list the verdicts we obtained irrespective of
	 * the return status.
	 */
	ret2 = acvp_respond(ctx);

	/* Fetch vsID with passing verdicts */
	while (!(ret = acvp_list_verdict_vsid(&idx, &vsid, true))) {
		if (!printed) {
			printf("\nThe following vsIDs passed:\n");
			printed = true;
		}
		fprintf_green(stdout, "%u\n", vsid);
	}

	if (ret && (ret != -ENOENT))
		goto out;

	idx = 0;
	printed = false;

	/* Fetch vsID with failing verdicts */
	while (!(ret = acvp_list_verdict_vsid(&idx, &vsid, false))) {
		if (!printed) {
			printf("\nThe following vsIDs failed:\n");
			printed = true;
		}
		fprintf_red(stdout, "%u\n", vsid);
	}

	if (ret == -ENOENT)
		ret = 0;

	/* Restore the return status from the acvp_respond download. */
	if (!ret)
		ret = ret2;

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_publish(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	ctx->req_details.dump_register = opts->dump_register;

	CKINT(acvp_publish(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int list_ids(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, false));

	if (opts->list_available_ids) {
		CKINT(acvp_list_available_ids(ctx));
	} else if (opts->list_pending_request_ids) {
		CKINT(acvp_list_request_ids(ctx));
	} else if (opts->list_pending_request_ids_sparse) {
		CKINT(acvp_list_request_ids_sparse(ctx));
	}

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int list_verdicts(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, false));

	CKINT(acvp_list_verdicts(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int list_certificates(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, false));

	CKINT(acvp_list_certificates(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int list_cipher_options(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, false));

	CKINT(acvp_list_cipher_options(ctx, opts->list_cipher_options_deps));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int list_certificates_detailed(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, false));

	CKINT(acvp_list_certificates_detailed(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_fetch_cipher_options(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_cipher_get(ctx, opts->cipher_options_algo,
			      opts->cipher_options_algo_idx,
			      opts->cipher_options_file));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_rename(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, false));

	ctx->rename = &opts->rename_ctx;

	CKINT(acvp_rename_module(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

int main(int argc, char *argv[])
{
	struct opt_data opts;
	int ret;

	memset(&opts, 0, sizeof(opts));
	global_opts = &opts;

	macos_disable_nap();

	logger_set_verbosity(LOGGER_ERR);

	CKINT(parse_opts(argc, argv, &opts));

	if (opts.cipher_list || opts.cipher_options_algo_idx ||
	    opts.cipher_options_file) {
		CKINT(do_fetch_cipher_options(&opts));
	} else if (opts.rename) {
		CKINT(do_rename(&opts));
	} else if (opts.request) {
		CKINT(do_register(&opts));
	} else if (opts.publish) {
		CKINT(do_publish(&opts));
	} else if (opts.list_available_ids ||
		   opts.list_pending_request_ids ||
		   opts.list_pending_request_ids_sparse) {
		CKINT(list_ids(&opts));
	} else if (opts.list_verdicts) {
		CKINT(list_verdicts(&opts));
	} else if (opts.list_certificates) {
		CKINT(list_certificates(&opts));
	} else if (opts.list_cipher_options || opts.list_cipher_options_deps) {
		CKINT(list_cipher_options(&opts));
	} else if (opts.list_certificates_detailed) {
		CKINT(list_certificates_detailed(&opts));
	} else {
		CKINT(do_submit(&opts));
	}

out:
	acvp_release();
	free_opts(&opts);
	return -ret;
}
