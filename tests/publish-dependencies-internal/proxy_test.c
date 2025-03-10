/* ACVP Proxy application
 *
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
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
#define OPT_STR_TLSKEYPASSCODE		"tlsKeyPasscode"
#define OPT_STR_TOTPSEEDFILE		"totpSeedFile"

#define OPT_CIPHER_OPTIONS_MAX		512

struct opt_data {
	struct acvp_search_ctx search;
	struct acvp_opts_ctx acvp_ctx_options;
	char *specific_modversion;

	char *basedir;
	char *secure_basedir;
	char *definition_basedir;
	char *cipher_options_file;
	char *cipher_options_algo[OPT_CIPHER_OPTIONS_MAX];
	size_t cipher_options_algo_idx;

	bool request;
	bool publish;
	bool dump_register;
	bool request_sample;
	bool official_testing;

	bool match;
	char *match_expected;
	char *match_actual;
};

/*
 * Pointer to parsed options. This pointer is only to be used by the async
 * callback function of last_gen_cb.
 */
static struct opt_data *global_opts = NULL;

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
	fprintf(stderr, "\t-f --fuzzy\t\t\tPerform a fuzzy search (perform a\n");
	fprintf(stderr, "\t\t\t\t\tsubstring search)\n");
	fprintf(stderr, "\n\tNote: The search critera allow narrowing the processed module\n");
	fprintf(stderr, "\tdefinitions found with the list operation. The less search criteria are\n");
	fprintf(stderr, "\tprovided, the broader the scope is. If no search critera are provided,\n");

	fprintf(stderr, "\tall module definitions are in scope. For example, using --request with\n");
	fprintf(stderr, "\tno search criteria implies that test vectors for all module\n");
	fprintf(stderr, "\timplementations known to the library are requested.\n\n");
	fprintf(stderr, "\t-c --config\t\t\tConfiguration file\n");
	fprintf(stderr, "\t-l --list\t\t\tList supported crypto modules\n");
	fprintf(stderr, "\t-u --unregistered\t\tList unregistered crypto definitions\n");
	fprintf(stderr, "\t   --modversion <VERSION>\tSpecific module version to send to ACVP\n");
	fprintf(stderr, "\t   --vsid <VSID>\t\tSubmit response for given vsID\n");
	fprintf(stderr, "\t\t\t\t\tOption can be specified up to %d times\n",
		MAX_SUBMIT_ID);
	fprintf(stderr, "\t   --testid <TESTID>\t\tSubmit response for given testID\n");
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

	fprintf(stderr, "\t   --resubmit-results\t\tIn case test results were already\n");
	fprintf(stderr, "\t\t\t\t\tsubmitted for a vsID, resubmit the\n");
	fprintf(stderr, "\t\t\t\t\tcurrent results on file to update the\n");
	fprintf(stderr, "\t\t\t\t\tresults on the ACVP server\n");
	fprintf(stderr, "\t   --register-definition\tRegister pending definitions with ACVP\n");

	fprintf(stderr, "\t   --cipher-options <DIR>\tGet cipher options from ACVP server\n");
	fprintf(stderr, "\t   --cipher-algo <ALGO>\t\tGet cipher options particular cipher\n");

	fprintf(stderr, "\n\t-v --verbose\t\t\tVerbose logging, multiple options\n");
	fprintf(stderr, "\t\t\t\t\tincrease verbosity\n");
	fprintf(stderr, "\t\t\t\t\tNote: In debug mode (3 or more -v),\n");
	fprintf(stderr, "\t\t\t\t\t      threading is disabled.\n");
	fprintf(stderr, "\t   --logger-class <NUM>\t\tLimit logging to given class\n");
	fprintf(stderr, "\t\t\t\t\t(-1 lists all logging classes)\n");
	fprintf(stderr, "\t-q --quiet\t\t\tNo output - quiet operation\n");
	fprintf(stderr, "\t   --version\t\t\tVersion of ACVP proxy\n");
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
	if (opts->basedir)
		free(opts->basedir);
	if (opts->secure_basedir)
		free(opts->secure_basedir);
	if (opts->definition_basedir)
		free(opts->definition_basedir);
	if (opts->cipher_options_file)
		free(opts->cipher_options_file);
	if (opts->match_actual)
		free(opts->match_actual);
	if (opts->match_expected)
		free(opts->match_expected);
	for (i = 0; i < opts->cipher_options_algo_idx; i++)
		free(opts->cipher_options_algo[i]);
}

static int duplicate_string(char **dst, char *src)
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

static int parse_opts(int argc, char *argv[], struct opt_data *opts)
{
	struct acvp_search_ctx *search = &opts->search;
	int c = 0, ret;
	char version[200] = { 0 };
	unsigned long val = 0;
	long lval;
	unsigned int dolist = 0, listunregistered = 0, modconf_loaded = 0;

	memset(opts, 0, sizeof(*opts));

	while (1) {
		int opt_index = 0;
		static struct option options[] = {
			{"verbose",		no_argument,		0, 'v'},
			{"logger-class",	required_argument,	0, 0},
			{"quiet",		no_argument,		0, 'q'},
			{"version",		no_argument,		0, 0},
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
			{"register-definition",	no_argument,		0, 0},

			{"cipher-options",	required_argument,	0, 0},
			{"cipher-algo",		required_argument,	0, 0},

			{"match-expected",	required_argument,	0, 0},
			{"match-actual",	required_argument,	0, 0},

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
				logger_inc_verbosity();
				break;
			case 1:
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
				logger_set_verbosity(LOGGER_NONE);
				break;
			case 3:
				acvp_versionstring(version, sizeof(version));
				fprintf(stderr, "Version %s\n", version);
				ret = 0;
				goto out;
				break;
			case 4:
				usage();
				ret = 0;
				goto out;
				break;

			case 5:
				CKINT(duplicate_string(&search->modulename,
						       optarg));
				break;
			case 6:
				CKINT(duplicate_string(&search->vendorname,
						       optarg));
				break;
			case 7:
				CKINT(duplicate_string(&search->execenv,
						       optarg));
				break;
			case 8:
				CKINT(duplicate_string(&search->moduleversion,
						       optarg));
				break;
			case 9:
				CKINT(duplicate_string(&search->processor,
						       optarg));
				break;
			case 10:
				search->modulename_fuzzy_search = true;
				search->moduleversion_fuzzy_search = true;
				search->vendorname_fuzzy_search = true;
				search->execenv_fuzzy_search = true;
				search->processor_fuzzy_search = true;
				break;

			case 11:
				dolist = 1;
				break;
			case 12:
				listunregistered = 1;
				break;
			case 13:
				CKINT(duplicate_string(&opts->specific_modversion,
						       optarg));
				break;
			case 14:
				if (search->nr_submit_vsid >= MAX_SUBMIT_ID) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "%u --submit options are allowed at maximum\n",
					       MAX_SUBMIT_ID);
					ret = -EINVAL;
					goto out;
				}
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "vsID too big\n");
					usage();
					ret = -EINVAL;
					goto out;
				}
				search->submit_vsid[search->nr_submit_vsid++] = (unsigned int)val;
				break;
			case 15:
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
			case 16:
				opts->request = true;
				break;
			case 17:
				opts->publish = true;
				break;

			case 18:
				opts->dump_register = true;
				break;
			case 19:
				opts->request_sample = true;
				break;
			case 21:
				CKINT(acvp_def_config(optarg));
				modconf_loaded = 1;
				break;
			case 22:
				opts->official_testing = true;
				break;
			case 23:
				CKINT(duplicate_string(&opts->basedir, optarg));
				break;
			case 24:
				CKINT(duplicate_string(&opts->secure_basedir,
						       optarg));
				break;
			case 25:
				CKINT(duplicate_string(&opts->definition_basedir,
						       optarg));
				break;

			case 26:
				opts->acvp_ctx_options.resubmit_result = true;
				break;
			case 27:
				opts->acvp_ctx_options.register_new_module = true;
				opts->acvp_ctx_options.register_new_vendor = true;
				opts->acvp_ctx_options.register_new_oe = true;
				break;

			case 28:
				CKINT(duplicate_string(&opts->cipher_options_file,
						       optarg));
				break;
			case 29:
				CKINT(duplicate_string(&opts->cipher_options_algo[opts->cipher_options_algo_idx],
						       optarg));
				opts->cipher_options_algo_idx++;
				if (opts->cipher_options_algo_idx >=
				    OPT_CIPHER_OPTIONS_MAX) {
					ret = -EOVERFLOW;
					goto out;
				}
				break;

			case 30:
				CKINT(duplicate_string(&opts->match_expected,
						       optarg));
				if (opts->match_actual)
					opts->match = true;
				break;
			case 31:
				CKINT(duplicate_string(&opts->match_actual,
						       optarg));
				if (opts->match_expected)
					opts->match = true;
				break;

			default:
				usage();
				ret = -EINVAL;
				goto out;
				break;
			}
			break;

		case 'm':
			CKINT(duplicate_string(&search->modulename, optarg));
			break;
		case 'n':
			CKINT(duplicate_string(&search->vendorname, optarg));
			break;
		case 'e':
			CKINT(duplicate_string(&search->execenv, optarg));
			break;
		case 'r':
			CKINT(duplicate_string(&search->moduleversion, optarg));
			break;
		case 'p':
			CKINT(duplicate_string(&search->processor, optarg));
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
		case 'd':
			CKINT(acvp_def_config(optarg));
			modconf_loaded = 1;
			break;
		case 'o':
			opts->official_testing = 1;
			break;
		case 'b':
			CKINT(duplicate_string(&opts->basedir, optarg));
			break;
		case 's':
			CKINT(duplicate_string(&opts->secure_basedir, optarg));
			break;

		case 'v':
			logger_inc_verbosity();
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

	return ret;

out:
	free_opts(opts);
	exit(-ret);
}

static int set_totp_seed(struct opt_data *opts)
{
	int ret = 0;
	uint8_t seed[16];

	(void)opts;

	CKINT(acvp_init(seed, sizeof(seed), 0, 0, NULL));

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "TOTP base64 seed converted into binary and applied\n");

out:
	return ret;
}

static int initialize_ctx(struct acvp_ctx **ctx, struct opt_data *opts)
{
	int ret = 0;

	CKINT(acvp_ctx_init(ctx, opts->basedir, opts->secure_basedir));

	/* Official testing */
	if (opts->official_testing) {
		CKINT(acvp_req_production(*ctx));
		CKINT(acvp_set_net(NIST_DEFAULT_SERVER,
				   NIST_DEFAULT_SERVER_PORT,
				   NULL /*"../acvp-keys/acvp.nist.gov.crt"*/,
				   "foo.cer", "foo.pem", NULL));
	} else {
		CKINT(acvp_set_net(NIST_TEST_SERVER,
				   NIST_DEFAULT_SERVER_PORT,
				   NULL /*"../acvp-keys/acvp.nist.gov.crt"*/,
				   "foo.cer", "foo.pem", NULL));
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
	uint64_t testid;
	int ret, idx = 0;
	bool printed = false;

	CKINT(initialize_ctx(&ctx, opts));

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
	while (!(ret = acvp_list_failed_testid(&idx, &testid))) {
		if (!printed) {
			fprintf(stderr, "Not all testIDs were downloaded cleanly. Invoke ACVP Proxy with the following options to download the remaining test vectors:\n");

			/* log to STDOUT to allow capturing apart from the log data */
			printf("--request ");
			printed = true;
		}
		printf("--testid %"PRIu64" ", testid);
	}

	if (ret == -ENOENT)
		ret = 0;

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_submit(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	uint64_t vsid;
	int ret, ret2, idx = 0;
	bool printed = false;

	CKINT(initialize_ctx(&ctx, opts));

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
	int ret = 0;

	CKINT(initialize_ctx(&ctx, opts));

	ctx->req_details.dump_register = opts->dump_register;

	CKINT(acvp_publish(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_fetch_cipher_options(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret = 0;

	CKINT(initialize_ctx(&ctx, opts));

	CKINT(acvp_cipher_get(ctx, opts->cipher_options_algo,
			      opts->cipher_options_algo_idx,
			      opts->cipher_options_file));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int match_expected(const char *actualfile, const char *expectedfile)
{
	struct json_object *actual = NULL, *expobj = NULL;
	int ret;

	/* Open and parse expected test result */
	expobj = json_object_from_file(expectedfile);
	CKNULL_LOG(expobj, -EFAULT, "Cannot parse expected file\n");

	/* Open and parse actual test result */
	actual = json_object_from_file(actualfile);
	CKNULL_LOG(actual, -EFAULT, "Cannot parse actual file\n");

	ret = json_object_equal(expobj, actual);
	if (ret) {
		if (logger_get_verbosity(LOGGER_C_ANY) >= LOGGER_WARN) {
			fprintf_green(stdout, "[PASSED] ");
			fprintf(stdout,"compare %s with %s\n", actualfile,
			        expectedfile);
		}
		ret = 0;
	} else {
		if (logger_get_verbosity(LOGGER_C_ANY) >= LOGGER_WARN) {
			fprintf_red(stdout, "[FAILED] ");
			fprintf(stdout, "compare %s with %s\n", actualfile,
			        expectedfile);
		}
		ret = -EIO;
	}

out:
	if (actual)
		json_object_put(actual);
	if (expobj)
		json_object_put(expobj);

	return ret;
}

int main(int argc, char *argv[])
{
	struct opt_data opts;
	int ret = 0;

	memset(&opts, 0, sizeof(opts));
	global_opts = &opts;

	macos_disable_nap();

	logger_set_verbosity(LOGGER_ERR);

	CKINT(parse_opts(argc, argv, &opts));

	CKINT(set_totp_seed(&opts));

	if (opts.cipher_options_file) {
		CKINT(do_fetch_cipher_options(&opts));
	} else if (opts.request) {
		CKINT(do_register(&opts));
	} else if (opts.publish) {
		CKINT(do_publish(&opts));
	} else if (opts.match) {
		CKINT(match_expected(opts.match_actual, opts.match_expected));
	} else {
		CKINT(do_submit(&opts));
	}

out:
	acvp_release();
	free_opts(&opts);
	return -ret;
}
