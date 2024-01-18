/* ACVP Proxy application
 *
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

#include <getopt.h>
#include <stdio.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>

#include <json-c/json.h>

#include "acvpproxy.h"
#include "amvpproxy.h"
#include "esvpproxy.h"
#include "base64.h"
#include "credentials.h"
#include "helper.h"
#include "logger.h"
#include "memset_secure.h"
#include "ret_checkers.h"
#include "term_colors.h"

#include "macos.h"

#define OPT_CIPHER_OPTIONS_MAX 512

struct opt_data {
	struct acvp_search_ctx search;
	struct acvp_opts_ctx acvp_ctx_options;
	struct acvp_rename_ctx rename_ctx;
	char *specific_modversion;

	uint32_t purchase_opt;
	uint32_t purchase_qty;
	const char *ponumber;

	struct opt_cred cred;

	const char *cert_details_niap_req_file;
	const char *acvp_server_db_search;
	uint32_t acvp_server_db_fetch_id;
	uint32_t acvp_server_db_validation_id;
	enum acvp_server_db_search_type search_type;
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
	bool list_missing_certificates;
	bool list_missing_results;
	bool list_certificates_detailed;
	bool list_cipher_options;
	bool list_cipher_options_deps;
	bool dump_register;
	bool request_sample;
	bool official_testing;
	bool sync_meta;
	bool list_purchased_vs;
	bool list_available_purchase_opts;
	bool fetch_verdicts;
	bool esvp_proxy;
	bool amvp_proxy;
};

static void usage(void)
{
	char version[200];

	acvp_versionstring(version, sizeof(version));

	fprintf(stderr, "\nACVP Test Vector And Test Verdict Proxy\n");
	fprintf(stderr, "\nACVP proxy library version: %s\n", version);
	fprintf(stderr, "\nACVP proxy library GIT version: %s\n\n", GITVER);
	fprintf(stderr, "Register module and fetch test vectors:\n");
	fprintf(stderr,
		"  acvp-proxy [-mrnepf MODULE_SEARCH_CRITERIA] --request\n\n");
	fprintf(stderr,
		"Continue download interrupted fetch of test vectors:\n");
	fprintf(stderr,
		"  acvp-proxy [-mrnepf MODULE_SEARCH_CRITERIA] --request [--testid|--vsid ID]\n\n");
	fprintf(stderr,
		"Upload test responses and (continue to) fetch verdict:\n");
	fprintf(stderr,
		"  acvp-proxy [-mrnepf MODULE_SEARCH_CRITERIA] [--testid|--vsid ID]\n\n");

	fprintf(stderr, "Download samples after vectors are obtained:\n");
	fprintf(stderr,
		"  acvp-proxy [-mrnepf MODULE_SEARCH_CRITERIA] [--testid|--vsid ID] --sample\n\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr,
		"\tModule search criteria limiting the scope of processed modules:\n");
	fprintf(stderr,
		"\t-m --module <NAME>\t\tDefinition search criteria: Name of\n");
	fprintf(stderr, "\t\t\t\t\tcrypto module to process\n");
	fprintf(stderr,
		"\t-r --releaseversion <VERSION>\tDefinition search criteria: Version\n");
	fprintf(stderr, "\t\t\t\t\tof crypto module to process\n");
	fprintf(stderr,
		"\t-n --vendorname <NAME>\t\tDefinition search criteria: Name of\n");
	fprintf(stderr, "\t\t\t\t\tvendor of crypto module to process\n");
	fprintf(stderr,
		"\t-e --execenv <NAME>\t\tDefinition search criteria: Name of \n");
	fprintf(stderr, "\t\t\t\t\texecution environment of crypto module\n");
	fprintf(stderr, "\t\t\t\t\tto process\n");
	fprintf(stderr,
		"\t-p --processor <NAME>\t\tDefinition search criteria: Name of \n");
	fprintf(stderr, "\t\t\t\t\tprocessor executing crypto module\n");
	fprintf(stderr,
		"\t-f --fuzzy\t\t\tPerform a fuzzy search for all search \n");
	fprintf(stderr, "\t\t\t\t\tcriteria (perform a substring search)\n");
	fprintf(stderr,
		"\n\tNote: The search critera allow narrowing the processed module\n");
	fprintf(stderr,
		"\tdefinitions found with the list operation. The less search criteria are\n");
	fprintf(stderr,
		"\tprovided, the broader the scope is. If no search critera are provided,\n");
	fprintf(stderr,
		"\tall module definitions are in scope. For example, using --request with\n");
	fprintf(stderr,
		"\tno search criteria implies that test vectors for all module\n");
	fprintf(stderr,
		"\timplementations known to the library are requested.\n\n");
	fprintf(stderr,
		"\tNote 2: Prepending the search strings with \"f:\" requests a fuzzy search\n");
	fprintf(stderr, "\tfor only that particular search criteria.\n\n");

	fprintf(stderr, "\t-c --config\t\t\tConfiguration file\n");
	fprintf(stderr, "\t-l --list\t\t\tList supported crypto modules\n");
	fprintf(stderr,
		"\t-u --unregistered\t\tList unregistered crypto definitions\n");
	fprintf(stderr,
		"\t   --modversion <VERSION>\tSpecific module version to send to ACVP\n");
	fprintf(stderr,
		"\t   --vsid <VSID>\t\tSubmit response for given vsID\n");
	fprintf(stderr, "\t\t\t\t\tOption can be specified up to %d times\n",
		MAX_SUBMIT_ID);
	fprintf(stderr,
		"\t   --testid <TESTID>\t\tSubmit response for given testID\n");
	fprintf(stderr, "\t\t\t\t\t(use -1 to download all pending testIDs)\n");
	fprintf(stderr, "\t\t\t\t\tOption can be specified up to %d times\n",
		MAX_SUBMIT_ID);
	fprintf(stderr, "\t   --request\t\t\tRequest new test vector set\n");
	fprintf(stderr, "\t   --request-json <FILE>\tRequest new test vector set from\n");
	fprintf(stderr, "\t\t\t\t\tcaller-supplied file. This option applies \n");
	fprintf(stderr, "\t\t\t\t\tthe provided JSON file to all module\n");
	fprintf(stderr, "\t\t\t\t\tdefinitions in the search scope!\n");
	fprintf(stderr,
		"\n\tNote: If the caller provides --testid or --vsid together with\n");
	fprintf(stderr,
		"\t--request, the application assumes that pending vector sets shall\n");
	fprintf(stderr,
		"\tbe downloaded again (e.g. in case prior download attempts failed).\n\n");
	fprintf(stderr, "\t   --publish\t\t\tPublish test verdicts\n");
	fprintf(stderr,
		"\n\tNote: You can use --testid or --vsid together with\n");
	fprintf(stderr, "\t--publish to limit the scope.\n\n");

	fprintf(stderr,
		"\t   --dump-register\t\tDump register JSON request to stdout\n");
	fprintf(stderr,
		"\t   --sample\t\t\tRequest a test sample with expected\n");
	fprintf(stderr, "\t\t\t\t\tresults\n");
	fprintf(stderr,
		"\t-d --definitions\t\tDirectory holding the module definitions\n");
	fprintf(stderr, "\t\t\t\t\tfor one specific module\n");
	fprintf(stderr,
		"\t   --official\t\t\tPerform an official testing to get\n");
	fprintf(stderr, "\t\t\t\t\tcertificates (use official NIST servers)\n");
	fprintf(stderr, "\t-b --basedir\t\t\tBase directory for test data\n");
	fprintf(stderr,
		"\t-s --secure-basedir\t\tBase directory for sensitive data\n");
	fprintf(stderr,
		"\t   --definition-basedir\t\tBase directory for module definition\n\n");

	fprintf(stderr,
		"\t   --resubmit-result\t\tIn case test results were already\n");
	fprintf(stderr, "\t\t\t\t\tsubmitted for a vsID, resubmit the\n");
	fprintf(stderr, "\t\t\t\t\tcurrent results on file to update the\n");
	fprintf(stderr, "\t\t\t\t\tresults on the ACVP server\n\n");

	fprintf(stderr,
		"\t   --delete-test\t\tDelete all vsIds in scope which\n");
	fprintf(stderr, "\t\t\t\t\tare part of the registration - this\n");
	fprintf(stderr, "\t\t\t\t\toption is only applicable during\n");
	fprintf(stderr, "\t\t\t\t\tsubmitting responses to the ACVP server\n");
	fprintf(stderr,
		"\t   --fetch-verdicts\t\tFetch verdicts for all vsIDs in scope\n");
	fprintf(stderr, "\t\t\t\t\tThis option can be used to also refresh\n");
	fprintf(stderr, "\t\t\t\t\ta vsID to guard it against deletion due\n");
	fprintf(stderr, "\t\t\t\t\tto 30 day inactivity\n\n");

	fprintf(stderr,
		"\tUpdate ACVP database with content from JSON configuration files:\n");
	fprintf(stderr,
		"\t   --nopublish-prereqs\t\tRemove prerequisites from publication\n");
	fprintf(stderr, "\t\t\t\t\trequest\n");
	fprintf(stderr,
		"\t   --register-definition\tRegister pending definitions with ACVP\n");
	fprintf(stderr,
		"\t   --delete-definition <TYPE>\tDelete definition at ACVP server\n");
	fprintf(stderr,
		"\t   --update-definition <TYPE>\tUpdate definition at ACVP server\n");
	fprintf(stderr, "\t\t\t\t\tTYPE: [oe|vendor|module|person|force]\n");
	fprintf(stderr, "\t\t\t\t\tNote: Force implies that even when no\n");
	fprintf(stderr, "\t\t\t\t\t      consistency is established between\n");
	fprintf(stderr, "\t\t\t\t\t      the ACVP server and the local\n");
	fprintf(stderr, "\t\t\t\t\t      definition selected with the TYPE,\n");
	fprintf(stderr, "\t\t\t\t\t      it is deleted from the ACVP\n");
	fprintf(stderr, "\t\t\t\t\t      server.\n");
	fprintf(stderr,
		"\t   --sync-meta\t\t\tSynchronize meta data with server\n\n");

	fprintf(stderr, "\tList of IDs and verdicts:\n");
	fprintf(stderr,
		"\t   --list-request-ids\t\tList all pending request IDs\n");
	fprintf(stderr,
		"\t   --list-request-ids-sparse\tList all pending request IDs\n");
	fprintf(stderr, "\t\t\t\t\twithout duplicates\n");
	fprintf(stderr,
		"\t   --list-available-ids\t\tList all available IDs\n");
	fprintf(stderr, "\t   --list-verdicts\t\tList all verdicts\n\n");
	fprintf(stderr, "\t   --list-certificates\t\tList all certificates\n");
	fprintf(stderr, "\t   --list-missing-certificates\tList all missing certificates\n");
	fprintf(stderr, "\t   --list-missing-results\tList all missing results\n");
	fprintf(stderr,
		"\t   --list-cert-details\t\tList all certificate details for\n");
	fprintf(stderr, "\t\t\t\t\tTE.01.12.01\n");
	fprintf(stderr,
		"\t   --list-cert-niap <FILE>\tList all certificate details for\n");
	fprintf(stderr, "\t\t\t\t\ta NIAP CC eval\n");
	fprintf(stderr,
		"\t   --list-cipher-options\tList all cipher options\n");
	fprintf(stderr,
		"\t   --list-cipher-options-deps\tList all cipher options with\n");
	fprintf(stderr, "\t\t\t\t\tcipher dependencies\n\n");

	fprintf(stderr, "\tSearch the ACVP Server DB:\n");
	fprintf(stderr,
		"\t   --list-server-db <TYPE>\tList entries in ACVP server database\n");
	fprintf(stderr, "\t\t\t\t\twhich are found in the local JSON\n");
	fprintf(stderr, "\t\t\t\t\tconfig files\n");
	fprintf(stderr, "\t\t\t\t\tTYPE: [oe|vendor|module|person]\n");
	fprintf(stderr,
		"\t   --search-server-db <SEARCH>\tSearch ACVP server database\n");
	fprintf(stderr, "\t\t\t\t\tSEARCH: <TYPE>:<QUERY>\n");
	fprintf(stderr, "\t\t\t\t\tTYPE:\t[oe|vendor|module|person|\n");
	fprintf(stderr, "\t\t\t\t\t\taddress|dependency|validation]\n");
	fprintf(stderr, "\t\t\t\t\tQUERY: string as defined in ACVP spec\n");
	fprintf(stderr, "\t\t\t\t\tsection 11.6 \n");
	fprintf(stderr, "\t   --fetch-id-from-server-db <SEARCH>\n");
	fprintf(stderr, "\t\t\t\t\tFetch given ID from ACVP server DB\n");
	fprintf(stderr, "\t\t\t\t\tSEARCH: <TYPE>:<ID>\n");
	fprintf(stderr, "\t\t\t\t\tTYPE:\t[oe|vendor|module|person|\n");
	fprintf(stderr, "\t\t\t\t\t\taddress|dependency|validation]\n");
	fprintf(stderr, "\t\t\t\t\tID: numeric ID to search for\n");
	fprintf(stderr,
		"\t   --fetch-validation-from-server-db <VALIDATION ID>\n");
	fprintf(stderr, "\t\t\t\t\tAll meta data for validation ID from\n");
	fprintf(stderr, "\t\t\t\t\tACVP server DB to populate new\n");
	fprintf(stderr, "\t\t\t\t\tmodule_definition directory\n\n");

	fprintf(stderr, "\tGathering cipher definitions from ACVP server:\n");
	fprintf(stderr,
		"\t   --cipher-list\t\tList all ciphers supported by ACVP\n");
	fprintf(stderr, "\t\t\t\t\tserver\n");
	fprintf(stderr,
		"\t   --cipher-options <DIR>\tGet cipher options from ACVP server\n");
	fprintf(stderr, "\t\t\t\t\tand store them in <DIR>\n");
	fprintf(stderr,
		"\t   --cipher-algo <ALGO>\t\tGet cipher options particular cipher\n\n");

	fprintf(stderr, "\tPayment options:\n");
	fprintf(stderr,
		"\t   --list-purchased-vs\t\tList number of yet unused and thus\n");
	fprintf(stderr, "\t\t\t\t\tavailable vector sets\n");
	fprintf(stderr,
		"\t   --list-purchase-opts\t\tList purchase options offered by ACVP\n");
	fprintf(stderr, "\t\t\t\t\tserver\n");
	fprintf(stderr,
		"\t   --purchase <OPTION>\t\tPurchase option <OPTION>\n");
	fprintf(stderr, "\t\t\t\t\t- see output of --list-purchase-opts\n");
	fprintf(stderr,
		"\t   --ponumber <STRING>\t\tPurchase order - arbitrary string\n");
	fprintf(stderr, "\t\t\t\t\tto be used by NIST when creating invoice\n");
	fprintf(stderr, "\t\t\t\t\tto allow assigning the invoice in local\n");
	fprintf(stderr, "\t\t\t\t\tpayment system\n\n");

	fprintf(stderr, "\tAuxiliary options:\n");
	fprintf(stderr,
		"\t   --proxy-extension <SO-FILE>\tShared library of ACVP Proxy extension\n");
	fprintf(stderr, "\t\t\t\t\tZero or more extensions can be provided.\n");
	fprintf(stderr,
		"\t   --proxy-extension-dir <DIR>\tDirectory with ACVP Proxy extensions\n");
	fprintf(stderr,
		"\t   --rename-version <NEW>\tRename version of definition\n");
	fprintf(stderr, "\t\t\t\t\t(moduleVersion)\n");
	fprintf(stderr,
		"\t   --rename-name <NEW>\t\tRename name of definition (moduleName)\n");
	fprintf(stderr,
		"\t   --rename-oename <NEW>\tRename OE name of definition (oeEnvName)\n");
	fprintf(stderr,
		"\t   --rename-procname <NEW>\tRename processor name of definition \n");
	fprintf(stderr, "\t\t\t\t\t(procName)\n");
	fprintf(stderr,
		"\t   --rename-procseries <NEW>\tRename processor series of definition \n");
	fprintf(stderr, "\t\t\t\t\t(procSeries)\n");
	fprintf(stderr,
		"\t   --rename-procfamily <NEW>\tRename processor family of definition \n");
	fprintf(stderr, "\t\t\t\t\t(procFamily)\n");
	fprintf(stderr,
		"\t   --register-only\t\tOnly register tests without downloading\n");
	fprintf(stderr, "\t\t\t\t\ttest vectors\n");
	fprintf(stderr,
		"\t   --upload-only\t\tOnly upload test responses without\n");
	fprintf(stderr, "\t\t\t\t\tdownloading test verdicts\n");
	fprintf(stderr,
		"\t-v --verbose\t\t\tVerbose logging, multiple options\n");
	fprintf(stderr, "\t\t\t\t\tincrease verbosity\n");
	fprintf(stderr, "\t\t\t\t\tNote: In debug mode (3 or more -v),\n");
	fprintf(stderr, "\t\t\t\t\t      threading is disabled.\n");
	fprintf(stderr,
		"\t   --logger-class <NUM>\t\tLimit logging to given class\n");
	fprintf(stderr, "\t\t\t\t\t(-1 lists all logging classes)\n");
	fprintf(stderr, "\t   --logfile <FILE>\t\tFile to write logs to\n");
	fprintf(stderr, "\t-q --quiet\t\t\tNo output - quiet operation\n");
	fprintf(stderr, "\t   --version\t\t\tVersion of ACVP proxy\n");
	fprintf(stderr,
		"\t   --version-numeric\t\tNumeric version of ACVP proxy\n");
	fprintf(stderr, "\t-h --help\t\t\tPrint this help information\n");
}

static void free_opts(struct opt_data *opts)
{
	struct acvp_search_ctx *search = &opts->search;
	size_t i;

	cred_free(&opts->cred);

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
	for (i = 0; i < opts->cipher_options_algo_idx; i++)
		free(opts->cipher_options_algo[i]);
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
		logger(LOGGER_ERR, LOGGER_C_ANY, "Unknown delete type %s\n",
		       string);
		return -EINVAL;
	}

	return 0;
}

static int convert_show_type(const char *string, unsigned int *option)
{
	if (!strncmp(string, "oe", 2)) {
		*option |= ACVP_OPTS_SHOW_OE;
	} else if (!strncmp(string, "vendor", 6)) {
		*option |= ACVP_OPTS_SHOW_VENDOR;
	} else if (!strncmp(string, "person", 6)) {
		*option |= ACVP_OPTS_SHOW_PERSON;
	} else if (!strncmp(string, "module", 6)) {
		*option |= ACVP_OPTS_SHOW_MODULE;
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY, "Unknown show type %s\n",
		       string);
		return -EINVAL;
	}

	return 0;
}

static int convert_search_type_string(const char *string,
				      const char **searchstr,
				      enum acvp_server_db_search_type *type)
{
	if (!strncmp(string, "oe:", 3)) {
		*type = NIST_SERVER_DB_SEARCH_OE;
		*searchstr = string + 3;
	} else if (!strncmp(string, "vendor:", 7)) {
		*type = NIST_SERVER_DB_SEARCH_VENDOR;
		*searchstr = string + 7;
	} else if (!strncmp(string, "person:", 7)) {
		*type = NIST_SERVER_DB_SEARCH_PERSONS;
		*searchstr = string + 7;
	} else if (!strncmp(string, "module:", 7)) {
		*type = NIST_SERVER_DB_SEARCH_MODULE;
		*searchstr = string + 7;
	} else if (!strncmp(string, "dependency:", 11)) {
		*type = NIST_SERVER_DB_SEARCH_DEPENDENCY;
		*searchstr = string + 11;
	} else if (!strncmp(string, "address:", 8)) {
		*type = NIST_SERVER_DB_SEARCH_ADDRESSES;
		*searchstr = string + 8;
	} else if (!strncmp(string, "validation:", 11)) {
		*type = NIST_SERVER_DB_SEARCH_VALIDATION;
		*searchstr = string + 11;
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY, "Unknown search type %s\n",
		       string);
		return -EINVAL;
	}

	return 0;
}

static int convert_search_type_id(const char *string, uint32_t *id,
				  enum acvp_server_db_search_type *type)
{
	const char *search;
	unsigned long val;
	int ret;

	CKINT(convert_search_type_string(string, &search, type));
	val = strtoul(search, NULL, 10);
	if (val == UINT_MAX) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "ID too big\n");
		usage();
		ret = -EINVAL;
		goto out;
	}

	*id = (uint32_t)val;

out:
	return ret;
}

static int parse_opts(int argc, char *argv[], struct opt_data *opts)
{
	struct acvp_search_ctx *search = &opts->search;
	struct acvp_rename_ctx *rename = &opts->rename_ctx;
	struct opt_cred *cred = &opts->cred;
	int c = 0, ret;
	char version[200] = { 0 };
	unsigned long val = 0;
	long lval;
	unsigned int dolist = 0, listunregistered = 0, modconf_loaded = 0;
	bool logger_force_threading = false;

	while (1) {
		int opt_index = 0;
		static struct option options[] = {
			{ "verbose", no_argument, 0, 'v' },
			{ "logger-class", required_argument, 0, 0 },
			{ "logfile", required_argument, 0, 0 },
			{ "quiet", no_argument, 0, 'q' },
			{ "version", no_argument, 0, 0 },
			{ "version-numeric", no_argument, 0, 0 },
			{ "help", no_argument, 0, 'h' },

			{ "module", required_argument, 0, 'm' },
			{ "vendorname", required_argument, 0, 'n' },
			{ "execenv", required_argument, 0, 'e' },
			{ "releaseversion", required_argument, 0, 'r' },
			{ "processor", required_argument, 0, 'p' },
			{ "fuzzy", no_argument, 0, 'f' },

			{ "list", no_argument, 0, 'l' },
			{ "config", required_argument, 0, 'c' },
			{ "definitions", required_argument, 0, 'd' },

			{ "unregistered", no_argument, 0, 'u' },
			{ "modversion", required_argument, 0, 0 },
			{ "vsid", required_argument, 0, 0 },
			{ "testid", required_argument, 0, 0 },
			{ "request", no_argument, 0, 0 },
			{ "publish", no_argument, 0, 0 },
			{ "dump-register", no_argument, 0, 0 },
			{ "sample", no_argument, 0, 0 },

			{ "official", no_argument, 0, 'o' },
			{ "basedir", required_argument, 0, 'b' },
			{ "secure-basedir", required_argument, 0, 's' },
			{ "definition-basedir", required_argument, 0, 0 },

			{ "resubmit-result", no_argument, 0, 0 },
			{ "delete-test", no_argument, 0, 0 },
			{ "register-definition", no_argument, 0, 0 },
			{ "delete-definition", required_argument, 0, 0 },
			{ "update-definition", required_argument, 0, 0 },
			{ "nopublish-prereqs", required_argument, 0, 0 },
			{ "sync-meta", no_argument, 0, 0 },

			{ "list-request-ids", no_argument, 0, 0 },
			{ "list-request-ids-sparse", no_argument, 0, 0 },
			{ "list-available-ids", no_argument, 0, 0 },
			{ "list-verdicts", no_argument, 0, 0 },
			{ "list-certificates", no_argument, 0, 0 },
			{ "list-missing-certificates", no_argument, 0, 0 },
			{ "list-missing-results", no_argument, 0, 0 },
			{ "list-cert-details", no_argument, 0, 0 },
			{ "list-cert-niap", required_argument, 0, 0 },
			{ "list-cipher-options", no_argument, 0, 0 },
			{ "list-cipher-options-deps", no_argument, 0, 0 },
			{ "list-server-db", required_argument, 0, 0 },
			{ "search-server-db", required_argument, 0, 0 },
			{ "fetch-id-from-server-db", required_argument, 0, 0 },
			{ "fetch-validation-from-server-db", required_argument,
			  0, 0 },

			{ "cipher-options", required_argument, 0, 0 },
			{ "cipher-algo", required_argument, 0, 0 },
			{ "cipher-list", no_argument, 0, 0 },

			{ "proxy-extension", required_argument, 0, 0 },
			{ "proxy-extension-dir", required_argument, 0, 0 },
			{ "rename-version", required_argument, 0, 0 },
			{ "rename-name", required_argument, 0, 0 },
			{ "rename-oename", required_argument, 0, 0 },
			{ "rename-procname", required_argument, 0, 0 },
			{ "rename-procseries", required_argument, 0, 0 },
			{ "rename-procfamily", required_argument, 0, 0 },

			{ "register-only", no_argument, 0, 0 },
			{ "upload-only", no_argument, 0, 0 },

			{ "list-purchased-vs", no_argument, 0, 0 },
			{ "list-purchase-opts", no_argument, 0, 0 },
			{ "purchase", required_argument, 0, 0 },
			{ "ponumber", required_argument, 0, 0 },

			{ "fetch-verdicts", no_argument, 0, 0 },

			{ "request-json", required_argument, 0, 0 },

			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "m:n:e:r:p:fluc:d:ob:s:vqh",
				options, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* verbose */
				logger_inc_verbosity();
				if (logger_get_verbosity(LOGGER_C_ANY) >=
					    LOGGER_DEBUG &&
				    !logger_force_threading)
					opts->acvp_ctx_options
						.threading_disabled = true;
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
					       "Failed to set logger class %lu\n",
					       val);
					goto out;
				}
				break;
			case 2:
				/* logfile */
				CKINT(logger_set_file(optarg));
				logger_force_threading = true;
				opts->acvp_ctx_options.threading_disabled =
					false;
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
				/* config */
				CKINT(duplicate_string(&cred->configfile,
						       optarg));
				break;
			case 15:
				/* definitions */
				CKINT(acvp_def_config(optarg));
				modconf_loaded = 1;
				break;

			case 16:
				/* unregistered */
				listunregistered = 1;
				break;
			case 17:
				/* modversion */
				CKINT(duplicate_string(
					&opts->specific_modversion, optarg));
				break;
			case 18:
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
					search->submit_vsid
						[search->nr_submit_vsid++] =
						UINT_MAX;
				else
					search->submit_vsid
						[search->nr_submit_vsid++] =
						(unsigned int)lval;
				break;
			case 19:
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
				search->submit_testid[search->nr_submit_testid++] =
					(unsigned int)val;
				break;
			case 20:
				/* request */
				opts->request = true;
				break;
			case 21:
				/* publish */
				opts->publish = true;
				break;

			case 22:
				/* dump-register */
				opts->dump_register = true;
				break;
			case 23:
				/* sample */
				opts->request_sample = true;
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
				CKINT(duplicate_string(
					&opts->definition_basedir, optarg));
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
				opts->acvp_ctx_options.register_new_module =
					true;
				opts->acvp_ctx_options.register_new_vendor =
					true;
				opts->acvp_ctx_options.register_new_oe = true;
				break;
			case 31:
				/* delete-definition */
				CKINT(convert_update_delete_type(
					optarg, &opts->acvp_ctx_options
							 .delete_db_entry));
				/* This operation must use the publish path */
				opts->publish = true;
				break;
			case 32:
				/* update-definition */
				CKINT(convert_update_delete_type(
					optarg, &opts->acvp_ctx_options
							 .update_db_entry));
				/* This operation must use the publish path */
				opts->publish = true;
				break;
			case 33:
				/* nopublish-prereqs */
				opts->acvp_ctx_options.no_publish_prereqs =
					true;
				break;
			case 34:
				/* sync-meta */
				opts->sync_meta = true;
				break;

			case 35:
				/* list-request-ids */
				opts->list_pending_request_ids = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 36:
				/* list-request-ids-sparse */
				opts->list_pending_request_ids_sparse = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 37:
				/* list-available-ids */
				opts->list_available_ids = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 38:
				/* list-verdicts */
				opts->list_verdicts = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 39:
				/* list-certificates */
				opts->list_certificates = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 40:
				/* list-missing-certificates */
				opts->list_missing_certificates = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 41:
				/* list-missing-results */
				opts->list_missing_results = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 42:
				/* list-cert-details */
				opts->list_certificates_detailed = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 43:
				/* list-cert-niap */
				opts->list_certificates_detailed = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				opts->cert_details_niap_req_file = optarg;
				break;
			case 44:
				/* list-cipher-options */
				opts->list_cipher_options = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 45:
				/* list-cipher-options-deps */
				opts->list_cipher_options_deps = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 46:
				/* list-server-db */
				CKINT(convert_show_type(
					optarg, &opts->acvp_ctx_options
							 .show_db_entries));
				break;
			case 47:
				/* search-server-db */
				CKINT(convert_search_type_string(
					optarg, &opts->acvp_server_db_search,
					&opts->search_type));
				break;
			case 48:
				/* fetch-id-from-server-db */
				CKINT(convert_search_type_id(
					optarg, &opts->acvp_server_db_fetch_id,
					&opts->search_type));
				break;
			case 49:
				/* fetch-validation-from-server-db */
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "validation ID too big\n");
					usage();
					ret = -EINVAL;
					goto out;
				}
				opts->acvp_server_db_validation_id =
					(unsigned int)val;

				break;

			case 50:
				/* cipher-options */
				CKINT(duplicate_string(
					&opts->cipher_options_file, optarg));
				break;
			case 51:
				/* cipher-algo */
				CKINT(duplicate_string(
					&opts->cipher_options_algo
						 [opts->cipher_options_algo_idx],
					optarg));
				opts->cipher_options_algo_idx++;
				if (opts->cipher_options_algo_idx >=
				    OPT_CIPHER_OPTIONS_MAX) {
					ret = -EOVERFLOW;
					goto out;
				}
				break;
			case 52:
				/* cipher-list */
				opts->cipher_list = true;
				break;

			case 53:
				/* proxy-extension */
				CKINT(acvp_load_extension(optarg));
				break;
			case 54:
				/* proxy-extension-dir */
				CKINT(acvp_load_extension_directory(optarg));
				break;
			case 55:
				/* rename-version */
				rename->moduleversion_new = optarg;
				opts->acvp_ctx_options.threading_disabled =
					true;
				opts->rename = true;
				break;
			case 56:
				/* rename-name */
				rename->modulename_new = optarg;
				opts->acvp_ctx_options.threading_disabled =
					true;
				opts->rename = true;
				break;
			case 57:
				/* rename-oename */
				rename->oe_env_name_new = optarg;
				opts->acvp_ctx_options.threading_disabled =
					true;
				opts->rename = true;
				break;
			case 58:
				/* rename-procname */
				rename->proc_name_new = optarg;
				opts->acvp_ctx_options.threading_disabled =
					true;
				opts->rename = true;
				break;
			case 59:
				/* rename-procseries */
				rename->proc_series_new = optarg;
				opts->acvp_ctx_options.threading_disabled =
					true;
				opts->rename = true;
				break;
			case 60:
				/* rename-procfamily */
				rename->proc_family_new = optarg;
				opts->acvp_ctx_options.threading_disabled =
					true;
				opts->rename = true;
				break;

			case 61:
				/* register-only */
				opts->acvp_ctx_options.register_only = true;
				break;
			case 62:
				/* register-only */
				opts->acvp_ctx_options.upload_only = true;
				break;
			case 63:
				/* list-purchased-vs */
				opts->list_purchased_vs = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 64:
				/* list-purchase-opts */
				opts->list_available_purchase_opts = true;
				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 65:
				/* purchase */
				lval = strtol(optarg, NULL, 10);
				if (lval == UINT32_MAX || lval <= 0) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "undefined purchase option\n");
					usage();
					ret = -EINVAL;
					goto out;
				}

				opts->purchase_opt = (uint32_t)lval;
				// TODO
				opts->purchase_qty = 1;

				opts->acvp_ctx_options.threading_disabled =
					true;
				break;
			case 66:
				/* ponumber */
				opts->ponumber = optarg;
				break;

			case 67: /* fetch-verdicts */
				/* force the proxy to contact server */
				opts->acvp_ctx_options.resubmit_result = true;
				opts->fetch_verdicts = true;
				break;

			case 68:
				/* request-json */
				opts->request = true;
				snprintf(opts->acvp_ctx_options.caller_json_request,
					 sizeof(opts->acvp_ctx_options.caller_json_request),
					 "%s", optarg);
				opts->acvp_ctx_options.caller_json_request_set =
					true;
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

		case 'c':
			CKINT(duplicate_string(&cred->configfile, optarg));
			break;
		case 'd':
			CKINT(acvp_def_config(optarg));
			modconf_loaded = 1;
			break;

		case 'v':
			logger_inc_verbosity();
			if (logger_get_verbosity(LOGGER_C_ANY) >= LOGGER_DEBUG)
				opts->acvp_ctx_options.threading_disabled =
					true;
			break;
		case 'q':
			logger_set_verbosity(LOGGER_NONE);
			break;
		case 'h':
			usage();
			ret = 0;
			goto out;
			break;

		case 'l':
			dolist = 1;
			break;
		case 'u':
			listunregistered = 1;
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
		default:
			usage();
			ret = -EINVAL;
			goto out;
			break;
		}
	}

	/* Only operate on entropy sources */
	if (opts->esvp_proxy)
		search->with_es_def = true;

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
		    !ask_yes(
			    "Are you sure to perform a forced deletion operation")) {
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

	if (!cred->configfile) {
		if (opts->official_testing) {
			if (opts->amvp_proxy)
				cred->configfile = strdup(
					"amvpproxy_conf_production.json");
			else if (opts->esvp_proxy)
				cred->configfile = strdup(
					"esvpproxy_conf_production.json");
			else
				cred->configfile = strdup(
					"acvpproxy_conf_production.json");
		} else {
			if (opts->amvp_proxy)
				cred->configfile =
					strdup("amvpproxy_conf.json");
			else if (opts->esvp_proxy)
				cred->configfile =
					strdup("esvpproxy_conf.json");
			else
				cred->configfile =
					strdup("acvpproxy_conf.json");
		}
		CKNULL(cred->configfile, -ENOMEM);
	}

	CKINT(load_config(cred));

	return ret;

out:
	free_opts(opts);
	exit(-ret);
}

static int initialize_ctx(struct acvp_ctx **ctx, struct opt_data *opts,
			  const bool enable_net)
{
	const struct opt_cred *cred;
	char *server =
		opts->official_testing ? NIST_DEFAULT_SERVER : NIST_TEST_SERVER;
	unsigned int port = NIST_DEFAULT_SERVER_PORT;
	enum acvp_protocol_type proto = acv_protocol;
	int ret;

	if (opts->esvp_proxy) {
		server = opts->official_testing ? NIST_ESVP_DEFAULT_SERVER :
							NIST_ESVP_TEST_SERVER;
		port = NIST_ESVP_DEFAULT_SERVER_PORT;
		proto = esv_protocol;
	}
	if (opts->amvp_proxy) {
		server = opts->official_testing ? NIST_AMVP_DEFAULT_SERVER :
							NIST_AMVP_TEST_SERVER;
		port = NIST_AMVP_DEFAULT_SERVER_PORT;
		proto = amv_protocol;
	}

	CKINT(acvp_set_proto(proto));

	CKINT(set_totp_seed(&opts->cred, opts->official_testing, enable_net));

	CKINT(acvp_ctx_init(ctx, opts->basedir, opts->secure_basedir));

	cred = &opts->cred;
	/* Official testing */
	if (opts->official_testing) {
		CKINT(acvp_req_production(*ctx));
		if (enable_net)
			CKINT(acvp_set_net(server, port, cred->tlscabundle,
					   cred->tlscakeychainref,
					   cred->tlscert,
					   cred->tlscertkeychainref,
					   cred->tlskey, cred->tlspasscode));
	} else if (enable_net) {
		CKINT(acvp_set_net(server, port, cred->tlscabundle,
				   cred->tlscakeychainref, cred->tlscert,
				   cred->tlscertkeychainref, cred->tlskey,
				   cred->tlspasscode));
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

	if (opts->acvp_ctx_options.register_only) {
		if (!ret) {
			fprintf(stderr,
				"Test definitions registered successfully, do not forget to download them at a later time.\n");
		} else if (ret == -ENOENT)
			ret = 0;

		goto out;
	}

	/* Fetch testID whose download failed */
	// TODO: Maybe store that data for automated resumption of download?
	while (!(ret = acvp_list_failed_testid(&idx, &testid))) {
		if (!printed) {
			fprintf(stderr,
				"Not all testIDs were downloaded cleanly. Invoke ACVP Proxy with the following options to download the remaining test vectors:\n");

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

static int list_missing_certificates(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, false));

	CKINT(acvp_list_missing_certificates(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int list_missing_results(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, false));

	CKINT(acvp_list_missing_results(ctx));

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

	CKINT(acvp_list_certificates_detailed(
		ctx, opts->cert_details_niap_req_file));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_fetch_cipher_options(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_cipher_get(ctx, (const char **)opts->cipher_options_algo,
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

static int do_list_server_db(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_server_db_list(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_search_server_db(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_server_db_search(ctx, opts->search_type,
				    opts->acvp_server_db_search));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_fetch_server_db(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_server_db_fetch_id(ctx, opts->search_type,
				      opts->acvp_server_db_fetch_id));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_fetch_validation_server_db(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_server_db_fetch_validation(
		ctx, opts->acvp_server_db_validation_id));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_sync_meta(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_synchronize_metadata(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_list_purchased_vsids(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_purchase_list_available_vsids(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_list_available_purchased_opts(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_purchase_get_options(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_purchase(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	ctx->req_details.dump_register = opts->dump_register;
	CKINT(acvp_purchase(ctx, opts->purchase_opt, opts->purchase_qty,
			    opts->ponumber));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int do_fetch_verdicts(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	CKINT(initialize_ctx(&ctx, opts, true));

	CKINT(acvp_fetch_verdicts(ctx));

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int esvp_proxy_handling(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

	opts->acvp_ctx_options.esv_certify = opts->publish;

	/*
	 * The ES definitions we operate on have one instance only as read
	 * by definitions.c. Yet they hold the auth token. Thus, we cannot
	 * multi-thread on them. Only if the session-local data are not
	 * stored in the ES definitions any more, we can enable multi-threading.
	 */
	opts->acvp_ctx_options.threading_disabled = true;

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
		CKINT(esvp_continue(ctx));
	} else {
		CKINT(esvp_register(ctx));
	}

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int amvp_do_register(struct opt_data *opts)
{
	struct acvp_ctx *ctx = NULL;
	int ret;

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
		CKINT(amvp_respond(ctx));
	} else {
		CKINT(amvp_register(ctx));
	}

	if (opts->acvp_ctx_options.register_only) {
		if (!ret) {
			fprintf(stderr,
				"Test definitions registered successfully, do not forget to download them at a later time.\n");
		} else if (ret == -ENOENT)
			ret = 0;

		goto out;
	}

out:
	acvp_ctx_release(ctx);
	return ret;
}

static int amvp_do_submit(struct opt_data *opts)
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
	ret2 = amvp_respond(ctx);

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
static int amvp_proxy_handling(struct opt_data *opts)
{
	int ret;

	// TODO - see amvp_set_paths for this limitation
	if (opts->secure_basedir || opts->basedir) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "The AMVP Proxy currently cannot handle setting the basedir/secure_basedir\n");
		return -EOPNOTSUPP;
	}

	if (opts->request) {
		CKINT(amvp_do_register(opts));
	} else {
		CKINT(amvp_do_submit(opts));
	}

out:
	return ret;
}

int main(int argc, char *argv[])
{
	struct opt_data opts;
	const char *basen;
	int ret;

	memset(&opts, 0, sizeof(opts));

	basen = basename(argv[0]);
	CKNULL(basen, -EFAULT);
	if (!strncmp("esvp-proxy", basen, 10))
		opts.esvp_proxy = true;
	if (!strncmp("amvp-proxy", basen, 10))
		opts.amvp_proxy = true;

	macos_disable_nap();

	logger_set_verbosity(LOGGER_ERR);

	CKINT(parse_opts(argc, argv, &opts));

	if (opts.esvp_proxy) {
		ret = esvp_proxy_handling(&opts);
		goto out;
	}
	if (opts.amvp_proxy) {
		ret = amvp_proxy_handling(&opts);
		goto out;
	}

	if (opts.fetch_verdicts) {
		CKINT(do_fetch_verdicts(&opts));
	} else if (opts.list_purchased_vs) {
		CKINT(do_list_purchased_vsids(&opts));
	} else if (opts.list_available_purchase_opts) {
		CKINT(do_list_available_purchased_opts(&opts));
	} else if (opts.purchase_opt) {
		CKINT(do_purchase(&opts));
	} else if (opts.sync_meta) {
		CKINT(do_sync_meta(&opts));
	} else if (opts.acvp_server_db_search && opts.search_type) {
		CKINT(do_search_server_db(&opts));
	} else if (opts.acvp_server_db_fetch_id && opts.search_type) {
		CKINT(do_fetch_server_db(&opts));
	} else if (opts.acvp_server_db_validation_id) {
		CKINT(do_fetch_validation_server_db(&opts));
	} else if (opts.acvp_ctx_options.show_db_entries) {
		CKINT(do_list_server_db(&opts));
	} else if (opts.cipher_list || opts.cipher_options_algo_idx ||
		   opts.cipher_options_file) {
		CKINT(do_fetch_cipher_options(&opts));
	} else if (opts.rename) {
		CKINT(do_rename(&opts));
	} else if (opts.request) {
		CKINT(do_register(&opts));
	} else if (opts.publish) {
		CKINT(do_publish(&opts));
	} else if (opts.list_available_ids || opts.list_pending_request_ids ||
		   opts.list_pending_request_ids_sparse) {
		CKINT(list_ids(&opts));
	} else if (opts.list_verdicts) {
		CKINT(list_verdicts(&opts));
	} else if (opts.list_certificates) {
		CKINT(list_certificates(&opts));
	} else if (opts.list_missing_certificates) {
		CKINT(list_missing_certificates(&opts));
	} else if (opts.list_missing_results) {
		CKINT(list_missing_results(&opts));
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
