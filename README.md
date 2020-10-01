# ACVP Proxy

The ACVP Proxy allows the retrieving of test vectors from the ACVP
servers. In addition, it allows the submission of test results to the ACVP
servers and to retrieve the verdict of the test results.

The obtained test vectors stored in the files `testvector-request.json`
are intended to be transferred to the test system hosting the cryptographic
module to be tested. The JSON file must be inserted into the cryptographic
module to produce the `testvector-response.json` file holding the responses
according to the ACVP protocol specification. An example implementation
that parses these JSON files, invokes the cryptographic implementation
and generates the test response files, see the ACVP Parser.

The ACVP Proxy is proudly supported by [atsec information security corp](https://www.atsec.com).

## Ease of Use

The ACVP Proxy has many options and allows a flexible deployment. However,
the common use case is to (1) fetch test vectors, (2) upload responses,
(3) fetch test verdicts and (4) obtain the certificate.

This use case is encapsulated within the script `helper/proxy.sh`. This
script is intended to be copied out of the source code tree to a directory
where the test vectors and all auxiliary data for one or a groups of IUTs
are maintained. After setting the proper variables in `helper/proxy.sh`
the ACVP Proxy can be used immediately via this script. No manual invocation
with the number of command line options is necessary.

The make system allows to generate a binary distribution by calling
`make binarchive`. If this archive is unpacked directly into `PROXYBINPATH`
as defined by `proxy.sh`, it will be used with priority.

## Interaction of ACVP Proxy and ACVP Parser - First Steps

The ACVP Proxy and the ACVP Parser collaborate in a full ACVP test cycle as
follows.

1. Find the right cipher definition or create a new definition with the
   ACVP Proxy:
   `acvp-proxy -l`

2. Download the ACVP test vectors for the chosen cryptographic module using
   the ACVP Proxy:
   `acvp-proxy -m <cryptomodule> --request`

3. Send the entire testvectors data store to the IUT that is connected with the
   ACVP Parser. You may use the following command:
   `tar -cvzf testvectors-<vendor>-<date>.tar.gz testvectors/`

   You may also create a symbolic link to the testvectors directory from the
   ACVP Parser.

4. Invoke the JSON files in the testvectors directory with the ACVP Parser:
   `acvp-parser testvector-request.json testvector-response.json`

   You may use the helper script helper/exec_*.sh in the ACVP Parser code
   to automate the processing of all JSON files.

5. Load the generated testvector-response.json files into the testvectors/
   data store of the ACVP Proxy. For example:

	a. Create the archive with the responses from ACVP Parser:
	   `tar -cvzf testvectors-<vendor>-response-<date>.tar.gz testvectors/`

	b. Unpack the testvector-responses.json files into the ACVP Proxy
	   testvectors/ directory:
	   `tar -xvzf testvectors-<vendor>-response-<date>.tar.gz *testvector-response.json`

    You may skip this copying business if the ACVP Proxy and ACVP Parser both
    access the very same testvectors directory.

6. Use the ACVP Proxy to submit the test responses and fetch the verdicts.
   `acvp-proxy -m <cryptomodule>`

7. Check the verdict.json file in the testvectors directory for the ACVP
   server verdict.

## Test Publication Phase

When communicating the cipher options, the test vectors and responses and the
test verdicts in the process above, no information about the particular
module like module name or version or vendor details is communicated.

After obtaining the hopefully passing verdict the test session is eligible
for obtaining a certificate (with the production server). For such publication
the ACVP server now must receive all meta data characterizing the product.

Below this README describes how the user shall maintain several JSON files
defining the vendor, the module, and the operational environment. During the
publication phase, the ACVP server is informed about this meta data and it
is associated with the test session. That means that even yet unannounced
products can be tested using the public servers since nobody will be able to
associate the test session with a particular product before the publication
phase.

The publication phase is triggered with the `--publish` option. During the
publication phase, the ACVP proxy will ensure the ACVP server receives the
meta data and then combines it with the test session.

The ultimate result of the publication phase is the creation of the
`testsession_certificate_info.json` file which contains all details about
the certificatication, including the official certificate number.

### Vendor ID / Module ID / Operational Environment ID

To support the publication phase, the ACVP Proxy will add and maintain
various ID entries in the JSON files explained below.

These IDs point to the respective vendor, module or operational environment
information maintained by the ACVP server for the given data set like vendor
or contact person details. These IDs must be used by the ACVP Proxy for the
final publication phase, i.e. when the option `--publish` is used. Before
using them, the ACVP proxy will verify that the IDs still point to the
entry with the same information as given by the JSON files.

If the IDs do not exist in the JSON files, the ACVP Proxy tries to resolve them
by looking up the ACVP server database which may take some time.

In case the specified resource like vendor definition or module definition
is not found, the definition is registered with the ACVP server if the
`--register-definition` option is provided with the `acvp-proxy` tool.

As mentioned, even existing IDs are checked with the ACVP server to verify
the ACVP server still contains the proper information. If it does not
and `--register-definition` is provided, it will request an update of the
ACVP server entry.

If the ACVP proxy identifies it needs to perform a register operation but
the `--register-definition` option is not provided, it will issue a warning
about the needed register operation and terminate. In this case, no add or
update request is sent to the ACVP server.

Please note: if the addition or update request is sent to the ACVP server,
NIST will need to perform a manual step to verify the data. Thus, you MUST
interact with NIST to have the request(s) approved. After the approval process
the publication operation can be invoked again and the ACVP proxy will
now fetch the registered ID information from the ACVP server. If the
request was not yet approved at the time the ACVP proxy shall publish
a particular module, it will identify this scenario and terminate with an
error message.

Note, if you maintain multiple modules which have the same, say, vendor
definition or operational environment definition, and you have the respective
IDs for one module already, you may copy them to the JSON files of the
respective other modules. In this case, the ACVP proxy can skip the resolving
operation that may be lengthy and simply verify the given ID.

## Prerequisites

The code is written in clean and plain C-99 and has the following dependencies:

- POSIX API

- if threading is enabled, support for the POSIX threading API must be present

- SysV message queues if the TOTP server is compiled

Compile-time options can be specified in the `lib/config.h` file.

The ACVP Proxy requires the presence of the following libraries and the
associated header files:

- libcurl (not on macOS)

With these limited prerequisites, the code can be compiled and executed at
least on the following operating systems:

- Linux

- BSDs

- Apple macOS

- MS Windows

- Solaris

## Compilation

The ACVP Proxy is used by compiling the command line configuration
application `acvp-proxy`. This application is compiled by calling make.

To compile the ACVP Proxy standalone shared library, call `make` in the
`lib/` directory.

Compiling with `make debug` allows debugging of the code.

### Building on Windows 10

To compile the tool on Windows 10, perform the following steps as administrator:

- Enable Windows Subsystem for Linux (WSL)

	* In the Windows Settings search box, type: Turn Windows features on or off

	* Select: Windows Subsystem for Linux

- Reboot

In addition, perform the following steps with your normal (developer) account:

- Install "Ubuntu 18.04 LTS" from the Windows Store

- Launch "Ubuntu 18.04 LTS" app to bring up a bash shell. In bash, type:

```
	sudo apt-get update
	sudo apt install gcc
	sudo apt install make
	sudo apt install libcurl4-gnutls-dev
	sudo apt install libssl-dev
	sudo apt-get update

	mkdir src
	cd src
	git clone https://github.com/smuellerDD/acvpproxy
	cd acvpproxy
	make
```

### Building and Execution on Cygwin

The following steps are required to build the ACVP Proxy on Cygwin:

- Verify that the required cygwin packages are installed:

	* gcc

	* make

	* libcurl

	* cygserver

- Build acvp-proxy.exe using make.

For running the acvp proxy, IPC support is enabled by starting the windows
service cygserver by running the following command as administrator under
Cygwin:

`./cygserver-config`

Reply "yes" when asked whether to install cygserver as service. The service
is started with the command:

`net start cygserver`

## Configuration File

The ACVP proxy needs a configuration file as documented in apps/README.md.

## Module Instantiation Configuration

The ACVP Proxy contains the module cipher definition as part of its C code.

However, the instantiation of a particular module cipher definition into a
module is driven by configuration files. With the term instantiation, the
combination of the cipher option with a module information, the operational
environment and the vendor information is referred to.

To instantiate a particular module cipher definition, the ACVP Proxy uses
information provided in a directory `module_definitions` in the current
working directory. A different directory can be provided with a command
line switch.

That directory must have the following structure:

```
<directory>
    |
    \---- oe
    |
    \---- vendor
    |
    \---- module_info
    |
    \---- implementations
```

The `implementations` directory allows the specification of
supported cipher definitions. The C code commonly defines as much cipher
implementations as possible. However, some versions of the module (e.g. older
ones) may not support one or the other cipher definitions. Thus, one or more
JSON files in `implementations` can be defined that only define the supported
cipher definitions.

Each of these directories must have JSON files providing the
module definition. One JSON file holds one definition. It is permissible to
have multiple JSON files in one directory. The ACVP Proxy will instantiate the
module with all permutations of oe/vendor/module_info definitions that it
finds.

The JSON files in the `oe` directory must contain the following JSON keywords:

* `oeEnvName`: Name of the operation environment (such as operating system and
  its version) - it is allowed to be a JSON "NULL" value if the operating
  system information is not required (i.e. if the platform is HW)

* `cpe`: CPE tag (may be non-existant if `swid` exists)

* `swid`: SWID tag (may be non-existant if `cpe` exists)

* `oe_description`: Description of the operational environment

* `manufacturer`: Manufacturer of the underlying CPU executing the module.

* `procFamily`: Processor family executing the module. Note, this string must
  match one `processor` of the module cipher definitions registered with the
  ACVP Proxy. See `acvp-proxy -u` for details. If the list contains an
  empty string for the processor, the JSON are not restricted in the processor
  information.

* `procFamilyInternal`: This is an optional keyword that if present is used to
  resolve the uninstantiated definitions. It is not used for anything else.
  Its purpose is to support private ACVP Proxy extensions with slight
  derivations from ACVP Proxy built-in definitions.

* `procName`: Specific processor name executing the module.

* `procSeries`: Processor series executing the module.

* `features`: Feature defined by an OR of the `OE_PROC_*` definitions.

* `envType`: Type of the execution environment which is a selection from
  `enum def_mod_type`. Instead of a numeric value, the following values are
   equally allowed: `Software`, `Hardware`, `Firmware`.

* `dependencies-internal`: This keyword is optional. For details, see section
  about automated dependency handling.

* `dependencies-external`: This keyword is optional. For details, see section
  about manual dependency handling.

The JSON files in the `vendor` directory must contain the following JSON
keywords:

* `vendorName`: Company name of the vendor.

* `vendorUrl`: URL of the company.

* `contactName`: Name of the contact person at the vendor.

* `contactEmail`: Email address of the vendor's contact person.

* `dependencies-internal`: This keyword is optional. For details, see section
  about automated dependency handling.

* `dependencies-external`: This keyword is optional. For details, see section
  about manual dependency handling.

The JSON files in the `module_info` directory must contain the following JSON
keywords:

* `moduleName`: Free-form name of the module. Note, this name must be identical
  to the cryptographic definitions name found in the variable `algo_name` that
  can be obtained with `acvp-proxy -u`.
  Note, when instantiating the module, that string is appended by the module
  crypto definition detailed reference specified with the variable `impl_name`
  found in the C code defining the cryptographic implementation. That
  implementation name can be shown with `acvp-proxy -u`.

* `moduleNameInternal`: This is an optional keyword that if present is used to
  resolve the uninstantiated definitions. It is not used for anything else.
  Its purpose is to support private ACVP Proxy extensions with slight
  derivations from ACVP Proxy built-in definitions.

* `moduleVersion`: Version number of the module.

* `moduleDescription`: Free-from description of the module.

* `moduleType`: Type of the module which is a selection from
  `enum def_mod_type`.

* `dependencies-internal`: This keyword is optional. For details, see section
  about automated dependency handling.

* `dependencies-external`: This keyword is optional. For details, see section
  about manual dependency handling.

The JSON files in the `implementations` directory must contain the following
JSON keywords:

* `implementations`: This keyword must point to an array or one or more
  supported names which match the `impl_name` variable in the algorithm
  definitions of the C code.

* `dependencies-internal`: This keyword is optional. For details, see section
  about automated dependency handling.

* `dependencies-external`: This keyword is optional. For details, see section
  about manual dependency handling.

## Dependency Handling

Some cipher algorithm testing requires that subordinate ciphers are tested
as well. These subordinated ciphers must be announced to the ACVP server.

For example, when testing a Hash DRBG, the SHA cipher must be tested as well.

Usually it is common that such dependencies are provided with the same test
session. For example, you define the Hash DRBG and the supporting SHA cipher
for the same test session. In some cases that is either not desired or not
possible.

The ACVP Proxy supports the dependency handling. The following two cases are
possible:

* Internal dependencies: The IUT implements the depending cipher, but it is
  tested with a different test session. Both test sessions are executed
  for the same IUT module, version and operational environment. In this case,
  the ACVP Proxy is able to automatically resolve the dependencies and announce
  the correct dependencies to the server. For details see the following section
  about automated dependency handling.

* External dependencies: If a depending cipher is not provided by the IUT,
  the ACVP Proxy allows the user to specify the certificate number. The
  ACVP Proxy will announce the certificate reference to the ACVP server. For
  details, see the following section about manual dependency handling.

### Automated Dependency Handling

The ACVP Proxy supports automated dependency handling by inserting the newly
obtained ACVP certificate ID as a dependency for another cipher. This alleviates
the user from manually juggling dependencies of cipher definitions as mandated
by the ACVP protocol.

For example, you define an FFC DH cipher for one test session which requires
a DRBG and a SHA dependency. The DRBG and SHA tests are provided with another
test session. Instead of manually track these dependencies and fill in newly
obtained certificates into the FFC DH definition, the ACVP Proxy can do that
for you.

The ACVP Proxy requires that the automated dependency resolution is confined
to one IUT only. I.e. if you, say, have OpenSSL with multiple different
test sessions defined, you can define inter-dependencies between these
test sessions. Though, the ACVP Proxy does not allow you to define one
dependency from OpenSSL to another IUT such as the Linux kernel. If you have
such dependencies, you still must manually track those.

To inform the ACVP Proxy about dependencies, the configuration file in the
`implementations`, `oe`, `vendors` and/or `module_info` directories may contain
the keyword `dependencies-internal`. This keyword points to an object listing
all implementation references and their dependencies. For example, the following
`implementations` file illustrates the use:

```
{
	"implementations": [
		"SP800-38A AES Implementation with DRBG",
		"SP800-38D GCM Implementation",
	],

	"dependencies-internal": {
		"SP800-38D GCM Implementation": {
			"AES": "SP800-38A AES Implementation with DRBG",
			"DRBG": "SP800-38A AES Implementation with DRBG"
		},
	}
}
```

This example defines two different cipher implementations.
"SP800-38A AES Implementation with DRBG" provides AES-ECB, AES-CBC and a
CTR-DRBG. "SP800-38D GCM Implementation" defines AES-GCM with random IV
generation which based on the ACVP protocol has a dependency to the underlying
AES and to the DRBG. With the `dependencies`, an dependency entry for these
two dependencies from "SP800-38D GCM Implementation" to
"SP800-38A AES Implementation with DRBG" is defined.

It is permissible to specify a substring when referencing to a depending
definition as it is visible in the example above for the `AES` dependency.
In case the substring will resolve to more than one definition the ACVP Proxy
will match the first one.

During the resolution of dependencies, the ACVP Proxy will make sure that
dependencies apply to the same vendor, execution environment, processor,
module name and module version. For example, if you have a module definition
with two operational environments in the `oe` module instantiation, the ACVP
Proxy will automatically ensure that a module definition for the same
operational environment is used to fulfill the dependency.

During publication phase, both implementations are published in unison.
However, when the final certificate request is made, the GCM implementation
will not be registered for a certificate unless the certificate for the
AES implementation is awarded. Once the AES implementation certificate is
available, the certificate number is used to announce the dependency during
the GCM implementation certificate request.

Besides the initial definition of the dependencies, you do not need to
manually track these dependencies any more.

### Manual Dependency handling

In case the ACVP Proxy is unable to resolve a dependency within an IUT,
the user is allowed to specify dependencies to existing certificates.

The configuration is almost identical to the automated dependency handling
except that instead of the pointer to the internal implementation,
a pointer to the existing certificate is provided.

For example, the following configuration for `oe` illustrates the approach:

```
{
        "oeEnvName": "My Module",
        "cpe": "some_cpe",
        "manufacturer": "Intel",
        "procFamily": "X86",
        "procName": "i7",
        "procSeries": "Broadwell",
        "features": 7,
        "envType": 2,
        "dependencies-external": {
                "SP800-38D GCM Implementation": {
                        "DRBG": "DRBG 1234"
                },
        }
}
```

This configuration adds the dependency for GCM for DRBG to the DRBG
certificate `DRBG 1234` for all test sessions covering the execution environment
specified with the `oe` configuration file.

## Usage

The ACVP Proxy has the following use cases:

- The retrieval of test vectors from ACVP is the first use case. This use case
  is invoked by using the command line option of `--request`. The test vectors
  are stored in local directory documented below.

- The submission of test results to ACVP and the fetching of the ACVP verdict
  for the test results is invoked by using the command line option of either
  `--vsid <VSID>` or `--testid <TESTID>`.

- Register the meta information about the module with the ACVP server, including
  vendor information, module information and operational environment
  information.

- Request the publication of the completed ACVP testing cycle to obtain an
  ACVP certificate.

NOTE: If neiter `--request`, nor `--vsid <VSID>` or `--testid <TESTID>` is
specified, the application will try to send out all existing test results
which have not yet been submitted and obtain a verdict for them.

## Signals

The ACVP Proxy supports the following signals:

* SIGHUP, SIGINT, SIGTERM: Stopping any outstanding requests and deleting the
  outstanding requests at the ACVP server (invoke the DELETE operation
  on the test session URL). The ACVP server is intended to cleanup all
  reference to the test session preventing any later retrieval.

* SIGSTOP (commonly CTRL+\ ): Stopping any outstanding requests without
  deleting them on the ACVP server. This allows terminating the network
  connection and allow the retrieval of the test vector at a later time.
  Usually this is helpful if the ACVP server takes a long time where you
  do not want the ACVP Proxy to constantly retry downloading the vector. To
  resume the download of the test vectors, use `--request --testid <NUM>`
  where `<NUM>` is the test session ID printed out by the ACVP Proxy when
  receiving SIGSTOP.

The stopping and restarting of downloads applies to the download of
testvectors (i.e. when --request is used) as well as to the download of
verdicts after the upload of the test responses.

## Register Test Sessions Only

Downloading test vectors may take some time. As outlined above, SIGSTOP can
be used to interrupt an ongoing download. In addition, the ACVP Proxy allows
registering cipher definitions only, i.e. without starting the download
of the test vectors. This is akin to the regular operation but sending a
SIGSTOP signal right after all register operations complete.

At a later time, the ACVP Proxy can be used to fetch the test vectors. Note,
the ACVP Server will produce the test vectors during that time which implies
that once the test vector download is triggered, the wait time is likely to
be reduced significantly.

At the conclusion of the register-only operation, the ACVP Proxy will
list the command line options to be used again for triggering the download
of the registered test sessions.

## Directory Structure To Maintain Test Vectors and Test Results

The test vectors and results are stored in the directories with the following
structure: `testresults/<Module_Name>/<Module_Version>/<testsessionID>/<vsID>`.

The `<Module_Name>/<Module_Version>` directory refers to the name and version
of the cryptographic module under test.

The `<testsessionID>/<vsID>` is a unique number provided by the ACVP server
for the respective test. This test session ID and vsID are the unique
references for subsequent data exchange with the ACVP server regarding the
particular obtained test vector.

In each `<testsessionID>/<vsID>` directory, the following files can be found,
depending on the state of the communication with the ACVP server.

- `testvector-request.json`: Test vector to be processed by the module
  implementation.

- `testvector-response.json`: The test results returned by the module
  implementation must be provided in this file.

- `verdict.json`: After submission of the test results to the ACVP server, the
  test verdict is provided in this file.

- `processed.txt`: This file contains the time stamp when the test results
  were sent to the ACVP server and the verdict was received. Once this file
  is present, the ACVP Proxy will not submit the test results again.

In addition to the `testresults` directory, a shadow `secure-datastore` is
maintained with the same directory structure. That shadow directory contains
internal or sensitive data as follows:

- `jwt_authtoken.txt`: JWT authorization token required for authentication
  with the ACVP server when exchanging subsequent messages for the vsID.

- The `*.debug` files contain the respective server responses allowing to
  debug network communication problems. These files are not processed by
  the ACVP Proxy.

- The `request-<DATE>.json` file contains the IUT register data sent to
  the ACVP server for requesting test vectors.

- The `testid_metadata.json` file contain the initial response from the
  ACVP server indicating the number of vsIDs as well as the testID
  with their URLs.

## FIPS 140-2 Compliance

The ACVP Proxy uses the following cryptographic support:

- TLS: This is provided by the TLS implementation used by CURL. Commonly this
  is provided by either OpenSSL or NSS. On macOS, the native TLS provider is
  used which in turn uses the FIPS 140-2 validated Corecrypto library for
  the cryptographic support. Those libraries are FIPS 140-2 validated
  and thus should be used according to the security policy.

- TOTP: HMAC SHA-256 is used as the cipher for the TOTP operation.
  This implies that the ACVP Proxy implements a FIPS 140-2 cipher which must
  be subject to the power on self test. The known answer test for the
  HMAC SHA-256 is always executed. The integrity test is executed when
  the environment variable ACVPPROXY_FORCE_FIPS is set (or on Linux, when
  /proc/sys/crypto/fips_enabled contains a 1). In this case the integrity
  check with HMAC SHA-256 is enforced where the HMAC control file is
  searched in the same directory as the ACVP Proxy executable. When the
  HMAC control file does not exist, it is created.

## Search the ACVP Server Database

The ACVP Proxy offers a frontend to search the server database with all
module meta data. The search is based on the search string defined in
section 11.6 of the [ACVP specification](https://github.com/usnistgov/ACVP/blob/master/artifacts/draft-fussell-acvp-spec-00.txt).

To indicate which object to search for, the search type must be specified
with one of the following:

* `vendor`

* `address`

* `persons`

* `oe`

* `module`

* `dependency`

The search type must be followed by the query string compliant to the ACVP
specification 11.6 delimited with a colon.

For example, the following string searches the ACVP server meta data base
for the person called "John Doe".	

  `acvp-proxy --search-server-db "person:fullName[0]=contains:John Doe"`

# Architecture of ACVP Proxy

The ACVP Proxy contains of the following components:

- A small wrapper application allowing the user to provide command line
  options. This wrapper application does not contain any of the ACVP Proxy
  logic and can be replaced using the API of the library mentioned below.

- The libacvpproxy.so library implements the ACVP Proxy logic. It
  exports an API in `acvpproxy.h` that can be used by a wrapping
  application.

## ACVP Proxy Library

The ACVP Proxy library provided in the `lib/` directory contains the heavy
lifting. This library also contains an internal structure. The core ACVP
protocol handling uses the following extensions which can be replaced with
a respective different implementation:

- A network access backend implements the communication provider. The ACVP
  server requires HTTPS support which implies that the communication provider
  must implement HTTPS. The network access backend is provided by
  implementing the callbacks specified in `struct acvp_netaccess_be`. An
  example implementation based on libcurl is provided in
  `network_backend_curl.c`.

- A datastore backend implements the storage of the data retrieved from the
  ACVP server or must provide the data to be sent to the ACVP server. The
  datastore backend implements the callbacks defined by
  `struct acvp_datastore_be`. The example implementation storing the data
  in directories as outlined above is provided in `datastore_file.c`.

- The JSON request generators for the different cipher types are implemented
  in the files `request_sym.c` and similar. To add a new generator for a new
  cipher type, create a data structure to hold all options in `definition.h`
  (like `struct def_algo_sym`) add add it to `struct def_algo` along with a new
  identifier. Finally, the entry function to the new generator must be
  invoked in the function `acvp_req_set_algo`. The JSON generator shall
  implement the generation of one entry for a particular cipher request only.

- A definition for a particular module holds all supported cipher options.
  Such a definition instantiates the data structures defined by the different
  JSON generators. One example for such a definition is provided in
  `definition_impl_openssl.c`. Each definition must have a unique module name
  and version combination to allow a user to point to it.

## Threading Support

Using the PTHREAD library support, threading is implemented. Concurrent
threads are supported for the following operations:

- Downloading of the test vectors: The test vectors of each individual vsID are
  downloaded in a separate thread.

- Uploading of test responses and downloading the associated verdicts for
  each testsession ID and the assoicated vsID.

## Debugging

Compile with `make debug` to compile debug symbols for debugging.

# Addition of New Cipher Implementation Definitions

The library is written such that new cipher implementations can be added to
generate the required register information with the CAVS servers.

## Registering

A new cipher implementation is registered with the library using the API call
of `acvp_register_algo_map`. This call should be made during the initialization
of the library.

To allow isolating the module definition code into one C file, it is
permissible to invoke the `acvp_register_algo_map` function from a constructor.
For example, the following function is invoked autonomously from the loader
of the library and does not require any changes to the library code itself
in order to register the module specification:

```
ACVP_DEFINE_CONSTRUCTOR(libgcrypt_register)
static void libgcrypt_register(void)
{
	acvp_register_algo_map(libgcrypt_algo_map,
			       ARRAY_SIZE(libgcrypt_algo_map));
}
```

## Defining of Cipher Implementation Capabilities

The function `acvp_register_algo_map` requires a completely defined data
structure tree which contains all details of the cipher implementation. Thus,
for a new cipher definition, all data structures starting with struct
definition must be filled in corresponding to the implementation details.

The header files defining the data structures contain the documentation how
the data needs to be filled in.

## Out-of-tree Management

It is permissible that the cipher implementations are maintained out-of-tree
to the ACVP Proxy. In this case the C file needs the following extensions
at the very end with the example from above:

	ACVP_EXTENSION(libgcrypt_algo_map)

This C file needs to be compiled as a shared library. The example Makefile
`helper/Makefile.out-of-tree` may be used for that. When compiling this
file, it needs ACVP Proxy header files. This implies that the CFLAGS
variable needs to contain
`-I<PATH_TO_ACVPPROXY_SOURCE>/lib -I<PATH_TO_ACVPPROXY_SOURCE>/lib/module_implementations`.
In addition, the compilation must enable the following definition using
CFLAGS: `-DACVPPROXY_EXTENSION`.

Once the shared library is compiled, it can to be referenced with the
ACVP Proxy command line option `--proxy-extension`.

# Supported Ciphers

The following ciphers are supported by the ACVP Proxy to obtain test vectors
and relay responses.

## Block Cipher Modes
* AES-CBC
* AES-CFB1
* AES-CFB8
* AES-CFB128
* AES-CTR
* AES-ECB
* AES-GCM
* AES-GCM-SIV
* AES-KW
* AES-KWP
* AES-OFB
* AES-XPN
* AES-XTS
* AES-FF1
* AES-FF3-1
* TDES-CBC
* TDES-CBCI
* TDES-CFBP1
* TDES-CFBP8
* TDES-CFBP64
* TDES-CTR
* TDES-ECB
* TDES-KW
* TDES-OFB
* TDES-OFBI

## Secure Hash
* SHA-1
* SHA-224
* SHA-256
* SHA-384
* SHA-512
* SHA-512/224
* SHA-512/256
* SHA3-224
* SHA3-256
* SHA3-384
* SHA3-512
* SHAKE-128
* SHAKE-256

## Message Authentication
* AES-GMAC
* AES-CCM
* CMAC-AES
* CMAC-TDES
* HMAC-SHA-1
* HMAC-SHA2-224
* HMAC-SHA2-256
* HMAC-SHA2-384
* HMAC-SHA2-512
* HMAC-SHA2-512/224
* HMAC-SHA2-512/256
* HMAC-SHA3-224
* HMAC-SHA3-256
* HMAC-SHA3-384
* HMAC-SHA3-512

## DRBG
* ctrDRBG-AES-128
* ctrDRBG-AES-192
* ctrDRBG-AES-256
* ctrDRBG-TDES
* HASH DRBG
* HMAC DRBG

## Digital Signature
* RSA mode: keyGen
* RSA mode: sigGen
* RSA mode: sigVer
* RSA mode: signaturePrimitive
* RSA mode: decryptionPrimitive
* RSA mode: legacySigVer
* ECDSA mode: sigGenComponent
* ECDSA mode: keyGen
* ECDSA mode: keyVer
* ECDSA mode: sigGen
* ECDSA mode: sigVer
* DSA mode: keyGen
* DSA mode: sigVer
* DSA mode: sigGen
* DSA mode: pqgGen
* DSA mode: pqgVer
* EDDSA mode: keyGen
* EDDSA mode: keyVer
* EDDSA mode: sigGen
* EDDSA mode: sigVer

## Key Agreement
### Full KAS Testing
* KAS ECC ephemeralUnified
* KAS ECC fullUnified
* KAS ECC onePassDh
* KAS ECC OnePassUnified
* KAS ECC staticUnified
* KAS FFC dhHybrid1
* KAS FFC dhEphem
* KAS FFC dhHybridOneFlow
* KAS FFC dhOneFlow
* KAS FFC dhStatic
* KAS ECC ephemeralUnified Sp800-56Ar3
* KAS ECC fullUnified Sp800-56Ar3
* KAS ECC onePassDh Sp800-56Ar3
* KAS ECC OnePassUnified Sp800-56Ar3
* KAS ECC staticUnified Sp800-56Ar3
* KAS FFC dhHybrid1 Sp800-56Ar3
* KAS FFC dhEphem Sp800-56Ar3
* KAS FFC dhHybridOneFlow Sp800-56Ar3
* KAS FFC dhOneFlow Sp800-56Ar3
* KAS FFC dhStatic Sp800-56Ar3
* KAS IFC KAS1-basic
* KAS IFC KAS1-Party_V-confirmation
* KAS IFC KAS2-basic
* KAS IFC KAS2-bilateral-confirmation
* KAS IFC KAS2-Party_U-confirmation
* KAS IFC KAS2-Party_V-confirmation
* KTS IFC KTS-OAEP-basic
* KTS IFC KTS-OAEP-Party_V-confirmation

### KAS SSC Testing
* KAS ECC ephemeralUnified
* KAS ECC fullUnified
* KAS ECC onePassDh
* KAS ECC OnePassUnified
* KAS ECC staticUnified
* KAS ECC CDH-Component
* KAS FFC dhHybrid1
* KAS FFC dhEphem
* KAS FFC dhHybridOneFlow
* KAS FFC dhOneFlow
* KAS FFC dhStatic
* KAS ECC SSC ephemeralUnified Sp800-56Ar3
* KAS ECC SSC fullUnified Sp800-56Ar3
* KAS ECC SSC onePassDh Sp800-56Ar3
* KAS ECC SSC OnePassUnified Sp800-56Ar3
* KAS ECC SSC staticUnified Sp800-56Ar3
* KAS FFC SSC dhHybrid1 Sp800-56Ar3
* KAS FFC SSC dhEphem Sp800-56Ar3
* KAS FFC SSC dhHybridOneFlow Sp800-56Ar3
* KAS FFC SSC dhOneFlow Sp800-56Ar3
* KAS FFC SSC dhStatic Sp800-56Ar3
* KAS IFC SSC KAS1 Sp800-56Br2
* KAS IFC SSC KAS2 Sp800-56Br2

### KAS KDF Testing SP800-56Cr1

* KAS KDF HKDF Sp800-56Cr1
* KAS KDF OneStep Sp800-56Cr1
* KAS KDF TwoStep Sp800-56Cr1

## KDFs
* Counter KDF
* Feedback KDF
* Double Pipeline Iterator KDF
* IKEv1
* IKEv2
* SSH
* TLS
* TLS v1.3
* PBKDF

## Safe Primes
* SafePrimes KeyGen
* SafePrimes KeyVer

## Conditioning Components
* ConditioningComponent AES-CBC-MAC
* ConditioningComponent BlockCipher_DF
* ConditioningComponent Hash_DF

# Author

Stephan Mueller <smueller@chronox.de>
Copyright (C) 2018 - 2020

