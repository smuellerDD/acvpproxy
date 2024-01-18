v1.8.1:
- fix: rename now works for multiple test sessions
- enhancement: leancrypto - add EDDSA
- Update DRBG numbers to be consistent with spec
- Support SHA-3-based DRBGs and test using OpenSSL 3
- Support HKDF SP 800-56Cr2 and add to OpenSSL
- Add SP 800-108r1 KMAC KBKDF to OpenSSL 3.1 and above
- Support SP 800-108r1 KMAC KBKDF
- Add EdDSA to OpenSSL
- Fix bitwise checks across various algorithms
- Add option to set customKeyInLength for KBKDF
- fix handling of OE type processing
- Support RSA Signature Component revision 2.0
- fix rename for multiple sessions
- update RSA decprim with fixed pub exp mode
- OpenSSL 3 supports KAS2

v1.8.0
- fix: ESV register multiple OEs in one certify operation
- enhancement: AMVP client working as of Hackathon Mid Aug 2023

v1.7.8
- enhancement: add --list-missing-certificates
- enhancement: add --list-missing-results
- enhancement: add Key: sdType to esvp-proxy supporting document upload
- enhancement: add upload of multiple EAs with one ESVP certify request
- fix: add hOut entropy source handling
- bug fixes

v1.7.7
- enhancement: add KTS-SSC to Linux kernel
- enhancement: update ESV implementation to match latest definitions
- enhancement: add leancrypto definition

v1.7.6
- fix: revert switch threading from poll to push wait - makes problems on macOS
- enhancement: as requested by NIST: KAS-KDF -> KDA
- enhancement: streamline kernel crypto API DRBG
- enhancement: KTS-SSC for libgcrypt
- Linux kcapi definitions updated: we only have RSA sigver and RSA primitives

v1.7.5
- enhancement: switch threading from poll to push wait
- fix: --sync-meta OE: first check deps followed by OE
- enhancement: separate OpenSSL ECC K/B curves out
- enhancement: add ICC
- enhancement: add ANSI X9.63 support

v1.7.4
- fix: conditioning component definition: derived_len -> payload_len to match documentation
- fix: use XTS protocol version 2.0 as default
- fix: use SHA-3 protocol version 2.0
- fix: use RFC7627 definition for TLS1.2 - NOTE: you now must use the definition of DEF_ALG_TYPE_KDF_TLS12 for TLS1.2 - all other configs can remain unchanged
- enhancement: in case of an error, the offending code line is always printed in the debug log
- fix: update NIST certificate in certs/
- fix: compilation of lib/

v1.7.3
- enhancement: only update meta data on server that has changed
- enhancement: add POWER for KCAPI, OpenSSL, libgcrypt, GnuTLS, NSS
- enhancement: add ARM to NSS
- fix: allow undefined region definition for addresses
- enhancement: add TPM KDF support
- enhancement: add OpenSSL 3.0.0 definitions

v1.7.2
- enhancement: add CTS to NSS
- fix: --fetch-validation-from-server-db uses OE config file version 2
- enhancement: add CLiC
- add ESVP /certify endpoint handling
- enhancement: add SP800-56C rev 2 support
- enhancement: add complete LRNG test definition

v1.7.1
- enhancement: PSS definition for GnuTLS
- enhancement: KBKDF definition for NSS
- fix: FIPS 186-2 legacy sigver request
- enhancement: Verify that the certificate used to create the JWT is also used for uploading the date
- fix: sometimes empty ACVP definitions are shown - this is now fixed
- fix: support OE definition without dependencies (just define "oeDependencies" = [])
- ESVP tool: first successful upload of data
- enhancement: add cryptographic POST

v1.7.0
- enhancement: add --fetch-id-from-server-db to allow fetching the ACVP server DB data for the given ID
- enhancement: add --fetch-validation-from-server-db allowing to provide a validation ID which is used to query the ACVP server DB to populate a full module_definitions/<dir> directory which can immediately be used for ACVP Proxy operations on the meta data
- enhancement: NSS, libgcrypt, OpenSSL - provide a fully working RSA OAEP test definition
- enhancement: add --fetch-verdicts to get the current verdicts from the ACVP server - this option can be used to refresh a vsID against deletion after 30 day of inactivity
- enhancement: AES-XTS support for specification version 2.0
- enhancement: CTR mode: add support for requesting RFC3686 compliant vectors
- enhancement: add saltLen support to 56Cr1
- enhancement: Support arbitrary number of CPU/SW definitions (potential ACVP server issue relevant here: issue #65)
- apply clang-format with Linux kernel formatting
- enhancement: add --upload-only option and modify proxy.sh post to operate asynchronously: the first invocation simply uploads the test vectors and the second invocation downloads the verdicts.

v1.6.2
- enhancement: add payment options --list-purchased-vs, --list-purchase-opts, --purchase
- fix: Various cipher definition updates

v1.6.1
- enhancement: add definitions for Jitter RNG
- fix: add specification of public exponent definition for RSA signature primitive
- enhancement: add NSS and GnuTLS TLS v1.3 test definitions

v1.6.0
- enhancement: add DEF_ALG_SYM_CTRINCREMENT_DISABLE
- enhancement: add check to verify appropriateness of test vectors to proxy-lib.sh
- enhancement: proxy.sh get now is asynchronous
- enhancement: add --sync-meta to just synchronize the local and server meta data without pending test sessions
- enhancement: add ECDH / ECDSA for CPACF
- enhancement: add HKDF testing support
- enhancement: add KAS-IFC-SSC support
- fix: update KAS-IFC definition to match the ACVP server
- enhancement: add SP800-90B Conditioning Component request capability
- enhancement: add SP800-56A rev 3 to OpenSSL, CoreCrypto, NSS, GnuTLS, Linux kernel
- enhancement: add conditioning function support
- fix: DRBG definition only supports max 4096 bits request size
- enhancement: add onestep and twostep KDF standalone tests
- enhancement: replace HMAC/Hash implementation with self-written code - ACVP certificate number A770
- enhancement: add TLS v1.3

v1.5.2
- fix segfault with --cipher-list
- fix format string usage as indicated with __attribute__((format()))
- fix race in creating a database
- fix HMAC SHA2-512/224 and /256

v1.5.1
- fix: add definitions for CFBP and OFBI TDES ciphers to definition_impl_common.h
- fix: add KAS SSC cipher listing
- fix: allow definition of TDES DRBG

v1.5.1
- fix: allow NULL phoneNumber
- fix: keyword for next pointer in the paging searches changed on the server
- fix: convert server-provided paging URLs to HTML-clean URLs
- fix: locking bug that bites when automated certificate handling is employed

v1.5.0
- enhancement: envType can hold a numeric environment ID reference from enum def_mod_type or one of the strings Hardware, Software, Firmware
- enhancement: add logic for tracking and enforcing versioning of extensions
- fix: prevent asking question for registration twice
- enhancement: add support for refresh of multiple JWT with one login providing a massive performance boost to submissions of test responses and publication
- fix: force a JWT refresh if authentication error was received
- enhancement: add KAS-ECC-SSC and KAS-FFC-SSC
- enhancement: RSA - add DEF_ALG_RSA_PSS_SALT_VALUE to set a specific salt length value
- enhancement: add --list-cert-niap to provide a listing of the available certificates limited to only the ciphers and their implementations of interest - this shall aid the CC evaluations
- enhancement: --rename* now also cause the rename of the corresponding entry in the configuration files
- enhancement: use interactive mode during publishing when ACVP server database does not match local data and --register-definition is not set
- fix: add tests for KAS_FFC|ECC SP800-56A rev 3
- fix: add tests for safeprimes SP800-56A rev 3
- fix: add tests for KAS_FFC|ECC_SSC SP800-56A rev 3
- fix: add tests for KAS_IFC SP800-56B rev 2
- fix: update dependency listing parsing for /oes/<ID> for new web frontend
- enhancement: use link-time-optimizations
- enhancement: add --list-server-db
- enhancement: add --search-searver-db
- fix: update PBKDF request to new server structure

v1.4.0
- add --proxy-extension-dir
- enable modularized compilation
- bug fix: generation of cipher listing in SP800-108 KDF
- bug fix: libgcrypt hash/hmac DRBG SHA-512 added
- bug fix: disable threading for publication operation
- enhancement: only require the presence of the key / seed data if a network operation is to be performed
- SEP: remove HMAC DRBG, RSA keygen
- enhancement: allow parallel execution of production and demo ACVP Proxy execution
- fix: deactivate large endpoint handling as new ACVP server frontend does not need it
- fix: listing of ciphers modified to new ACVP server structure
- enhancement: --sample is now allowed to be used during posting of results or resubmitting results (--resubmit-result) showing the expected result for the failures
- enhancement: add .impl_description to struct def_algo_map to allow specific implementation descriptions to be mentioned on the certificate
- enhancement: speed-up of authentication: re-use of initial login token
- fix: OpenSSL ARM definitions
- code restructuring: consolidate ACVP meta data handling

v1.3.2
- NSS: CMAC not supported
- add CPACF
- bug fix to make option --vsid work again
- OpenSSL: add safeprime keygen test
- Corecrypto: add safeprime keygen test
- macOS: log HTTP error return data

v1.3.1
- GnuTLS: add XTS
- update --list-cert-details output to match structure required by NIST
- add --list-cipher-options
- add --list-cipher-options-deps
- get SP800-56A rev3 ECC/FFC and SP800-56B rev2 IFC working after update on the ACVP server side
- add maclen configuration support to CMAC / HMAC

v1.3.0
- add --rename-procname, --rename-procseries, --rename-procfamily
- add SP800-56A rev3 registration capabilities
- add SP800-56A rev3 safe primes registration capabilities
- addition of sanity checks of cipher definitions
- add --list-cert-details
- add --testid -1 support to download all pending testIDs
- add --logfile
- add vsID and test session ID to logging information
- add SP800-56B rev2 registration capabilities
- add automated dependency handling - see README.md section "Automated Dependency Handling"
- add manual dependency handling - see README.md section "Manual Dependency Handling"
- add --list-request-ids-sparse to make life for NIST easier

v1.2.5
- reenable SIGQUIT signal handling
- prevent crash in signal handler
- kcapi: add CTS
- common cipher definition: converted all cipher definition to Domain definitions
- add libica
- add S390/ARM64 support for: kcapi, OpenSSL, GnuTLS, libgcrypt
- add support for multiple cipher implementations in libgcrypt
- add --register-only option to only register a new cipher definition without downloading the test vectors

v1.2.4
- OpenSSL: Add ECC CDH, ECDH with P224, add P224 to ECDSA siggen/sigver
- bug fix for macOS: allow CA certificate file (a bug did not allow a file, but only a keychain entry)
- bug fix: prevent displaying of user passcode in debug log
- Apple corecrypto: add ECDH P224 and P521, CMAC
- bug fix: reenable TOTP server which was accidentally disabled with the last patch
- fix: do not store an artificial status verdict any more

v1.2.3
- enhancement: add Apple keychain support - server CA and client cert/key can be stored in keychain (see apps/README.md for details on the configuration)

v1.2.2
- enhancement: TOTP MQ facility is now is implemented with full scalability to support arbitrary numbers of threads
- enhancement: add native Apple networking support
- enhancement: add procFamilyInternal support
- enhancement: add RSA PSS, X9.31 and PQGGen (SHA384/SHA512) for OpenSSL
- add helper/acvpkeys

v1.2.1
- fix documentation as complained by clang
- add "status" to proxy-lib.sh showing the verdicts, request IDs and certificates
- add --rename-version
- add --rename-name
- add --rename-oename
- add moduleNameInternal support
- fix: reenable large file support as it is required for files > 4MB (e.g. GCM responses) - issue 755 still discusses the issue of SHAKE uploads
- add --delete-test allowing the deletion of the vsId in the search scope from the test session

v1.2.0
- add IKEv1 and IKEv2 to NSS
- add GET /validations/<certificateId> when having certificateId available -
  the result is stored in testsession_certificate_info.json
- add CFB8, shake to libgcrypt
- fix: JWT can be larger than 1024 bytes - the proxy now has a maximum size of
  16384 bytes
- replace --publish-prereqs with --no-publish-prereqs: Per default, the
  prerequisites are sent during publication. The submission can be prevented
  with this option. This is currently disabled due to issue #749.
- apply the currently applicable JSON format for prerequisites during
  publicationss
- if oeEnvName is set to the NULL JSON data type, the OE is not registered with the module (e.g. relevant for hardware modules)
- do not enforce the presence of SWID or CPE
- fix: complete new register operation now uses correct URL
- add --list-certificates to provide a listing of all received certificate
  numbers
- add listing of received certificates to --list-verdicts
- isolate SHA-3 into separate test session for OpenSSL
- add --version-numeric
- add --proxy-extension
- add helper/proxy.sh and helper/proxy-lib.sh to simplify ACVP Proxy execution for standard tasks
- add binarchive Makefile target for creating a binary distribution of the ACVP Proxy
- handle "unreceived" test responses by re-submitting them
- disable large file upload support but leave the code pending conclusion of issue #755

v1.1.0
- fix: update PBKDF to match published ACVP definition
- fix: do not log mmap()ed buffer as vsnprintf performs a strlen() operation and
       the mmap buffer is not guaranteed to be NULL terminated
- fix: Apple corecrypto cipher definitions
- move the definition_reference.json file from the secure data base to the
  test vector data base to allow users to map the test vectors to the right
  IUT
- --list-verdicts now contains cipher reference
- Data store version 3: definition_reference.json moved from secure to nonsecure data base. File is also extended to provide more information testing framework.
 This additional data is not required by the ACVP Proxy. Hence, if you have
 a datastore version 2, simply copy that file from the secure to the non-secure
 datastore and bump the datastore version to 3 manually.
- fix: bug fixes around re-downloading verdicts
- enhancement: add fuzzy search capability for an individual search criteria by
  prepending the search string with "f:", e.g.
	acvp-proxy -m f:module_name_substring -p specific_processor
- fix: resubmission of results working now (but not yet supported by server)
- enhancement: add ACVP server error parser to validate errors which we can ignore
- add XTS / CCM to libgcrypt
- add --publish-prereqs: resolution of ACVP Issue 733 may affect this option
  in the future
- fix: NIST requires the OE name to be unique - the proxy now concatenates
  the OE software and hardware information into one string for guaranteeing
  uniqueness
- fix: Generate UTF-8 characters in JSON output
=== Tool version was used to obtain ACVP certificates A6 through A32) ===

v1.0.0
- replace --list-certificate-ids with --list-available-ids
- version crypto implementation
- GnuTLS: add XTS
- OpenSSL: Add SSH KDF
- add: AES-FF1 and AES-FF3-1 support
- production ACVP: use testvector-production and secure-datastore-production databases
- add GMAC testing support
- fix OE / Dependency meta data handling
- first official ACVP certificate using the production server: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=11251
- Generic HMAC definition: use domain from 8 to 524288 bits for key size

v0.7.2
- add support for DELETE of all meta data endpoints
- add support for listing certificate IDs and pending request IDs
- add Nvidia definitions
- add listing of request IDs
- add listing of certificate IDs
- add listing of verdicts
- add PBKDF support
- fix storing of OE ID
- add ECDSA signature generation component testing support
- add --update-definition command line option - per default the ACVP proxy
  will now always register meta data with new entries in case the JSON
  configuration data with its ID does not match with the ACVP server.
  If the ACVP server shall be updated, --update-definition has to be used
- add --cipher-list

v0.7.1
- add ECDSA dependency to ECDH
- enable multi-threaded --publish
- enable support for registering dependencies together with OEs
- support demo IDs vs production IDs
- fix -b option
- add AES_CBC_CS[1|2|3]
- add support for automatically select acvpproxy_conf_production.json
  configuration file when using the --official option. See apps/README.md for
  details
- add search support when validating meta data without ID
- add hints for using libcurl with Apple Secure Transport on MacOS
- add hints that OpenSSL <= 1.0.2 threading is broken even though threading
  callbacks are registered - this implies that still random crashes when using
  OpenSSL <= 1.0.2 may be observed - see README.openssl.md
- support for validating CA certificates and CA certificate bundles added
- add certificate chain bundle for ACVP demo server

v0.7.0
- fix SHAKE support
- add SHAKE definitions for OpenSSL
- add AES-GCM-SIV support
- add GET / POST /persons
- add GET / PUT /persons/<personID>
- add PUT /vendors/<vendorID>
- add PUT /modules/<moduleID>
- add PUT /dependencies/<dependencyID>
- add PUT /oes/<dependencyID>
- add Paging support
- add bugfix when writing JSON files
- ACVP v1.0 support: change URLs and versions
- ACVP add revision support
- make /large support working after it is enabled on ACVP server
- add support for range domain values defined with DEF_ALG_DOMAIN
- add tests verifying the generation of requests
- update cipher names as mandated by ACVP
- (hopefully last) fix of MQ server with different multthreaded clients

v0.6.5
- add BouncyCastle definitions
- add /large endpoint handling
- remove HMAC SHA3 for GnuTLS as it is not implemented
- speed up --cipher-options
- use pthread mutexes
- remove message queue always during startup to prevent attaching to a stale
  message queue and restarting the MQ server election process
- Fix support for --resubmit-results

v0.6.4
- fix MQ server test on macOS
- add HMAC-SHA3 and SHA3 definitions for OpenSSL
- add RSA component signature and decryption support for the kernel
- add CMAC and CFB8 support for GnuTLS
- add SHA3 / HMAC SHA3 support to libgcrypt
- Linux kernel: Fix GCM test definitions

v0.6.3
- fix curl code compile issue on old libcurl versions
- MQ server: use busy-wait around client-side msgrcv to ensure catching a signal
- add test cases
- add BoringSSL definitions

v0.6.2:
- enable safety check guaranteeing that module definition did not change between test vector request and test response submission
- fix bug in acvp_publish
- SIGSEGV is caught to remove message queue
- OpenSSL: add missing CBC
- CommonCrypto: add symmetric ciphers
- statically link JSON-C
- fix make cppcheck

v0.6.1:
- Support --vsid without --testid on command line
- MQ server: fix starting and restarting of server thread
- fix IKEv2 register operation

v0.6.0:
- switch to ACVP protocol v0.5 - the following options are implemented
	/testSessions: POST
	/testSessions/<testSessionId>: GET, PUT, DELETE
	/testSessions/<testSessionId>/vectorSets: GET
	/testSessions/<testSessionId>/retults: GET
	/testSessions/<testSessionId>/vectorSets/<vectorSetId>: GET
	/testSessions/<testSessionId>/vectorSets/<vectorSetId>/results: GET, POST, PUT
	/testSessions/<testSessionId>/vectorSets/<vectorSetId>/expected: GET
	/vendors: GET, POST
	/vendors/<vendorId>: GET
	/oes: GET, POST
	/oes/<oeId>: GET
	/dependencies: GET, POST
	/dependencies/<dependencyId>: GET
	/modules: GET, POST
	/modules/<modulesId>: GET
- add unnanounced Apple KDF hardware specification
- add --resubmit-result option to resubmit already submitted test vectors
- obtain expected test results with --sample options
- Fix threading support return code handling
- Switch database store format. A complete new testvectors and secure-datastore
directory must be used.
- Add support for clean shutdown everywhere
- Analyze verdict response and print out the verdict at the end of a response submission
- Add support for DER and P12 certificates
- Add support for password-protected keys
- thread per-testid operation
- Support for resuming the download of the verdict without re-uploading the
  response after interruption of download operation
- addition of EDDSA
- restructure directories
- add download of cipher algorithm information
- support download of samples
- add Qualcomm TDES support

v0.5.8:
- replace all cipher string definitions with cipher_t
- __init -> ACVP_DEFINE_CONSTRUCTOR
- addition of ACVPProxy Hash/HMAC definitions
- addition of FIPS 140-2 compliance (POST)
- fix final race condition in mutex
- Apple user/kernel land version 9.0 definitions, Apple SKS 2.0 definitions
- get rid of all memleaks reported by valgrind
- use reader locks when protected resource is only read
- add FFCDH and ECDH to Apple vectors

v0.5.7:
- remove DRBG/RSA from kernel crypto API SHA MB implementation

v0.5.6
- add NSS definitions
- add 32 and 64 bit definitions
- fix Linux kernel DH definitions
- fix libkcapi KDF feedback mode
- add SHA3 / CFB definitions to Linux kernel and libkcapi

v0.5.5
- bug fixes in cipher definitions

v0.5.4
- bug fixes in cipher definitions

v0.5.3
- Add listing of uninstantiated cipher definitions - this supports the creation of new module definition configuration files
- add TOTP message queue server
- add -b and -s options for basedir and secure_basedir and split up secure/data store
- more strictly sanitize user-provided strings that may be used as path names
- protect auth token with permission bits
- add HTTP PUT and DELETE operations to curl backend to stage REST API changes that are coming
- add SSH protocol support with OpenSSH server and client example
- add IKEv2 protocol support with Strongswan example
- add TLS protocol support with OpenSSL example
- add IKEv1 protocol support with libreswan example
- add SP800-108 KDF support with libkcapi example
- add versioning of test vector data store and sensitive data store
- mandatory split of test vector data store and sensitive data store
- add KAS for OpenSSL
- add KAS for Linux kernel
- add KAS for GnuTLS

v0.5.2
- Fix several IUT definitions to match implementation and get DRBG working
- addition of KAS ECC
- addition of KAS FFC
- provide basic constructs to replace all cipher strings with numeric values using the definitions in cipher_definitions.h

v0.5.1
- store TOTP last generated time stamp in config file
- restructure data structures: de-entangle volatile from non-volatile ctx data,
  introduce acvp_vsid_ctx wrapping a vsID operation
- constify as much as possible
- fixed the sproadically OTP authentication errors (leading zeros for the OTP value must be printed!)

v0.5.0
- add support for comparing the upload and download servers for the ACVP
  vectors and results. Only when both match, results are uploaded. This
  will support the dual use of the tool for production and debug ACVP
  servers.
- add official testing mode
- split up request.c into acvp.c, acvp_request.c, acvp_response.c
- reduce code for datastore backend
- make backends fully standalone
- all DRBG definitions: update the requested cipher values as ACVP server is fixed
- extract module instantiation definitions into configuration files
- Provide the option to re-download vector sets when providing --request together with --vsid or --testid
- prevent the unneeded generation of directories in testvectors/

v0.4.1
- fix memory corruption in sig_enqueue_ctx and sig_dequeue_ctx
- various smaller fixes

v0.4.0
- Rename to acvpproxy
- Addition of documentation
- listing operation now supports search restrictions
- fix several memleaks
- add measures to make entire code thread-safe
- list number of expected vsIDs in definition listing

v0.3.1
- Update of corecrypto requests to make them working

v0.3.0
- Updated 2-factor authentication works
- Add ECDSA for libgcrypt, gnutls, OpenSSL
- Add DSA for libgcrypt, gnutls, OpenSSL
- threading of testID processing (retrieval and submission)
- compilation on macOS
- register of all Apple iOS, macOS, and SEP implementations
- register of CommonCrypto example

v0.2.0:
- 2-factor authentication works
- configuration file added (see readme)
- refresh of authentication token added
- OpenSSL added (CFB-1 and CFB-8 not working)

v0.1.5:
- GnuTLS added

v0.1.4:
- libgcrypt RSA working (RSA pss siggen currently fails with error "Could not verify signature: RSA PSS Verify: DB incorrect, '01' byte not found")

v0.1.3:
- Linux kernel crypto API definition added

v0.1.2:
- Nettle definition added

v0.1.1:
- completely isolate module definitions from remainder of library code
by adding the __init macro

v0.1.0:
- Linux kernel crypto API complete definition (symmetric, hashes, MACs, AEAD,
  DRBG, RSA)
- Effective file system structure for different vendors, modules, implementations and platforms

v0.0.6:
- RSA keygen for libgcrypt
- RSA siggen for libgcrypt
- RSA sigver for libgcrypt
- TDES tests

v0.0.5:
- code simplifications for production use
- Addition of TOTP (it is yet disabled)

v0.0.4:
- Threading support of data submission
- CTR DRBG with libgcryt
- HMAC with libgcrypt
- SHA MCT with libgcrypt
- AES KW with libgcrypt

v0.0.3:
- CMAC-TDES requests with libgcrypt

v0.0.2:
- HMAC requests with libgcrypt
- CMAC-AES requests with libgcrypt
- AES test result submission and fetching of results

v0.0.1:
- symmetric requests with libgcrypt
- SHA request with libgcrypt
- threading support
