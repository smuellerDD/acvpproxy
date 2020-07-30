v1.5.2
- fix segfault with --cipher-list
- fix format string usage as indicated with __attribute__((format()))
- fix race in creating a database
- fix HMAC SHA2-512/224 and /256

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
- bug fix: disable threading for publication operation
- enhancement: only require the presence of the key / seed data if a network operation is to be performed
- enhancement: allow parallel execution of production and demo ACVP Proxy execution
- fix: deactivate large endpoint handling as new ACVP server frontend does not need it
- fix: listing of ciphers modified to new ACVP server structure
- enhancement: --sample is now allowed to be used during posting of results or resubmitting results (--resubmit-result) showing the expected result for the failures
- enhancement: add .impl_description to struct def_algo_map to allow specific implementation descriptions to be mentioned on the certificate
- enhancement: speed-up of authentication: re-use of initial login token
- fix: OpenSSL ARM definitions
- code restructuring: consolidate ACVP meta data handling

v1.3.2
- bug fix to make option --vsid work again
- OpenSSL: add safeprime keygen test
- macOS: log HTTP error return data

v1.3.1
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
- common cipher definition: converted all cipher definition to Domain definitions
- add libica
- add S390/ARM64 support for: OpenSSL
- add --register-only option to only register a new cipher definition without downloading the test vectors

v1.2.4
- OpenSSL: Add ECC CDH, ECDH with P224, add P224 to ECDSA siggen/sigver
- bug fix for macOS: allow CA certificate file (a bug did not allow a file, but only a keychain entry)
- bug fix: prevent displaying of user passcode in debug log
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
- add GET /validations/<certificateId> when having certificateId available -
  the result is stored in testsession_certificate_info.json
- fix: JWT can be larger than 1024 bytes - the proxy now has a maximum size of
  16384 bytes
- replace --publish-prereqs with --no-publish-prereqs: Per default, the
  prerequisites are sent during publication. The submission can be prevented
  with this option. This is currently disabled due to issue #749.
- apply the currently applicable JSON format for prerequisites during
  publication
- if oeEnvName is set to the NULL JSON data type, the OE is not registered with the module (e.g. relevant for hardware modules)
- do not enforce the presence of SWID or CPE
- add SLES kernel definition
- fix: complete new register operation now uses correct URL
- add --list-certificates to provide a listing of all received certificate
  numbers
- add listing of received certificates to --list-verdicts
- remove CFB-8 from kernel (not implemented)
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
- add /large endpoint handling
- speed up --cipher-options
- use pthread mutexes
- remove message queue always during startup to prevent attaching to a stale
  message queue and restarting the MQ server election process
- Fix support for --resubmit-results

Changes v0.6.4
- MQ server test: fix for enabling testing on macOS
- add HMAC-SHA3 and SHA3 definitions for OpenSSL

Changes v0.6.3
- fix curl code compile issue on old libcurl versions
- MQ server: use busy-wait around client-side msgrcv to ensure catching a signal
- add test cases

Changes 0.6.2
- enable safety check guaranteeing that module definition did not change between test vector request and test response submission
- fix bug in acvp_publish
- SIGSEGV is caught to remove message queue
- OpenSSL: add missing CBC
- statically link JSON-C
- fix make cppcheck
- compile with -Wno-missing-field-initializers as some compilers require all structure fields to be initialized
- re-enable ACVP cancel operation upon SIGTERM, SIGINT, SIGQUIT, SIGHUP
- allow ACVP cancel operation to be terminated with 2nd receipt of signals

Changes 0.6.1
- Support --vsid without --testid on command line
- MQ server: fix starting and restarting of server thread
- fix IKEv2 register operation

Changes 0.6.0
 * first public release with support for ACVP v0.5
