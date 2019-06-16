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
