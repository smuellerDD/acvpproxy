# ESVP Support

The proxy code contains the logic to also access the NIST ESVP server using
the `esvp-proxy` tool that is compiled together with the `acvp-proxy`.

The concept of the ESVP proxy is similar ACVP proxy.

The following subsections enumerate the operations that can be performed with
the ESVP proxy.

## Register Entropy Source and Upload Data

When apart from the search scope, the ESVP proxy is invoked with no other
parameter, it registers the entropy source and uploads the associated data.
For example, the following command uploads the data for the Jitter RNG entropy
source.

	`esvp-proxy -m Jitter -f`

This call attempts also the certify operation. This operation most likely will
fail for the first time as the entropy data needs to be calculated. In this
case, please invoke the [Re-start Entropy Source Submission] operation at a
later time.

Note, the certify is the equivalent to the certification request in the ACVP
Proxy. Yet, it is required that all meta data is already registered with the
ACVP server - yes, the ESV Server and the ACVP server share the same meta data
base.

Thus, if the certify fails because some meta data is not yet registered,
simply use the ACVP proxy and publish or sync-meta the meta data. Then restart
the certify operation as outlined in [Re-start Entropy Source Certify].

## Re-Start Entropy Source Submission

In order to restart the submission of an interrupted upload or when uploading
new data to the ESVP server that was added after the initial submission, invoke
`esvp-proxy` with --testid `<ID>` that refers to the certification ID.

  `esvp-proxy --testid <ID>`

## Entropy Source Certify

In order to re-start the certify operation to fetch the certificate, invoke
`esvp-proxy` with --testid `<ID>` --publish that refers to the certification ID.

  `esvp-proxy --testid <ID> --publish`

## Multiple Operational Environments with one Entropy Source

It is permissible (and even cheaper for all) to certify one Entropy Source (ES)
on multiple operational environments with one certify request. The resulting
ESV certificate will then list all operational environments. This is in contrast
to having one ESV certificate for the same entropy source on different
operational environments.

The ESVP Proxy will automatically identify the entropy source definitions which
belong together and will register them as one during the certify step. Each
ES with its separate operational environment is maintained in a separate
`module_definitions` directory.

Example assuming that all meta data were already registered beforehand with
`acvp-proxy --sync-meta`

1. Upload Jitter RNG ES on OE 1 - definition is specified in
   `module_definitions/jitter_rng`: `esvp-proxy -m Jitter -f -e "Fedora 32"`

   -> Returned example test session ID is 1

2. Upload Jitter RNG ES on OE 2 - definition is specified in
   `module_definitions/jitter_rng2`: `esvp-proxy -m Jitter -f -e "Fedora 35"`

   -> Returned example test session ID is 2

3. Upload unrelated ES - just to show that unrelated ES are detected by the
   ESVP Proxy: `esvp-proxy -m LRNG -f`

   -> Returned example test session ID is 3

4. Certify step: `esvp-proxy --testid 1 --testid 2 --testid 3`

   -> ESVP Proxy will report:

   `ESVP server accepted certificate request - notify NIST to approve ID 1`

   `ESVP server accepted certificate request - notify NIST to approve ID 3`

   -> The test session ID 2 is not present as it is rolled into the certify
   request of test session ID 1.

The ESVP Proxy detects the ES which belong together based on the following:

* `labTestId` must be identical for the different ES

* `acvpModuleId` or `acvpModuleIdProduction` must be identical for the different
  ES

* `acvpVendorId` or `acvpVendorIdProduction` must be identical for the different
  ES

For the aforementioned example, the directories
`module_definitions/jitter_rng_firstOE` and
`module_definitions/jitter_rng_secondOE` contain the mentioned identical
information.

One suggested approach to ensure to get the same specification such that the
ESVP Proxy identifies the different specifications belong together applies
the following steps:

1. Create one `module_definitions` directory containing the ES definition
   and all data required for the ES on one operational environment. Upload the
   meta data with `acvp-proxy --sync-meta`.

2. Duplicate the created `module_definitions` directory and import the new
   entropy data on the given OE. Also update the OE definition in the
   `module_definitions/<NAME>/oe` directory. Synchronize the new OE meta data
   with the server using `acvp-proxy --sync-meta`.

3. Upload the ESV data for both ES definitions: `esvp-proxy`

4. Certify both ES definitions: `esvp-proxy --publish --testid <ID_ES1> --testid <ID_ES2>`

## Addition of OEs to Existing Certificates

The OEAdd support is provided as follows: It is an *identical* operation
compared to the certify operation. Its only difference is that the
`entropy_source/definition.json` JSON file is extended by the keyword
`esvCertificate` which refers to the certificate reference as a string:

```
{
        "primaryNoiseSource": "Jitter RNG",
        "labTestId":"JENT",
        "bitsPerSample": 8,
        "alphabetSize": 256,
        ...
        "esvCertificate": "ESV1234",
        ...
}
```
When using this JSON configuration, the associated OE is *added* to the
referenced certificate instead of a new certificate being requested.

Thus, to perform an OE addition operation, do:

1. You have a particular ES which was successfully validated and you have the
associated certificate reference.

2. Duplicate the `module_definitions` directory with the validated ES
definition and give it a new name.

3. The newly created `module_definition` now needs to be modified:

	1. add the `esvCertificate` as outlined above,

	2. modify the OE definition in the `module_definitions/<NAME>/oe`
	directory to cover the new OE.

	3. Add the new entropy data, perhaps additional documents

4. Optionally do that again to add multiple OEs (i.e. the statements given in
section [Multiple Operational Environments with one Entropy Source] apply).

5. Synchronize the new OE meta data with the server using
`acvp-proxy --sync-meta`.

6. Upload the ESV data for both ES definitions: `esvp-proxy` and obtain the testID(s).

7. Certify the newly created ES definition(s):
`esvp-proxy --publish --testid <ID_NEW_ES>`

With these steps it is clear that the OE Add operation is identical from a usage perspective compared to a "regular" certify operation.

## Update of PUD Document

It is permissible to update the PUD document for an already certified ES.
According to NIST: "This can be helpful for corrections or rebranding. There is
no cost recovery associated with this request."

Consider the note from NIST: "Please include a comment on what changed in the
document compared to the existing PUD. This will greatly expedite the review
process."

This PUD document update is only supported for an ES that has an ESV
certificate. Specify the ESV certificate in the `entropy_source/definition.json`
JSON file is extended by the keyword `esvCertificate` which refers to the
certificate reference as a string:

```
{
        "primaryNoiseSource": "Jitter RNG",
        "labTestId":"JENT",
        "bitsPerSample": 8,
        "alphabetSize": 256,
        ...
        "esvCertificate": "ESV1234",
        ...
}
```
To perform a PUD update operation, perform the following steps:

1. Optionally duplicate the `module_definitions` directory with the validated ES
definition in case you want to retain the old state.

2. The `module_definition` now needs to be modified:

	1. add the `esvCertificate` as outlined above.

3. Replace the existing PUD with the new PUD.

3. Upload the new PUD to the NIST ESVP server: `esvp-proxy` and obtain the testID(s).

4. Request the PUD update process: `esvp-proxy --pudupdate --testid <ID_NEW_ES>`

With the last step you get a simple acknowledgment which you then need to report
to NIST.

## Entropy Source Configuration

The entropy source configuration is stored within the `modules_definition`
directory just like the ACVP configuration for a given module.

The following sub-directories are allowed for one entropy source:

* `conditioning_component<NUM>`: This directory contains the information for
one specific conditioning component. The value <NUM> must start with 1 and
allows an arbitrary number of conditioning component definitions.

* `entropy_source`: This directory contains the specification and definition for
the given entropy source. Note, as defined in SP800-90B only one noise source
is allowed to be credited for entropy within one given entropy source.

* `documentation`: This directory contains documentation information around
the entropy source. One or more documents are allowed in this directory.
Yet, all must either be PDF, or Microsoft Word documents. This document is
uploaded with a data type as follows:

  - If the file starts with "Entropy-Analysis", "Entropy_Analysis", or "EAR"
    it is uploaded with the type that indicates an entropy analysis report.

  - If the file contains the characters "public", "Public", or "PUBLIC" it
    is uploaded as a public use document.

  - Otherwise it is uploaded with the data type referencing an other document.

### Conditioning Component Configuration

The directory `conditioning_component<NUM>` is defined to contain the
following files:

* `definition.json` specifies the properties of the conditioning component.
Its contents is defined below.

* `conditioned_bits.bin`: If the conditioning component is defined as a
non-vetted algorithm, the output of the conditioning component must be provided
with this file.

The properties of the conditioning component specified with `definition.json`
contains the following information:

* `description`: This keyword either contains a free-form text field referencing
the algorithm of the conditioning component if it is a non-vetted algorithm.
If the conditioning component is a vetted algorithm, the algorithm string
defined by ACVP must be specified (e.g. SHA2-256, HMAC-SHA2-512) - see for
valid names `struct cipher_def_map cipher_def_map`.

* `minHin`: minimum amount of entropy inputted to the conditioning function
per the number of bits inputted. Note, this value allows a fractional number.

* `minNin`: minimum bits inputted to the conditioning function

* `nw`: narrowest width of the conditioning function

* `nOut`: number of bits outputted by the conditioning function

* `vetted`: boolean indicating whether the conditioning component is classified
as a vetted conditioning component

* `acvtsCertificate`: if vetted, reference to ACVTS certificate number

* `bijective`: if non-vetted, this boolean indicates a conditioning component
that is a bijective function

### Entropy Source Configuration

The entropy source is defined with the following files in the `entropy_source`
directory:

* `definition.json` specifies the properties of the noise source.
Its contents is defined below.

* `raw_noise_bits.bin`: This file contains the raw unconditioned data from
the noise source sequenced into a bitstream. The file is expected to hold
1 million samples from the noise source.

* `restart_bits.bin`: This file contains the raw unconditioned data from the
noise source restart tests. This file is a bit stream with the following
characteristics: the sequenced bit stream data for one restart is concatenated
with the data from the next restart. The file is expected to hold 1000
restarts with 1000 samples from the noise source for each restart.

The properties of the conditioning component specified with `definition.json`
contains the following information:

* `primaryNoiseSource`: This references a free-form name of the primary
noise source.

* `labTestId`: This references a 4-letter lab test id.

* `bitsPerSample`: the number of bits per sample outputted by the noise source

* `numberOfRestarts`: the number of restarts used to generate the restart bits
data file - this should be 1000

* `samplesPerRestart`: the number of samples per restart used to generate the
restart bits data file - this should be 1000

* `hminEstimate`: an estimate of the number of bits of entropy outputted by the
noise source over one sample. Note, this value allows a fractional number.

* `iid`: boolean indicating whether the IUT claims the entropy source is
independent and identically distributed

* `physical`: boolean indicating whether the noise source is physical or
non-physical

* `limitEntropyAssessmentToVendor`: boolean indicating whether
ES is limited to one vendor, i.e., if FALSE, ES will be open for reuse;
if TRUE, ES will be restricted to vendor. Previously named
`limitEntropyAssessmentToSingleModule`; the old name is still accepted.

* `additionalNoiseSources`: boolean indicating whether additional noise sources
are incorporated in the entropy source

* `earFile`: optional string of file name pointing to the EAR document. Note,
if the common documentation directory contains any EAR document as mentioned
above, the proxy will submit *both*.

* `pudFile`: optional string of file name pointing to the PUD document. Note,
if the common documentation directory contains any PUD document as mentioned
above, the proxy will submit *both*.

# Author

Stephan Müller <smueller@chronox.de>
