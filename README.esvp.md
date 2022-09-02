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
case, please invoke the [Re-start Entropy Source Certify] operation at a later
time.

## Re-start Entropy Source Certify

In order to re-start the certify operation to fetch the certificate, invoke
`esvp-proxy` with --testid `<ID>` that refers to the certification ID.

### Entropy Source Configuration

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
Yet, all must either be PDF, or Microsoft Word documents.

#### Conditioning Component Configuration

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

#### Entropy Source Configuration

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

* `alphabetSize`: the total number of distinct samples possibly outputted by the
noise source

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

* `itar`: boolean indicating whether the entropy source claims heightened
security for an ITAR validation

* `additionalNoiseSources`: boolean indicating whether additional noise sources
are incorporated in the entropy source

# Author

Stephan Müller <smueller@chronox.de>
