# AMVP Support

The A(utomated) M(odule) V(alidation) P(rotocol) support is provided with the `amvp-proxy` tool provided with this source code.

The tool handles the entire communication related to CMVP validation artifacts between NIST and the lab. The following generic processing steps are performed and offered to the user:

1. Register the IUT module specifics with the NIST server.

2. Download the templates for the security policy and the test requirements pertaining to the registered module. This step is performed automatically when the user started step 1.

3. After the tester filled in parts or all of the data obtained in step 2, the data is uploaded to the server. This step can be performed as often as needed allowing even partial uploads of data.

4. When all test data and evidence information is uploaded, the user can request the publication of the data which marks the end of the test cycle. This step marks to NIST that the evidence is now ready for review.

## AMVP-Proxy Concepts

The `amvp-proxy` has the very same concepts as the `acvp-proxy`:

- The `amvp-testvectors` directory holds the official data, including the aforementioned templates retrieved from the NIST server as well as the evidence to be submitted to the server. Its structure is identical to that of the `acvp-proxy` where the ACVP test session ID is now referencing a module ID and the ACVP vector set ID references a certificate request.

- The `amvp-secure-datastore` directory holds the private data including authentication credentials.

- The `module_definitions` directory holds the meta data of the IUT where the search scope documented for the `acvp-proxy` is equally applicable and usable. The AMVP-Proxy also uses the `module_info` as well as the `vendor` specification the `acvp-proxy` equally uses, too. Specifically, the AMVP-Proxy retrieves the module name and additional information as well as vendor information from these files.

## Registration of the IUT Module Specifics

The registration of the IUT module to the NIST server announces the capabilities of the modules to the NIST server as well as some additional information.

The registration is performed with the following command:

`amvp-proxy --register`

The option `--dump-register` can be used as well in order to dump the JSON data about to be submitted to the server.

As stated before, a search scope can be applied as well.

Note, a module definition only is `eligible` for AMVP operations, if it is configured as such. The following configurations must all be present in the `module_definitions` directory of a given module:

* The file `cmvp/module_validation_definition.json` must be present and contain the IUT test definition. This file must contain the following JSON content adjusted as applicable to the given module:

```
{
        "implementsOtar":false,
        "hasNonApprovedMode":false,
        "requiresInitialization":false,
        "hasExcludedComponents":false,
        "hasDegradedMode":false,
        "hasPPAorPAI":false,
        "hasEmbeddedOrBoundModule":false,
        "hasCriticalFunctions":false,
        "hasNonApprovedAlgorithmsInApprovedMode":false,
        "hasExternalInputDevice":false,
        "hasExternalOutputDevice":false,
        "usesTrustedChannel":false,
        "supportsConcurrentOperators":false,
        "usesIdentityBasedAuthentication":false,
        "hasMaintenanceRole":false,
        "allowsOperatorToChangeRoles":false,
        "hasDefaultAuthenticationData":false,
        "usesEDC":false,
        "allowsExternalLoadingOfSoftwareOrFirmware":false,
        "containsNonReconfigurableMemory":false,
        "usesOpenSource":false,
        "providesMaintenanceAccessInterface":false,
        "hasVentilationOrSlits":false,
        "hasRemovableCover":false,
        "hasTamperSeals":false,
        "hasOperatorAppliedTamperSeals":false,
        "hasEFPorEFT":false,
        "outputsSensitiveDataAsPlaintext":false,
        "supportsManualSSPEntry":false,
        "usesSplitKnowledge":false,
        "hasCVE":false,
        "hasAdditionalMitigations":false,
        "usesOtherCurve":false,
        "supportsBypassCapability":false,
        "hasOTPMemory":false,

        "moduleInfo":{
                "embodiment":"software",
        },

        "secLevels":[
                {
                        "section":1,
                        "level":1
                },
                {
                        "section":2,
                        "level":1
                },
                {
                        "section":3,
                        "level":1
                },
                {
                        "section":4,
                        "level":1
                },
                {
                        "section":5,
                        "level":1
                },
                {
                        "section":6,
                        "level":1
                },
                {
                        "section":7,
                        "level":1
                },
                {
                        "section":8,
                        "level":1
                },
                {
                        "section":9,
                        "level":1
                },
                {
                        "section":10,
                        "level":1
                },
                {
                        "section":11,
                        "level":1
                },
                {
                        "section":12,
                        "level":1
                }
        ]
}
```

* The file `cmvp/registration_data.json` must be present and contain the following JSON structure. The `contactId` information is an array of IDs referencing the CVP number of the tester(s) working on this validation.

```
{
        "contactId": [
                "CVP-01234",
                "CVP-12345"
        ]
}
```

## AMVP Individual Steps

The main goal of the AMVP-Proxy is to not get into the way of the user. Therefore, it is possible with AMVP to perform each step of the server communication individually. The following sections outline the possibilities.

### One-Shot Registration

The common operation is a one-shot operation where a user invokes the proxy once and the proxy proceeds by executing as many steps automatically as possible. If at one step the proxy fails to complete the operation or data is missing, the proxy will stop the processing, outline the state and give guidance on the next steps.

Command: `amvp-proxy --request`

Response: Command attempts to proceed as far as possible, usually to the point of [Submit Data]. The output of the proxy will tell which next step to take.

Purpose: Initial registration of the module to the point where uploading of data is possible.

Next steps: Those are specified by the proxy - usually the next step is [Submit Data].

### Register Module Only

Command: `amvp-proxy --request --register-only`

Response: Module request ID

Purpose: Initial registration of a module.

Next steps: Have the request ID approved by NIST. Once approved, fetch it as outlined in [Fetch Module ID].

### Fetch Module ID

Command: `amvp-proxy --modulereqid <ID>` where `<ID>` is the ID obtained from [Register Module ID]

Response: Module ID

Purpose: The Module ID is required to register the certification request.

Next steps: The command tries to fetch the module ID. This ID is required to obtain register the certification request. If somehow that fails, you can re-initiate the certification request as outlined in [Certification Request].

### Certification Request

Command: `amvp-proxy --moduleid <ID>` where `<ID>` is the module ID obtained as outlined in [Fetch Module ID].

Response: certification request ID

Purpose: Register the certification request. The certification request is the session to interact with the AMVP server to upload any data, including TE and security policy data to the server.

Next steps: Submit data as outlined in [Submit Data].

### Submit Data

Command: `amvp-proxy --vsid <certification request ID>` where `<certification request ID>` is the ID obtained as outlined in [Certification Request].

Prerequisite: Data stored in `amvp-testvectors/.../<module ID>/<certification request ID>/te.json` and SP data as provided in `module_definition/cmvp` must be provided by the user.

Purpose: Upload the data to AMVP server.

Next step: Repeat operation as often as needed to upload evidence to server.

### Fetch Status

Command: `amvp-proxy --vsid <certification request ID> --fetch-status` where `<certification request ID>` is the ID obtained as outlined in [Certification Request].

Purpose: Fetch the current status of the certification request.

Next step: Repeat [Submit Data] as often as needed to send all data and receive a certificate.

### Fetch Security Policy

Command: `amvp-proxy --vsid <certification request ID> --fetch-sp` where `<certification request ID>` is the ID obtained as outlined in [Certification Request].

Purpose: Fetch the security policy PDF of the certification request.

Next step: N/A

### Finalize the Certification and request Certificate

Command: `amvp-proxy --vsid <certification request ID> --certify` where `<certification request ID>` is the ID obtained as outlined in [Certification Request].

Purpose: After all data has been submitted, this call marks the end of the test lab operation. It will close the certificate request such that NIST reviewers can perform their actions. If all goes well, you will receive a certificate eventually.

To query the status of the current certification request, use the command outlined in [Fetch Status].

Next step: Repeat [Fetch Status] until you receive a certificate.
