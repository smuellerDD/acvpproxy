# Addition of New Cipher Registration Capability

To add a new cipher registration capability, e.g. when NIST announced a new
cipher is testable with ACVP, the following steps must be taken:

1. Create a new definition_cipher_<cipher_name>.h that contains the data
   structure definition holding all information required for the registration
   and defined by the SPEC.

2. Add the new definition_cipher_<cipher_name>.h to definition.h.

3. In definition.h, do:

	a. enhance enum def_algo_type by a new type

	b. enhance union algo by referring to the root data structure for your
	   new algorithm definition in definition_cipher_<cipher_name>.h

4. Create a new request_cipher_<cipher_name>.c that creates the registration
   JSON structure. This C file must contain function implementations following these prototypes:

	a. Generate the JSON structure:

	   int acvp_req_set_algo_<name>(const struct <root_data_structure> *,
					struct json_object *entry)

	   The variable entry is filled by the function using the data from
	   struct <root_data_structure>.

	b. Fill the data structure used to provide a high-level list of
	   the cipher configuration for --list-cipher-options

	   int acvp_list_algo_<name>(const struct <root_data_structure> *,
				     struct acvp_list_ciphers **new)

	   The variable new is filled by the function using the data from
	   struct <root_data_structure>.

	c. Create the JSON structure listing the prerequisites:

	   int acvp_req_set_prereq_<name>(cconst struct <root_data_structure> *,
					  const struct acvp_test_deps *deps,
					  struct json_object *entry,
					  bool publish)

	   The variable entry is filled by the function using the data from
	   struct <root_data_structure>. The variables deps and publish should
	   be used when calling acvp_req_gen_prereq at the end of this function.

5. Register the three created functions from step 4 in:

	a. internal.h

	b. add acvp_req_set_prereq_<name> to acvp_publish_prereqs

	c. add acvp_list_algo_<name> to acvp_list_cipher_gatherer

	d. add acvp_req_set_algo_<name> to acvp_req_set_algo

After these changes, you can create new registration definitions for your
IUT in lib/module_implementations/ using the new registration capability.

# Author

Stephan Müller <smueller@chronox.de>