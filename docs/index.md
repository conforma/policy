
HACBS Enterprise Contract Policies
==================================

About
-----

The HACBS Enterprise Contract is a Tekton task that can be used to verify the
provenence of container images built in HACBS and validate them against a set of
policies.

Those policies are defined using
[rego](https://www.openpolicyagent.org/docs/latest/policy-language/) and are
described here.

Policy Rules
------------

### Attestation Task Bundle Rules

#### `[disallowed_task_reference]` Task bundle was not used or is not defined

Check for existence of a task bundle. Enforcing this rule will
fail the contract if the task is not called from a bundle.

* Path: `data.policies.attestation_task_bundle.warn`
* Failure message: `Task '%s' does not contain a bundle reference`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policies/attestation_task_bundle.rego#L13)

#### `[disallowed_task_bundle]` Task bundle was used that was disallowed

Check for existence of a valid task bundle. Enforcing this rule will
fail the contract if the task is not called using a valid bundle image.

* Path: `data.policies.attestation_task_bundle.warn`
* Failure message: `Task '%s' has disallowed bundle image '%s'`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policies/attestation_task_bundle.rego#L32)

### Attestation Type Rules

#### `[unknown_att_type]` Unknown attestation type found

A sanity check that the attestation found for the image has the expected
attestation type. Currently there is only one attestation type supported,
`https://in-toto.io/Statement/v0.1`.

* Path: `data.policies.attestation_type.deny`
* Failure message: `Unknown attestation type '%s'`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policies/attestation_type.rego#L18)

### Not Useful Rules

#### `[bad_day]` A dummy rule that always fails

It's expected this rule will be skipped by policy configuration.
This rule is for demonstration and test purposes and should be deleted soon.

* Path: `data.policies.not_useful.deny`
* Failure message: `It just feels like a bad day to do a release`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policies/not_useful.rego#L14)

### Source Image Task Rules

#### `[disallowed_input_image]` Verify the source-image-verify task accepts an image

Verify the source-image-verify task accepts a particular image
as an input param.

* Path: `data.policies.source_image_task.warn`
* Failure message: `Task '%s' does not contain '%s' as a param`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policies/source_image_task.rego#L13)

### Step Image Registries Rules

#### `[disallowed_task_step_image]` Task steps ran on container images that are disallowed

Enterprise Contract has a list of allowed registry prefixes. Each step in each
each TaskRun must run on a container image with a url that matches one of the
prefixes in the list.

The permitted registry prefixes are:

```
quay.io/buildah
quay.io/redhat-appstudio
registry.access.redhat.com/ubi8
registry.access.redhat.com/ubi8-minimal
registry.redhat.io/ocp-tools-4-tech-preview
registry.redhat.io/openshift4
registry.redhat.io/openshift-pipelines
```

* Path: `data.policies.step_image_registries.deny`
* Failure message: `Step %d in task '%s' has disallowed image ref '%s'`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policies/step_image_registries.rego#L23)

### Test Rules

#### `[test_data_missing]` No test data found

None of the tasks in the pipeline included a HACBS_TEST_OUTPUT
task result, which is where Enterprise Contract expects to find
test result data.

* Path: `data.policies.test.deny`
* Failure message: `No test data found`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policies/test.rego#L15)

#### `[test_results_missing]` Test data is missing the results key

Each test result is expected to have a 'results' key. In at least
one of the HACBS_TEST_OUTPUT task results this key was not present.

* Path: `data.policies.test.deny`
* Failure message: `Found tests without results`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policies/test.rego#L29)

#### `[test_result_failures]` Some tests did not pass

Enterprise Contract requires that all the tests in the
test results have a result of 'SUCCESS'. This will fail if any
of the tests failed and the failure message will list the names
of the failing tests.

* Path: `data.policies.test.deny`
* Failure message: `The following tests did not complete successfully: %s`
* [Source](https://github.com/hacbs-contract/ec-policies/blob/main/policies/test.rego#L46)

See Also
--------

* ["Verify Enterprise Contract" task definition](https://github.com/redhat-appstudio/build-definitions/blob/main/tasks/verify-enterprise-contract.yaml)
* [github.com/hacbs-contract/ec-policies](https://github.com/hacbs-contract/ec-policies)
* [github.com/hacbs-contract](https://github.com/hacbs-contract)
* [github.com/redhat-appstudio](https://github.com/redhat-appstudio/)
