# policy rules

[Rego][rego] policies related to the Conforma.

## Getting started for developers

### Makefile

The [`Makefile`](Makefile) contains a lot of useful scripts and commands. Run
`make` by itself to see the help.

### Dependencies

Go is required for development. Tools like [`conftest`][conftest] and [`opa`][opa] are executed with
the Go binary - they do not need to be installed in your system. See the top of the [go.mod](./go.mod)
file for the minimum version of Go required.

Most of the maintainers use [asdf][asdf] to seamlessly use the right version of Go.

Some, optional, make targets may require additional tooling. For example, `make live-test` requires
[entr][entr] to be installed.

### Formatting

The rego files should be formatted using the standard format. To apply the
standard format run this before committing:

    make fmt

### Documentation

The documentation is built using [Antora][antora].

Those docs are published [here][docs].

When making changes to policy rules, the docs will likely need to be re-generated. To do so run:

    make generate-docs

Commit all of the modified files.

### Running tests

From the top level directory you can run all tests and formatting checks, as
well as check that the docs are up to date, like this:

    make ci

You can run a single test like this:

    ec opa test ./policy -r <test_name_matcher>

or

    go run github.com/conforma/cli opa test ./policy -r <test_name_matcher>

The `<test_name_matcher>` is a regex, so you can use it to run more than one
test.

See [`Makefile`](Makefile) for other ways to run the tests.

### Writing tests

Policies must have unit tests validating them.
All test files must adhere to the naming convention:

    file.rego
    file_test.rego

Refer to the [policy testing docs][testing] for more information.

The CI also enforces that there is 100% test coverage. If you're not at 100%
you can use this to show what lines of code are not covered:

    make coverage

### Running policies against real pipline run image build attestations

Fetch an image attestation from a registry:

    make fetch-att
    more input/input.json # to look at it

or:

    make fetch-att IMAGE=<some-image-with-an-attestation-ref>

Create a dummy policy config file:

    make dummy-config
    cat data/config.json # to look at it

Then to verify the build using the defined policies:

    make check-release

### Running policies against real pipeline definitions

For example to fetch a pipeline definition from your local cluster:

    make fetch-pipeline
    make fetch-pipeline PIPELINE=<some-pipeline-name>
    more input/input.json # to look at it

For a realistic Konflux pipeline definition that
doesn't require cluster access, if you have the [build-definitions][builddefs]
repo checked out nearby you can do something like this:

    ( cd ../build-definitions && kustomize build pipelines/hacbs | yq 'select(document_index == 2)' -o json ) > input/input.json

Then to verify the pipeline definition using the defined policies:

    make check-pipeline

### Running policies against local [ec] build

Build a local version of `ec` in your local cli repo:

    make build

Create a `policy.yaml` file in your local `cli` repo with something like:

    ---
    sources:
      - policy:
          - <path-to>/policy/policy/lib
          - <path-to>/policy/policy/release
        data:
          - oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest
          - github.com/release-engineering/rhtap-ec-policy//data

Run the locally built `ec` command

    dist/ec_<arch> validate image --verbose --images '{"components": [{"containerImage": "<container-image>", "name":"my-image", "source":{"git":{"url":"<repository-url>","revision":"<commit-id>"}}}]}' --policy 'policy.yaml' --public-key <public-key-to-verify-the-image> --strict false  --ignore-rekor --verbose --output=text

## Policy bundles

The policies defined here are bundled and pushed as OCI artifacts using
`conftest`. There are three bundles, one for each of the release and pipeline
policies, and one for the data which is used by both.

The [push-bundles](.github/workflows/push-bundles.yml) automates creating and
pushing these bundles to [quay.io][quay], and generating a related PR in the
[infra-deployments repo][infradeployments] so the
latest bundles are used.

See also the [policy bundle documentation](./antora/docs/modules/ROOT/pages/policy_bundles.adoc).

## Getting started for policy authors

See the [Policy Authoring][authoring] documentation for guidance on
contributing to the definition of policy rules.

## See also

* [Policy rule documentation][policydocs]
* ["Verify Enterprise Contract" task definition][taskdef]
* [github.com/enterprise-contract][contract]
* [github.com/konflux-ci][konflux-ci]

[asdf]: https://asdf-vm.com/
[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[conftest]: https://www.conftest.dev/
[opa]: https://www.openpolicyagent.org/docs/latest/
[entr]: https://github.com/eradman/entr
[testing]: https://www.openpolicyagent.org/docs/latest/policy-testing/
[docs]: https://conforma.dev/
[policydocs]: https://conforma.dev/docs/policy/release_policy.html
[taskdef]: https://github.com/conforma/cli/blob/main/tasks/verify-enterprise-contract/0.1/verify-enterprise-contract.yaml
[contract]: https://github.com/enterprise-contract
[ec]: https://github.com/conforma/cli
[konflux-ci]: https://github.com/konflux-ci
[builddefs]: https://github.com/konflux-ci/build-definitions
[authoring]: https://conforma.dev/docs/policy/authoring.html
[antora]: https://docs.antora.org/antora/latest/install-and-run-quickstart/
[quay]: https://quay.io/
[infradeployments]: https://github.com/redhat-appstudio/infra-deployments
