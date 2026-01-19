SHELL := /bin/bash

COPY:=The Conforma Contributors

DATA_DIR=./example/data
CONFIG_DATA_FILE=$(DATA_DIR)/config.json

POLICY_DIR=./policy

# Use go run so we use the exact pinned versions from the mod file.
# Use ec for the opa and conftest commands so that our custom rego
# functions are available.
ifndef EC_REF
  EC_MOD=github.com/conforma/cli
else
  # EC_REF can be set to use ec built from a particular ref, e.g.:
  #   EC_REF=release-v0.2 make ec-version quiet-test
  EC_MOD=github.com/conforma/cli@$(EC_REF)
endif

EC=go run $(EC_MOD)

OPA=$(EC) opa
CONFTEST=EC_EXPERIMENTAL=1 $(EC)
TKN=go run github.com/tektoncd/cli/cmd/tkn
TEST_CMD_DEFAULT=$(OPA) test $(TEST_FILES) $(TEST_FILTER)
# if unshare is available we isolate the process to run without network access,
# if it is not we run as is; building ec will require network access to download
# the dependencies, for this we run `ec version` to have it built first
ifeq ($(shell command -v unshare),)
  TEST_CMD=$(TEST_CMD_DEFAULT)
else
  TEST_CMD=$(EC) version > /dev/null && unshare -r -n $(TEST_CMD_DEFAULT)
endif

LICENSE_IGNORE=-ignore '.git/**' -ignore '.idea/**'

TEST_FILES = $(DATA_DIR)/rule_data.yml $(POLICY_DIR) checks
define COVERAGE
@$(OPA) test --coverage --format json $(TEST_FILES) | { \
	T=$$(mktemp); tee "$${T}"; $(OPA) eval --format pretty \
	--input "$${T}" \
	--data hack/simplecov.rego \
	data.hack.from_opa > coverage.json; \
	rm -f "$${T}" || true ;\
} \
| jq -j -r 'if .coverage < 100 then "ERROR: Code coverage threshold not met: got \(.coverage) instead of 100.00\n" | halt_error(1) else "" end'
endef

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'function ww(s) {\
		if (length(s) < 59) {\
			return s;\
		}\
		else {\
			r="";\
			l="";\
			split(s, arr, " ");\
			for (w in arr) {\
				if (length(l " " arr[w]) > 59) {\
					r=r l "\n                     ";\
					l="";\
				}\
				l=l " " arr[w];\
			}\
			r=r l;\
			return r;\
		}\
	} BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", "make " $$1, ww($$2) } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

ec-version:
	@echo $(EC_MOD)
	@# To confirm that EC_REF is doing what you think it's doing
	@go list -m -json $(EC_MOD) | jq -r .Version
	@# Actually we get "development" as the version and "0001-01-01"
	@# as the change date but let's show it anyhow
	@$(EC) version

# Set TEST to only run tests that match the given string. It does a regex match
# on the fully qualified name iiuc, e.g. "policy.release.foo_test.test_thing"
# so you could use TEST=test_thing or TEST=release.foo_", etc
TEST_FILTER=$(if $(TEST),--run $(TEST))

# Todo maybe: Run tests with conftest verify instead
.PHONY: test
test: ## Run all tests in verbose mode and check coverage
	@$(TEST_CMD) --verbose
	$(COVERAGE)

.PHONY: quiet-test
quiet-test: ## Run all tests in quiet mode and check coverage
	@$(TEST_CMD)
	$(COVERAGE)

.PHONY: watch
watch: ## Run tests in watch mode, use TEST=package or TEST=test to focus on a single package or test
	@$(TEST_CMD) --verbose --watch

# Do `dnf install entr` then run this a separate terminal or split window while hacking
# (live-test and watch do similar things in different ways. Use whichever one you like better.)
.PHONY: live-test
live-test: ## Continuously run tests on changes to any `*.rego` files, `entr` needs to be installed
	@trap exit SIGINT; \
	while true; do \
	  git ls-files -c -o '*.rego' | entr -r -d -c $(MAKE) --no-print-directory quiet-test; \
	done

.PHONY: coverage
# The cat does nothing but avoids a non-zero exit code from grep -v
coverage: ## Show which lines of rego are not covered by tests
	@$(TEST_CMD) --coverage --format json | jq -r '.files | to_entries | map("\(.key): Uncovered:\(.value.not_covered)") | .[]' | grep -v "Uncovered:null" | cat

.PHONY: fmt
fmt: ## Apply default formatting to all rego files. Use before you commit
	@$(OPA) fmt . --write

.PHONY: fmt-amend
fmt-amend: fmt ## Apply default formatting to all rego files then amend the current commit
	@git --no-pager diff $$(git ls-files '*.rego')
	@echo "Amend commit '$$(git log -n1 --oneline)' with the above diff?"
	@read -p "Hit enter to continue, Ctrl-C to abort."
	git add $$(git ls-files '*.rego')
	git commit --amend --no-edit

.PHONY: opa-check
opa-check: ## Check Rego files with strict mode (https://www.openpolicyagent.org/docs/latest/strict/)
	@$(OPA) check $(TEST_FILES) --strict

.PHONY: conventions-check
conventions-check: ## Check Rego policy files for convention violations
	@OUT=$$($(OPA) eval --data checks --data $(POLICY_DIR)/lib --input <($(OPA) inspect . -a -f json) 'data.checks.violation[_]' --format raw); \
	if [[ -n "$${OUT}" ]]; then echo "$${OUT}"; exit 1; fi

.PHONY: ready
ready: fmt-amend ## Amend current commit with fmt changes

#--------------------------------------------------------------------
# The idea here is to use some real live recorded attestations in our tests.
# If the attestation files in https://github.com/conforma/hacks/provenance/recordings
# change, you can use `make sync-test-data` to sync the changes to this one local rego file.
RECORDED_ATT_DATA=policy/lib/tekton/recorded_att_data_test.rego

# Clears the file, adds the package command and some other preamble.
_init-test-data:
	@echo Initializing $(RECORDED_ATT_DATA)
	@( \
	  echo '# ** Do not edit this file. Regenerate it using `make sync-test-data` **'; \
	  echo ''; \
	  echo 'package lib.tekton_test'; \
	  echo 'import rego.v1'; \
	) > $(RECORDED_ATT_DATA)

# Appends one assignment to the file and then uses opa fmt to tidy it up.
# Use some bash tricks to convert to lowercase and to replace '-' chars with '_'.
_test-data-%:
	@echo Adding data from $*
	@( FILE="$*" && \
	   FILE_LOWER="$${FILE,,}" && \
	   REGO_VAR="att_$${FILE_LOWER//-/_}" && \
	   echo -n "$$REGO_VAR := " && \
	   curl -sL https://raw.githubusercontent.com/conforma/hacks/main/provenance/recordings/$*/attestation.json | jq . \
	) >> $(RECORDED_ATT_DATA)
	@opa fmt --write $(RECORDED_ATT_DATA)

# There are some other attestation files in https://github.com/conforma/hacks/provenance/recordings
# but these two are the most useful for testing currently
_sync-test-data-01: _test-data-01-SLSA-v0-2-Pipeline-in-cluster
_sync-test-data-05: _test-data-05-SLSA-v1-0-tekton-build-type-Pipeline-in-cluster

sync-test-data: _init-test-data _sync-test-data-01 _sync-test-data-05 ## Refresh policy/lib/tekton/test_data.rego
	@echo Done updating $(RECORDED_ATT_DATA)

#--------------------------------------------------------------------

##@ Documentation

.PHONY: annotations-opa
annotations-opa:
	@$(OPA) inspect --annotations --format json ./policy | jq '.annotations | sort_by(.location.file, .location.row)'

SHORT_SHA=$(shell git rev-parse --short HEAD)

generate-docs:  ## Generate static docs
	@cd docs && go run github.com/conforma/policy/docs -adoc ../antora/docs/modules/ROOT -rego .. -rego "$$(go list -modfile ../go.mod -f '{{.Dir}}' github.com/conforma/cli)/docs/policy/release"

##@ CI

.PHONY: fmt-check
fmt-check: ## Check formatting of Rego files
	@$(OPA) fmt . --list | xargs -r -n1 echo 'FAIL: Incorrect formatting found in'
	@$(OPA) fmt . --list --fail >/dev/null 2>&1

# See config in .regal/config.yaml
.PHONY: lint
lint: ## Runs Rego linter
# addlicense doesn't give us a nice explanation so we prefix it with one
	@go run github.com/google/addlicense -c '$(COPY)' -y '' -s -check $(LICENSE_IGNORE) . | sed 's/^/Missing license header in: /g'
# piping to sed above looses the exit code, luckily addlicense is fast so we invoke it for the second time to exit 1 in case of issues
	@go run github.com/google/addlicense -c '$(COPY)' -y '' -s -check $(LICENSE_IGNORE) . >/dev/null 2>&1
	@go run github.com/open-policy-agent/regal lint . $(if $(GITHUB_ACTIONS),--format=github)

.PHONY: lint-fix
lint-fix: ## Fix linting issues automagically
	@go run github.com/google/addlicense -c '$(COPY)' -y '' -s $(LICENSE_IGNORE) .

.PHONY: ci
ci: quiet-test acceptance opa-check conventions-check fmt-check lint generate-docs ## Runs all checks and tests

#--------------------------------------------------------------------

##@ Data helpers

.PHONY: clean-input
clean-input: ## Removes everything from the `./input` directory
	@rm -rf $(INPUT_DIR)
	@mkdir $(INPUT_DIR)

.PHONY: clean-data
clean-data: ## Removes ephemeral files from the `./data` directory
	@rm -rf $(CONFIG_DATA_FILE)

.PHONY: dummy-config
dummy-config: ## Create an empty configuration
	@echo '{"config":{"policy":{}}}' | jq > $(CONFIG_DATA_FILE)

# Use ec's policy-input output format to produce an accurate input.json for use when
# hacking on rego rules. Add jq for extra readability even though it's less correct.
# A public key is required here because ec has no --ignore-sig option.
#
# Set IMAGE and KEY as required like this:
#   make fetch-att IMAGE=<imageref> KEY=<publickeyfile>
#
ifndef IMAGE
  IMAGE="quay.io/konflux-ci/ec-golden-image:latest"
endif

ifndef KEY
  KEY="../cli/key.pub"
endif

.PHONY: fetch-att
fetch-att: clean-input ## Fetches attestation data and metadata for IMAGE, use `make fetch-att IMAGE=<ref> KEY=<keyfile>`
	@$(EC) validate image --image $(IMAGE) \
	  --public-key <(cat $(KEY)) --ignore-rekor \
	  --output policy-input | jq > $(INPUT_FILE)

#--------------------------------------------------------------------

# A convenient way to populate input/input.json with a pipeline definition
# Specify PIPELINE as an environment var to use something other than the default.
#
ifndef PIPELINE
  PIPELINE=quay.io/konflux-ci/tekton-catalog/pipeline-docker-build:devel
endif

.PHONY: fetch-pipeline
fetch-pipeline: clean-input ## Fetches pipeline data for PIPELINE from your local cluster, use `make fetch-pipeline PIPELINE=<name>`
	@$(TKN) bundle list $(PIPELINE) -o json > $(INPUT_FILE)

#--------------------------------------------------------------------

##@ Running

INPUT_DIR=./input
INPUT_FILE=$(INPUT_DIR)/input.json

ifndef NAMESPACE
	NAMESPACE_FLAG=--all-namespaces
else
	NAMESPACE_FLAG=--namespace $(NAMESPACE)
endif

.PHONY: check-release
check-release: ## Run policy evaluation for release
	@$(CONFTEST) test $(INPUT_FILE) \
	  $(NAMESPACE_FLAG) \
	  --policy $(POLICY_DIR) \
	  --data $(DATA_DIR) \
	  --no-fail \
	  --output json

.PHONY: check-pipeline
check-pipeline: ## Run policy evaluation for pipeline definition
	@$(CONFTEST) test $(INPUT_FILE) \
	  --all-namespaces \
	  --policy $(POLICY_DIR) \
	  --data $(DATA_DIR) \
	  --no-fail \
	  --output json

.PHONY: check
check: check-release

#--------------------------------------------------------------------

##@ Bundles

update-bundles: ## Push policy bundles to quay.io and generate infra-deployments PRs if required
	@hack/update-bundles.sh

#--------------------------------------------------------------------

##@ Acceptance Tests

.PHONY: acceptance
acceptance: ## Run acceptance tests
	@cd acceptance && go test ./...

#--------------------------------------------------------------------

##@ IDE Binaries

bin/ec: go.mod ## Create the EC binary
	@go build -o bin/ec github.com/conforma/cli

bin/regal: go.mod regal.go ## Create the regal binary
	@go build -o bin/regal regal.go

.PHONY: ide-binaries
ide-binaries: bin/ec bin/regal ## Build binaries for IDE integration
#--------------------------------------------------------------------
