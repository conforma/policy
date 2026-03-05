package lib.utils

import rego.v1

# sigstore_opts provides a safe way to access the default sigstore opts. It ensures policy rules
# don't accidentally evaluate to passing if the default values are not in the config.
default sigstore_opts := {
	"certificate_identity": "",
	"certificate_identity_regexp": "",
	"certificate_oidc_issuer": "",
	"certificate_oidc_issuer_regexp": "",
	"ignore_rekor": false,
	"public_key": "",
	"rekor_url": "",
}

sigstore_opts := data.config.default_sigstore_opts
