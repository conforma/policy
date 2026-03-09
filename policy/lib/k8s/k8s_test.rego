package lib.k8s_test

import rego.v1

import data.lib.assertions
import data.lib.k8s

test_name if {
	assertions.assert_equal(k8s.name({}), "noname")
	assertions.assert_equal(k8s.name(""), "noname")
	assertions.assert_equal(k8s.name(123), "noname")

	assertions.assert_equal(k8s.name({"metadata": {"name": "spam"}}), "spam")
}

test_version if {
	assertions.assert_equal(k8s.version({}), "noversion")
	assertions.assert_equal(k8s.version(""), "noversion")
	assertions.assert_equal(k8s.version(123), "noversion")

	assertions.assert_equal(
		k8s.version({"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}}}),
		"1.0",
	)
}

test_name_version if {
	assertions.assert_equal(k8s.name_version({}), "noname/noversion")
	assertions.assert_equal(k8s.name_version(""), "noname/noversion")
	assertions.assert_equal(k8s.name_version(123), "noname/noversion")

	assertions.assert_equal(k8s.name_version({"metadata": {"name": "spam"}}), "spam/noversion")

	assertions.assert_equal(
		k8s.name_version({"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}}}),
		"noname/1.0",
	)

	assertions.assert_equal(
		k8s.name_version({"metadata": {"name": "spam", "labels": {"app.kubernetes.io/version": "1.0"}}}),
		"spam/1.0",
	)
}
