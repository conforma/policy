package lib.k8s_test

import rego.v1

import data.lib.utils
import data.lib
import data.lib.k8s

test_name if {
	utils.assert_equal(k8s.name({}), "noname")
	utils.assert_equal(k8s.name(""), "noname")
	utils.assert_equal(k8s.name(123), "noname")

	utils.assert_equal(k8s.name({"metadata": {"name": "spam"}}), "spam")
}

test_version if {
	utils.assert_equal(k8s.version({}), "noversion")
	utils.assert_equal(k8s.version(""), "noversion")
	utils.assert_equal(k8s.version(123), "noversion")

	utils.assert_equal(
		k8s.version({"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}}}),
		"1.0",
	)
}

test_name_version if {
	utils.assert_equal(k8s.name_version({}), "noname/noversion")
	utils.assert_equal(k8s.name_version(""), "noname/noversion")
	utils.assert_equal(k8s.name_version(123), "noname/noversion")

	utils.assert_equal(k8s.name_version({"metadata": {"name": "spam"}}), "spam/noversion")

	utils.assert_equal(
		k8s.name_version({"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}}}),
		"noname/1.0",
	)

	utils.assert_equal(
		k8s.name_version({"metadata": {"name": "spam", "labels": {"app.kubernetes.io/version": "1.0"}}}),
		"spam/1.0",
	)
}
