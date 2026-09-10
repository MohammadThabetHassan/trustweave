package authz_test

import data.authz

test_untrusted_external_denied if {
	authz.decision == "deny" with input as {"source_trust": "untrusted", "action_class": "external"}
}

test_untrusted_sensitive_denied if {
	authz.decision == "deny" with input as {"source_trust": "untrusted", "action_class": "sensitive"}
}

test_conditional_external_requires_approval if {
	authz.decision == "require_approval" with input as {"source_trust": "conditional", "action_class": "external"}
}

# Exercises the default line -- so it is "covered" -- without pinning what it returns.
test_trusted_read_is_allowed if {
	authz.decision == "allow" with input as {"source_trust": "trusted", "action_class": "read"}
}
