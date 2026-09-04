package authz

# Default permits. `allow` is reachable ONLY through this line -- no rule produces it.
default decision := "allow"

decision := "deny" if {
	input.source_trust == "untrusted"
	input.action_class == "external"
}

decision := "deny" if {
	input.source_trust == "untrusted"
	input.action_class == "sensitive"
}

decision := "require_approval" if {
	input.source_trust == "conditional"
	input.action_class == "external"
}
