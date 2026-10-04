# Protocol: the exact adequacy of real Rego suites, extended to policy schemas

This protocol extends `EXACT_ADEQUACY_PROTOCOL_REGO.md` (the *primary protocol*) to a second
population. It was written and committed while the primary study was running and before any of
its results, primary or secondary, had been read, and `scripts/rego_exact_study.py` refuses to run
on this population unless this file hashes to the value fixed in the script. It changes nothing in
the primary protocol, whose population, measures and headline stand as written.

## Why a second population

The primary study takes the 18 suite-study modules the membership measurement judged inside the
fragment. 26 of the other 31 are **policy schemas**: their guards are stated against parameters
a Constraint supplies, so the module alone determines no decision function. But their suites do
not test them alone: every test supplies the parameters (`input.parameters`), which instantiates
the schema into a policy. The primary protocol already decides equivalence per instantiation of a
module's own suite, so the same procedure applies to a schema without change, and it covers the
suites the paper otherwise reports only by their raw kill rate.

## The population

The suite study's measured modules whose verdict in `docs/fragment-membership-rego-wide-v1.json`
is *outside* with the reason that the module is a policy schema: 26 modules. The 5 that read
`data.inventory` stay excluded. There is no development module in this population: the procedure
is the primary protocol's, run unchanged.

**Erratum to the primary protocol.** It describes the 31 modules outside its population as 25
schemas and 6 that read `data.inventory`; the membership artifact says 26 and 5. The primary
population is defined by the *inside* verdict, so its 18 modules are unaffected; the miscount is
recorded here rather than corrected there, because that file's hash fixes it as it was written.

## The procedure, the measures and the headline

Exactly the primary protocol's: instantiations recorded from the suite, the witness space per
instantiation (parameters read as the constants the instantiation fixes), the 250,000-cell cap,
the three completeness checks, kills as the suite study judges them, the buckets, the exact
score, the killing inputs and the closing of the gaps. A schema whose suite supplies no
parameters at all is instantiated by its parameters being absent, as any module is.

Results are reported as a **secondary population**, beside the primary one and never pooled into
its headline. A statement about the suite study's 48 modules as a whole is made only as the two
populations side by side, with the 5 excluded modules named.
