# Protocol: certifying the inside verdicts call by call

This protocol was written before the census it describes read any corpus, and
`scripts/guard_certification.py` refuses to run unless this file hashes to the value fixed in the
script. Like the paper's other protocols, it is a hash the authors recorded in the same working
session, not an externally timestamped registration.

## Why

The membership adapters accept a guard family by name. For most families finite refinement holds
whatever fills the operands. For patterns, products and some string operations it holds only when
an operand is a literal, and no adapter checks that. Rego's and Kyverno's adapters do not record
families per call at all. This census reads every guard call of every artifact the adapters judge
inside, records the kind of each operand, and certifies the verdict only when every call meets the
rule below.

## Population

The 5,175 artifacts judged inside in the committed membership artifacts behind Table 1
(`exclusion_taxonomy.CORPORA`). They are read from the corpora at the commits those artifacts
record, cloned by `scripts/clone_pinned_corpora.py`, and from the third-party Kyverno files at
their recorded digests. An artifact whose text cannot be recovered is reported as such.

## Operand kinds

An operand is one of three kinds:

- a **literal**: a constant the policy writes, including a parameter's default;
- a **read**: of the request, through a designator, field, path or reference;
- **computed**: anything else, such as a local variable, a nested call or a comprehension.

A nested call is certified first, on its own operands.

## The rule, per language

A call is certified when its family is **operand-free**, or when it is **literal-operand** and the
named operand is a literal. Any other call is uncertified. An artifact is certified when every
call in its guards is certified. The census records the first uncertified call.

### XACML

The family is the function's local name, matched by suffix as the adapter matches it.

- **Operand-free:**
  - equality and order;
  - `one-and-only`, `bag`, `bag-size`, `is-in`, `at-least-one-member-of`, `subset`, `set-equals`,
    `intersection`, `union`;
  - `and`, `or`, `not`, `n-of`;
  - the higher-order `any-of`, `all-of`, `any-of-any`, `all-of-any`, `any-of-all`, `all-of-all`,
    when their function is certified;
  - `add`, `subtract`, `abs`, `floor`, `round` and the numeric and string conversions;
  - `normalize-space`, `normalize-to-lower-case`;
  - `ip-in-range`, `dnsName-value-equal`.
- **Literal-operand:**
  - `regexp-match`, `starts-with`, `ends-with`, `contains`, `rfc822Name-match` and
    `x500Name-match`: the first argument, which is the pattern;
  - `multiply`, `divide` and `mod`: at least one argument;
  - duration arithmetic: the duration;
  - `substring`: both positions;
  - `string-concatenate`: all but at most one argument;
  - `map`: its function must be an operand-free unary one.

### Azure Policy

- **Operand-free leaf operators:** `equals`, `notEquals`, `in`, `notIn`, `less`, `lessOrEquals`,
  `greater`, `greaterOrEquals`, `exists`, `containsKey` and `notContainsKey`.
- **Literal-operand leaf operators:** `like`, `notLike`, `match`, `notMatch`,
  `matchInsensitively`, `notMatchInsensitively`, `contains` and `notContains`. The operand must be
  a literal.
- **Template expressions.** A template expression is certified when it reads at most one field,
  through `field()` or `current()`, and every other argument is a literal. Its functions must also
  all be among the following:
  - `field`, `current`, `parameters` (with a default), `requestContext`, and `subscription` and
    `resourceGroup` (their id properties only);
  - `concat`, `split`, `replace`, `toLower`, `toUpper`, `substring`, `first`, `last`, `length`,
    `empty`, `contains`, `startsWith`, `endsWith`, `indexOf`;
  - `if`, `equals`, `less`, `lessOrEquals`, `greater`, `greaterOrEquals`, `and`, `or`, `not`;
  - `int`, `string`, `bool`, `tryGet`, `createArray`, `createObject`, `array`, `union`,
    `intersection`, `ipRangeContains`.

### AWS IAM

Every condition operator is operand-free or a pattern the policy writes. A pattern containing a
policy variable (`${...}`) is certified when it contains at most one variable occurrence.

### Cedar

Certified by its designers' sound and complete logical encoding of the language. The census reads
no Cedar call.

### Rego

The calls are those in the rules the adapter's propagation reaches from the module's own rules,
read from the AST `opa parse` gives.

- **Operand-free:**
  - `equal`, `neq`, `lt`, `lte`, `gt`, `gte`;
  - `plus`, `minus`, `abs`, `round`, `ceil`, `floor`;
  - `count`, `max`, `min`;
  - `and`, `or`, `intersection`, `union`, `object.get` with a literal key;
  - `lower`, `upper`, `trim_space`;
  - the type tests (`is_string` and the rest, and `type_name`);
  - `array.concat`.
- **Literal-operand:**
  - `startswith`, `endswith`, `contains` and `glob.match`: the pattern;
  - `regex.match`: the pattern;
  - `trim`, `trim_left`, `trim_right`, `trim_prefix` and `trim_suffix`: the cutset or affix;
  - `split`: the separator;
  - `mul`, `div` and `rem`: one operand;
  - `net.cidr_contains`: the network.
- Unification and assignment (`eq`, `assign`) and the membership operators
  (`internal.member_2`, `internal.member_3`) are operand-free.
- Any other builtin is uncertified.
- A call whose named operand is a variable bound only to a literal counts as having a literal.
- A read of the policy's own parameters (`input.parameters`, or a Config Validator Constraint's
  `spec.parameters`) counts as a literal, because an instantiation fixes it.
- A call whose result is bound to a variable that is used only in the rule's head, typically a
  message, is output, not a guard, and is not checked.

### Kyverno

- `pattern` and `anyPattern` overlays are patterns the policy writes, so they are certified.
- Condition operators are operand-free.
- `message` and `messageExpression` fields are output, not guards, and are not checked.
- **JMESPath** (`{{ }}`) and **CEL** expressions are certified when they read at most one request
  path and every function they use is listed below, with the named argument a literal:
  - **JMESPath, operand-free:** `to_upper`, `to_lower`, `length`.
  - **JMESPath, literal-operand:** `contains`, `starts_with` and `ends_with` (the second
    argument); `regex_match` (the first); `split` (the separator).
  - **CEL, operand-free:** `size`, `has`, `exists`, `all`, `exists_one`, `in`, `lowerAscii`,
    `upperAscii`.
  - **CEL, literal-operand:** `startsWith`, `endsWith`, `contains` and `matches` (the argument);
    `split` (the separator).

## Outcomes

This is a descriptive census with no hypothesis. It reports:

- the certified share of the inside verdicts, per corpus and pooled;
- the uncertified families, with their counts;
- the artifacts whose text could not be recovered.

The paper reports the certified count beside the inside count.

## Deviations

Any departure from this protocol is recorded in the artifact, with its reason.
