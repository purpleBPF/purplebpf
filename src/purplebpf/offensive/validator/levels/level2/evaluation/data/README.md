# Level 2 Ground Truth

`ground_truth.json` is a human-authored static-analysis dataset. Expected values
must not be generated from or rewritten to match current Validator output.

Each expected command is listed in canonical extraction order. Detailed fields
are evaluated only when present:

- `tier`: support-tier classification
- `cli_valid` and `error_code`: CLI validation
- `elements`: option, option value, and operand mapping
- `resources`: role-preserving `requires` and `produces`
- `facts`: complete normalized fact objects

Invalid cases intentionally omit elements/resources/facts because mapping stops
at the first canonical CLI error. Composition cases focus on extraction order
and Tier classification.
