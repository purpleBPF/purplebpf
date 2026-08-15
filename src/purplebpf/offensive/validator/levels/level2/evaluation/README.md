# Level 2 Evaluation Framework

This package evaluates the existing Level 2 static Validator. It never executes
the commands in the dataset and does not import or evaluate Level 3.

## Run

From the repository root:

```bash
PYTHONPATH=src python -m \
  purplebpf.offensive.validator.levels.level2.evaluation.evaluate
```

The default human-readable report is printed to stdout and the machine-readable
result is written to `results/latest.json`.

Alternative inputs and outputs can be selected explicitly:

```bash
PYTHONPATH=src python -m \
  purplebpf.offensive.validator.levels.level2.evaluation.evaluate \
  --dataset path/to/ground_truth.json \
  --output path/to/result.json
```

Use `--no-write` to print metrics without creating a result file.

## Dataset

`data/ground_truth.json` contains exactly 100 human-authored cases:

- 60 Full cases: 10 each for `chmod`, `unshare`, `nsenter`, `mount`, `curl`,
  and `kill`
- 25 Metadata cases: 5 each for `wget`, `cat`, `pkill`, `grep`, and `tar`
- 15 composition cases covering lists, pipelines, nested `bash/sh -c`, generic
  commands, quoting, and escaping

Expected values are never produced from Validator output. Valid edge cases that
are outside the current approved metadata or semantic subset remain in the
dataset so regressions and coverage gaps are visible.

## Comparison

- Command extraction compares a multiset of raw executable names and separately
  checks canonical traversal order.
- CLI validation compares expected and actual three-state validity, but accuracy
  is measured only where Ground Truth supplies a boolean validity label.
- Elements are compared as complete canonical objects, including operand
  position and the owning option of an option value.
- Resources include their `requires` or `produces` role before canonical set
  comparison.
- Facts are compared as complete canonical objects, including identity,
  attributes, and evidence.
- Tier labels are compared per invocation and accumulated into an
  expected-by-actual confusion matrix.

Precision, recall, and F1 use micro-aggregated TP/FP/FN counts across the whole
dataset. A per-subject metric with no applicable positive objects has zero
counts; its numeric zero should be read as not assessed rather than a detected
failure. Applicability can be checked using the accompanying `tp`, `fp`, `fn`,
or `total` fields.

Every mismatch is retained in the JSON `failures` list with its testcase ID and
missing, unexpected, expected, or actual values.
