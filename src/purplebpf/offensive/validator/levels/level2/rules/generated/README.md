# Generated CLI metadata candidates

This directory is reserved for development-time metadata candidates produced by
`python -m levels.level2.tools.metadata_generator`.

Candidates remain `PENDING` until a human reviews their option aliases, value
requirements, operand bounds, command version, and source provenance. The
runtime `JsonMetadataProvider` reads only `../cli_metadata.json`; it never reads
files from this directory.

Approved subsets are copied manually into `cli_metadata.json` with
`review_status: "APPROVED"` provenance. Candidate generation itself never
promotes or merges metadata.
