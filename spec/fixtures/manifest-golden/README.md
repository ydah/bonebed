# Whole-manifest expected output

`spec/manifest_golden_spec.rb` constructs synthetic Collector observations, subtracts a fixed startup
baseline, runs ManifestBuilder, redacts real randomly generated honeypot tokens, and adds default-policy
findings. It compares the entire resulting document to these JSON files and validates both documents
against manifest schema v2. Empty arrays, nulls, field presence, counts, ordering, paths, error details,
truncation, metadata, and findings are part of the contract.

The quiet require profile retains one package file read after baseline subtraction. The suspicious
install profile exercises every current Collector event group, native/plugin metadata, independent
target and observer errors, repeated counts, path normalization, binary output repair, and canary
redaction across multiple fields, including bounded HTTP samples and TLS destination intent.
`package.txt` supplies fixed bytes for SHA-256 coverage; it is not an
installable gem and is never executed. Times, PIDs, virtual paths, package versions, and baseline IDs
are fixed input data.

Only Bonebed/seccomp-notify versions, Ruby/architecture/kernel information, and measured wall time are
normalized. The test first checks the runtime metadata against the current environment and retains all
fields. It does not normalize event counts, capabilities, paths, output, finding text, or canary hits.

There is no automatic update or regeneration switch. For an intentional format change, inspect the
test's complete diff, update the synthetic profile when necessary, and edit the expected JSON explicitly.
Review both profiles, including newly added empty fields, and run:

```sh
bin/dev bundle exec rspec spec/manifest_golden_spec.rb
```

These deterministic contracts complement the real syscall/adversarial integration tests; they do not
claim that synthetic input demonstrates live kernel coverage.
