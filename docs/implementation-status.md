# Roadmap implementation status

This page describes the source checkout after the October 2026 implementation work. The package version
remains 0.1.0 while these changes are unreleased. Implementing a feature is separate from meeting a
release's performance, deployment, and ecosystem acceptance conditions. No claim is made that every
catalog item or all six release milestones are complete.

## Implemented foundations

| Roadmap phase | Implemented source and local verification | Acceptance work still required |
| --- | --- | --- |
| 0: correctness and hygiene | Sensitive-path retention, socket-family handling, path/argv normalization, manifest-based resume, separated errors, CLI statuses/help, bounded capture, Standard/SimpleCov with an 85% full-suite CI floor, ARM/x86 CI configuration, documentation and templates | All eight hosted CI matrix jobs must pass on the final commit; release version/tag/publication and presentation measurements are separate |
| 1: observation accuracy | Prefetch before observation, phase-specific baselines, disposable honeypot environments, `all`, package metadata, schema v2/migration, capability matrix, manifest/threat-model docs, benchmark task, full-manifest golden contracts, fourteen-scenario adversarial fixtures | Broader representative-gem acceptance and the broader acceptance corpus |
| 2: observation coverage | Additional filesystem/exec syscalls, process tracking, UDP destinations and bounded DNS, listeners, selected sensitive calls and io_uring denial, separate RubyGems/Bundler plugin phases, executables, environment profiles, trace output, write-only mode, parallel surveys, repeated samples with stability summaries | Remaining catalog options, supported-architecture verification, and the roadmap's measured overhead budget |
| 3: diffs, policies, and CI | Capability keys/diffs, version and lockfile comparisons, history, YAML rules, approval locks, SARIF and other report formats, local bundle-install observation, a production container, composite Action, fixed-fixture/live top-20 nightly jobs, optional Prism source hints, GitLab/Lefthook examples | Hosted end-to-end Action runs in a separate integration repository, a reviewed release image/tag, policy calibration, and production workflow rollout |
| 4: isolation and enforcement | Network namespace wrapper with explicit fallback, delegated cgroup cleanup with tracked fallback, fail-closed DNS/HTTP/TLS sinkhole, Landlock filesystem/TCP rules, enforcement draft generation, explicit command observation, container launcher, resource limits, runtime diagnostics, optional Bundler approval plugin | Real delegated-cgroup acceptance on a writable host, remaining integration modes, and verification on restricted/older kernels |
| 5: local dataset tools | Static searchable export, JSON/RSS changes, factual Shields data, CycloneDX properties, watchlist monitoring with retryable checkpoints, streaming report summaries, an inactive sharded survey workflow with artifact attestation | Public top-1000 data collection, ongoing hosted monitoring, signatures, published site/feed, author-review operations, and measured survey success rate |

Local regressions exercise real seccomp observations, schema validation, namespace UDP rejection,
Landlock allow/deny behavior and exec inheritance, detached-child cleanup, policy/formatting behavior,
dataset escaping, and monitoring retry/state handling. Run `bin/dev bundle exec rake` on the final
checkout for the authoritative test result; do not infer hosted CI success from a local run.

Report rendering is separated into Markdown, JSON, SARIF, CSV, and HTML formatters (QA-12).
Markdown includes a contents list, policy findings ordered by severity, and folded target details
(OUT-09); capabilities without a matching rule remain unclassified.

Additional implemented interfaces include best-effort `--deny` policy refusal, `--docker --ruby`
runtime comparisons with separate results, `--verbose` diagnostics, optional host-execution refusal,
and a validated local snapshot fallback for ranking requests. Recorded process working directories
support package attribution during native builds and bundle installs; this inference is separate from
exact per-dependency event attribution. Own-package writes remain visible to policies and have a
separate classification. Other-process `kill` attempts are observed; signal-zero probes are trace-only.

The development-container observation of `rainbow` 3.1.1 installation produced zero network events
and one retained read for its input `.gem`. This demonstrates a specific baseline result, not a
universal noise guarantee. The [top-20 validation record](validation.md) includes successful native builds and platform loading. Performance acceptance needs before/after measurements on the same host
for pure Ruby and native-extension gems, not one sample or total test duration.

## Known limits and unimplemented catalog items

- Dedicated cgroup termination is implemented, but same-user processes that can write cgroup controls can migrate out. Read-only cgroup hosts use tracked cleanup, which can miss an unobserved fork/reparent race. A real delegated-cgroup integration test remains pending on the local read-only mount.
- Sinkhole HTTP Host/path/body-canary and TLS SNI observation is implemented and locally exercised. It serves DNS-based ports 80/443 only; arbitrary IP/port redirection and sinkhole trace output are not supported.
- DNS over TCP/HTTPS and arbitrary encrypted application traffic are not decoded.
- Best-effort denial has argument/path races and unobserved routes; it is not a security boundary.
  `tkill`, `tgkill`, and `pidfd_send_signal` are not covered by the `kill` observation.
- Static dataflow and dynamic-dispatch analysis, exact per-dependency execution attribution, and all cataloged syscall families are not complete. The implemented Prism scan reports selected syntactic call sites only. The `bundler_plugin` phase observes a declared plugin's real Bundler registration and loaded dependencies, including installation work. It does not invoke every registered command/hook. The separate optional Bundler approval plugin checks saved observations before frozen installation and does not protect Gemfile evaluation before its hook.
- The appendix-D synthetic scenarios have executable fixtures and assertions; see [the local validation record](validation-adversarial.md). They do not establish a real-world detection rate. Mutation testing and a multi-kernel CI matrix remain outstanding.
- Public top-1000 multi-version datasets, automated release-monitor hosting, registry notification workflows, community capability approvals, and a published discovery site are not deployed by the local tools. The release workflow requests container provenance/SBOM attestations, but no release image or attestation for these changes has been published and verified; the inactive dataset template also requests archive attestations, but an actual signed dataset run and verification remain outstanding.
- The v1.0 schema/CLI compatibility promise, at least 95% top-1000 survey success, and all-scenario detection acceptance have not been established.
- Optional catalog work still includes parallel notification handlers, filesystem metadata caches,
  RBS/Steep typing, additional YAML environment profiles and automatic profile comparisons, and
  measured rootless Podman/Lima/Colima acceptance. The current profiles are `dev`, `ci`, and `prod`;
  diagnostics have ordinary and verbose levels. Performance changes require representative measurements.

See [policies](policies.md), [the threat model](threat-model.md), [CI integration](ci.md), and
[datasets](dataset.md) for the implemented interfaces and their practical limits.

## Research track

General ADDFD open emulation (beyond the synthetic resolver), ptrace/eBPF backends, Ruby require-boundary probes, native executable-memory
tracking, time-shifted execution, statistical anomaly scoring, and native macOS observation remain
research work. The Linux container path is the supported route on macOS; a container does not make
the Linux observer a native macOS implementation.

## Release gates

Before cutting any milestone release, run the final Linux suite without pending integration examples,
complete its hosted Ruby/architecture matrix, validate representative surveys and manifest compatibility,
record required performance/detection measurements, review security assumptions, and update the version
and dated changelog. Only then perform the explicit tag/publication steps. Later milestone numbers in
the roadmap describe acceptance targets; they are not versions already published by this checkout.
