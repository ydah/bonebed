# Roadmap implementation status

This page describes the source checkout after the October 2026 implementation work. The package version
remains 0.1.0 while these changes are unreleased. Implementing a feature is separate from meeting a
release's performance, deployment, and ecosystem acceptance conditions. No claim is made that every
catalog item or all six release milestones are complete.

## Implemented foundations

| Roadmap phase | Implemented source and local verification | Acceptance work still required |
| --- | --- | --- |
| 0: correctness and hygiene | Sensitive-path retention, socket-family handling, path/argv normalization, manifest-based resume, separated errors, CLI statuses/help, bounded capture, Standard/SimpleCov with an 85% full-suite CI floor, ARM/x86 CI configuration, documentation and templates | All eight hosted CI matrix jobs must pass on the final commit; release version/tag/publication and presentation measurements are separate |
| 1: observation accuracy | Prefetch before observation, phase-specific baselines, disposable honeypot environments, `all`, package metadata, schema v2/migration, capability matrix, manifest/threat-model docs, benchmark task | Broader representative-gem acceptance, complete adversarial-fixture detection measurement, full-manifest golden coverage, and the broader acceptance corpus |
| 2: observation coverage | Additional filesystem/exec syscalls, process tracking, UDP destinations and bounded DNS, listeners, selected sensitive calls and io_uring denial, RubyGems plugins/executables, environment profiles, trace output, write-only mode, parallel surveys, repeated samples with stability summaries | Complete syscall catalog, all malicious-fixture scenarios, supported-architecture verification, and the roadmap's measured overhead budget |
| 3: diffs, policies, and CI | Capability keys/diffs, version and lockfile comparisons, history, YAML rules, approval locks, SARIF and other report formats, local bundle-install observation, a production container, composite Action, fixed-fixture/live top-20 nightly jobs, optional Prism source hints, GitLab/Lefthook examples | Hosted end-to-end Action runs in a separate integration repository, a reviewed release image/tag, policy calibration, and production workflow rollout |
| 4: isolation and enforcement | Network namespace wrapper with explicit fallback, tracked descendant cleanup, Landlock filesystem/TCP rules, enforcement draft generation, explicit command observation, container launcher, resource limits, runtime diagnostics | cgroup-based complete tree cleanup, sinkhole networking, remaining integration modes, and verification on restricted/older kernels |
| 5: local dataset tools | Static searchable export, JSON/RSS changes, factual Shields data, CycloneDX properties, watchlist monitoring with retryable checkpoints, an inactive sharded survey workflow example | Public top-1000 data collection, ongoing hosted monitoring, signatures, published site/feed, author-review operations, and measured survey success rate |

Local regressions exercise real seccomp observations, schema validation, namespace UDP rejection,
Landlock allow/deny behavior and exec inheritance, detached-child cleanup, policy/formatting behavior,
dataset escaping, and monitoring retry/state handling. Run `bin/dev bundle exec rake` on the final
checkout for the authoritative test result; do not infer hosted CI success from a local run.

The development-container observation of `rainbow` 3.1.1 installation produced zero network events
and one retained read for its input `.gem`. This demonstrates a specific baseline result, not a
universal noise guarantee. The [top-20 validation record](validation.md) includes successful native builds and platform loading. Performance acceptance needs before/after measurements on the same host
for pure Ruby and native-extension gems, not one sample or total test duration.

## Known limits and unimplemented catalog items

- Full cgroup ownership/termination is not implemented. Tracked cleanup can miss an entirely unobserved fork/reparent race.
- HTTP Host/TLS SNI sinkhole observation and its full canary-exfiltration path are not implemented.
- DNS over TCP/HTTPS and arbitrary encrypted application traffic are not decoded.
- Bundler plugin observation/integration, static dataflow and dynamic-dispatch analysis, exact per-dependency execution attribution, and all cataloged syscall families are not complete. The implemented Prism scan reports selected syntactic call sites only.
- The complete appendix-D malicious gem package suite, a published detection-rate report, mutation testing, and a multi-kernel CI matrix remain outstanding.
- Public top-1000 multi-version datasets, automated release-monitor hosting, registry notification workflows, community capability approvals, and a published discovery site are not deployed by the local tools. The release workflow requests container provenance/SBOM attestations, but no release image or attestation for these changes has been published and verified; dataset artifact signing remains outstanding.
- The v1.0 schema/CLI compatibility promise, at least 95% top-1000 survey success, and all-scenario detection acceptance have not been established.

See [policies](policies.md), [the threat model](threat-model.md), [CI integration](ci.md), and
[datasets](dataset.md) for the implemented interfaces and their practical limits.

## Research track

ADDFD open emulation, ptrace/eBPF backends, Ruby require-boundary probes, native executable-memory
tracking, time-shifted execution, statistical anomaly scoring, and native macOS observation remain
research work. The Linux container path is the supported route on macOS; a container does not make
the Linux observer a native macOS implementation.

## Release gates

Before cutting any milestone release, run the final Linux suite without pending integration examples,
complete its hosted Ruby/architecture matrix, validate representative surveys and manifest compatibility,
record required performance/detection measurements, review security assumptions, and update the version
and dated changelog. Only then perform the explicit tag/publication steps. Later milestone numbers in
the roadmap describe acceptance targets; they are not versions already published by this checkout.
