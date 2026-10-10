# Changelog

Changes are documented in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.
Before 1.0, minor releases may contain breaking changes, listed explicitly below.

## Unreleased

### Breaking

- Write schema v2 manifests in a nested, identity-specific layout. Reads are grouped as `self`, `resolver`, and `other`; open counters drop the `openat_` prefix. Reports still read v1; v1 reading is planned for removal at 1.0.
- Run targets in disposable home/project directories with decoy credentials and a reduced environment. Use `--real-home` or `--cwd DIR` to select real directories explicitly.
- Distinguish target failures and timeouts (exit 1), fatal observation failures (exit 2, with `--strict` also reporting nonfatal observer errors), policy violations (exit 3), and invalid usage (exit 64).
- Record observer failures in `observer_errors` separately from target `errors`; add target exit, signal, and timeout metadata.
- Default to a 600-second install timeout and a 60-second require timeout. Limit stored stdout and stderr to 1 MiB each; expose truncation flags.

### Added

- Add best-effort syscall policy refusal, other-process signal observations, working-directory build attribution, and own-package write classification.
- Add verbose diagnostics, optional container-only execution, and a validated local ranking snapshot fallback.
- Add Markdown report contents, severity-ordered findings, and folded target details; separate Markdown, JSON, SARIF, CSV, and HTML formatters while preserving report APIs.
- Observe declared Bundler plugins in a separate `bundler_plugin` phase through Bundler's registration API, with isolated configuration, matching baselines, and all-phase resume/approval checks.
- Compare observations across separate Ruby container runtimes and preserve runtime identity in saved results.
- Add fail-closed sinkhole observations with fake DNS, HTTP request samples, TLS SNI, canary redaction, and authenticated helper results.
- Add full-manifest golden contracts and the fourteen-scenario adversarial gem fixture suite.
- Prepare OIDC artifact attestations for the opt-in sharded dataset workflow.
- Add an opt-in Bundler pre-install plugin that requires frozen, exactly approved package observations and stops on incomplete results or policy violations.

- Stream aggregate report counts without retaining every manifest body in memory.
- Observe additional open/exec/file-change syscalls, process creation, listeners, datagram destinations, bounded DNS questions, selected sensitive syscalls, and io_uring attempts.
- Add decoded JSONL timelines, process relationships, environment profiles, write-only observations, and parallel survey workers.
- Add repeated observations with retained samples and stable/flaky capability summaries; scope resume to complete groups and matching execution settings.
- Observe explicit shell-free commands and declared RubyGems executables with literal arguments.
- Add an optional Prism source scan for command, network, and eval call sites, with approximate observation matching.
- Add capability diffs, gem/version and lockfile comparisons, history, validated YAML policy rules, capability approval locks, and JSON/HTML/CSV/SARIF output.
- Add a production container and SHA-pinned composite Action for changed lockfile dependencies.
- Configure multi-platform image publishing with provenance/SBOM attestations, live top-20 nightly surveys, and opt-in GitLab/Lefthook examples; add shell completions and a Japanese onboarding guide.
- Add a `--docker` launcher with restricted mounts, a bundled seccomp profile, container resource bounds, and per-target hard resource limits.
- Add network namespaces with explicit syscall fallback, tracked descendant cleanup, and optional Landlock filesystem/TCP enforcement.
- Add local dataset pages, search, JSON/RSS change feeds, factual badges, CycloneDX augmentation, and watchlist monitoring with retryable atomic checkpoints.
- Add an inactive, digest-pinned example workflow for sharded surveys and an observation review/correction guide.
- Add package prefetching outside observation, phase-specific baselines, and `--phase all` for linked install and require observations.
- Add package platform selection, package/dependency metadata, a capability matrix, canary detection, JSON Schema, and non-destructive `migrate` support.
- Add manifest compatibility documentation and an explicit threat model.
- Add version output, command-specific help, concise dig summaries, and expanded environment diagnostics.
- Add `--strict`, `--quiet-target`, `--output-limit`, and `--argv-limit` options.
- Report argv truncation and normalize paths in command arguments.
- Test Ruby 3.2 through 4.0 on x86_64 and aarch64 Linux; run Standard and measure coverage with SimpleCov.
- Add contribution and security reporting guides, issue templates, and gem metadata links.

### Fixed

- Resume surveys using manifest identity instead of filename prefixes; retry failed, incomplete, or unreadable results.
- Accept gem names containing dots and reject unsupported git/path sources in lockfile surveys.
- Record unknown socket address families without turning successful targets into failures.
- Retain attempted reads of sensitive paths even when the files do not exist.
- Normalize procfs task paths and exclude XDG RubyGems caches from notable files.
- Resolve relative paths using the target working directory and decode openat directory descriptors as integers.
- Isolate each survey entry in a worker process and record killed workers without stopping the survey.
- Improve require-path inference, dependency isolation, installed gem metadata, and failure reporting.
- Safely store binary target output as UTF-8 and include target output and network attempts in reports.

### Changed

- Add pinned repository automation for linting, dependency updates, security analysis, and trusted publishing.

## [0.1.0] - 2026-09-09

### Added

- Initial release: observe gem install and require activity using seccomp user notifications.
- Capture file, network, command, and thread activity with startup baseline subtraction and path normalization.
- Provide doctor, baseline, dig, survey, and Markdown report commands.

[0.1.0]: https://github.com/ydah/bonebed/releases/tag/v0.1.0
