# Changelog

Changes are documented in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.
Before 1.0, minor releases may contain breaking changes, listed explicitly below.

## Unreleased

### Breaking

- Distinguish target failures and timeouts (exit 1), observation failures (exit 2 with `--strict`), and invalid usage (exit 64). Reserve exit 3 for future policy violations.
- Record observer failures in `observer_errors` separately from target `errors`; add target exit, signal, and timeout metadata.
- Default to a 600-second install timeout and a 60-second require timeout. Limit stored stdout and stderr to 1 MiB each; expose truncation flags.

### Added

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
