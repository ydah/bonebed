<div align="center">

# Bonebed

Observe file, network, and process capabilities used while installing or requiring Ruby gems.

[![Gem Version](https://img.shields.io/gem/v/bonebed.svg?colorB=319e8c)](https://rubygems.org/gems/bonebed)
[![Downloads](https://img.shields.io/gem/dt/bonebed.svg)](https://rubygems.org/gems/bonebed)
![Ruby 3.2+](https://img.shields.io/badge/Ruby-3.2%2B-CC342D?logo=ruby&logoColor=white)
![Linux](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)

[Features](#features) · [Installation](#installation) · [Quick Start](#quick-start) · [Commands](#commands) · [How It Works](#how-it-works)

[日本語の導入ガイド](README.ja.md)

</div>

---

Bonebed uses Linux seccomp user notifications to observe filesystem changes, network activity, external commands, and process creation while a Ruby gem runs. It subtracts matching startup activity, writes JSON capability manifests, and compares observations across versions or lockfiles.

This README describes the current source checkout. Features listed under `Unreleased` in the [changelog](CHANGELOG.md) are not part of the published 0.1.0 gem. See [implementation status](docs/implementation-status.md) for completed work and remaining roadmap conditions.

> [!WARNING]
> Bonebed is an observation tool, not a security boundary. Pointer arguments can change between inspection and syscall continuation (TOCTOU), so the manifest describes what was observed rather than guaranteeing what happened.
>
> Use a disposable environment without credentials or valuable writable files for unknown gems. Disposable home and project directories reduce accidental exposure; optional Landlock rules restrict supported filesystem operations. The development container mounts this checkout read-write; use it for trusted fixtures. Read the [threat model](docs/threat-model.md) before executing unfamiliar code.

## Features

- Profile install, require, RubyGems plugins, and Bundler plugin registration
- Fetch packages before observation and use phase-specific baselines to remove installation machinery
- Detect access to decoy credentials in disposable home and project directories
- Observe file changes, DNS questions, UDP destinations, listeners, commands, processes, threads, and selected sensitive syscalls
- Subtract cached Ruby and Bundler startup baselines
- Normalize project, home, gem, and temporary paths for comparable manifests
- Survey RubyGems rankings, gem lists, or Bundler lockfiles with resumable results
- Summarize failures, project file access, and commands by survey target as Markdown
- Compare gem versions or lockfiles and check capability policies with Markdown, JSON, HTML, CSV, or SARIF output
- Export a searchable local dataset and monitor a gem watchlist for new releases

## Installation

Install Bonebed from RubyGems:

```bash
gem install bonebed
```

### Requirements

- Linux 5.5 or newer on x86_64 or aarch64
- Ruby 3.2 or newer
- Permission to install a seccomp user-notification filter

Docker must permit Bonebed's seccomp notification filter and any requested namespace setup. The
production wrapper uses the bundled [Docker seccomp profile](contrib/docker-seccomp.json); `bin/dev`
uses `seccomp=unconfined` for development. Bonebed does not run directly on macOS; use a Linux container.

## Quick Start

Run Bonebed in its Linux development container so the gem under observation is not executed directly on the host:

```bash
docker build -f Dockerfile.dev -t bonebed-dev .
bin/dev bundle install
bin/dev bundle exec exe/bonebed doctor
bin/dev bundle exec exe/bonebed dig json
```

The schema v2 manifest is written under `results/PHASE/GEM/`. The first observation also caches a matching phase-specific startup baseline in `.bonebed/baselines/`.

For the production container path, build the current checkout locally; a release image has not been published yet:

```sh
docker build -t bonebed:local .
BONEBED_IMAGE=bonebed:local bundle exec exe/bonebed --docker dig rainbow --phase all --offline
```

Use `--docker ... --ruby 3.3,3.4,4.0` to compare observations across container runtimes; see
[Ruby matrix observations](docs/ruby-matrix.md) for image preparation and comparison limits.

`--docker` mounts the current directory read-only and the results directory read-write. It uses a
read-only image, drops capabilities, and sets container process, memory, and CPU limits. Override
`BONEBED_IMAGE` with a reviewed image digest in automation.

## Commands

| Command | Purpose |
| --- | --- |
| `bonebed --version` | Print the Bonebed version |
| `bonebed doctor` | Check kernel, architecture, seccomp, and container support |
| `bonebed baseline [--refresh]` | Create or refresh the startup baseline |
| `bonebed dig GEM` | Observe a gem while it is required with only its runtime dependency closure visible; common load paths are inferred, or use `--require PATH` |
| `bonebed dig GEM --phase install` | Prefetch packages, then observe local installation in disposable directories |
| `bonebed dig GEM --phase all` | Observe linked install/require phases and detected RubyGems/Bundler plugins in one environment |
| `bonebed dig GEM --phase plugin` | Install a gem and observe RubyGems plugin loading |
| `bonebed dig GEM --phase bundler_plugin` | Install a gem and observe registration through Bundler's plugin API |
| `bonebed dig GEM --phase exec --executable NAME -- ARGS...` | Observe a declared gem executable with literal arguments |
| `bonebed survey --top N` | Observe gems from RubyGems.org's paginated all-time ranking |
| `bonebed survey --file FILE` | Observe gems listed as `NAME [VERSION|-] [REQUIRE_PATH]` |
| `bonebed survey --gemfile Gemfile.lock` | Observe gems from a Bundler lockfile |
| `bonebed run -- COMMAND ARGS...` | Observe an explicit command without an implicit shell |
| `bonebed report results --format md` | Summarize manifests; also accepts JSON, HTML, CSV, or SARIF |
| `bonebed report results --summary` | Stream aggregate counts as JSON without retaining manifest bodies |
| `bonebed diff BEFORE.json AFTER.json` | Compare normalized observed capability keys |
| `bonebed compare GEM VERSION_A VERSION_B` | Observe and compare two gem versions |
| `bonebed diff-lock BASE.lock HEAD.lock` | Observe dependencies whose versions changed in a lockfile |
| `bonebed history GEM --last 5` | Observe and compare recent available versions |
| `bonebed check results --fail-on high` | Evaluate observations against a capability policy |
| `bonebed lock --gemfile Gemfile.lock` | Record approved observed capabilities in a separate lockfile |
| `bonebed policy generate results` | Draft a Landlock enforcement configuration for review |
| `bonebed migrate results` | Convert v1 results to the v2 layout while retaining originals |
| `bonebed dataset results --output site` | Export local gem pages, change feeds, and factual badges |
| `bonebed monitor --file watchlist.txt` | Observe new stable releases and refresh a local dataset |
| `bonebed static PATH --manifest FILE` | Scan Ruby source with optional Prism and relate hints to recorded capabilities |

Use `bonebed help` for the command list and `bonebed dig --help` for observation options. `dig --version VERSION` selects the gem version. The `all` phase also observes declared RubyGems and Bundler plugins, so it can produce four linked manifests. [Bundler plugin observations](docs/bundler-plugin-observation.md) include registration and any dependency installation or code loading performed by Bundler.

Optional [Bash, Zsh, and Fish completion files](docs/completions.md) are included under `contrib/`.

`--offline` attempts a new user/network namespace through util-linux `unshare`. On success the target has no external interfaces and loopback stays down. If the kernel or container denies namespace creation, Bonebed records an observer error and falls back to rejecting observed connection and datagram calls; use `--strict` to make that fallback fail automation. The manifest's `run.mode.isolation` records the selected mode. Package prefetching still uses the network outside observation, before local installation.

Successful survey results are matched by manifest identity and execution settings; failed or incomplete results are retried. `--jobs N` runs isolated workers in parallel. Killed workers are recorded and the survey continues. Process cleanup tracks descendants and can recover detached children, but an entirely unobserved fork/reparent race remains possible without a delegated cgroup.

`survey --top N` pages through RubyGems download statistics. To continue during a registry outage or
page-format change, explicitly provide `--top-fallback reviewed-ranking.txt` (or set
`defaults.top_fallback` in `.bonebed.yml`). The file is used only when the live source fails or runs out
of names. Bonebed warns on stderr, replaces the entire requested list with its first N entries, and
does not mix partial live results with the snapshot or claim it is the current ranking.

Keep one gem name per line in ranking order, with optional `#` comments. Record the source URL,
ranking basis, collection date, and reviewer in comments; refresh from the same RubyGems statistics
pages, review changes, and commit the snapshot alongside your survey configuration. Names, duplicates,
and the full file are checked before use; insufficient names or version/require columns are rejected.
The snapshot is operator-reviewed input, not a bundled or automatically verified popularity list.
Configured fallback files are ignored for `--file` and `--gemfile` surveys.

Use `sinatra - sinatra/base` in a survey file to set a require path without pinning a version. Require paths are ignored during install surveys. Lockfile surveys support RubyGems sources; git and path sources are rejected with their gem names instead of substituting registry packages. Standalone require observations need the selected gem and its runtime dependencies installed already; use `--phase all` to observe a gem that is not installed. `dig --platform PLATFORM` selects the package platform.

Both phases use disposable home, project, temporary, and gem directories. Inherited environment variables are cleared for target execution, with a small runtime environment supplied explicitly. Decoy credential files and environment tokens contain fake values; their appearance in captured output or arguments is recorded as a canary hit. Use `--real-home` or `--cwd DIR` only when deliberately testing access to your own files. These options expose the selected real directories to target code.

`--sinkhole` requests local responses for observing network intent. It cannot be combined with `--offline` or `--trace`; failure to establish its network isolation prevents target execution. The option is available for `dig`, `survey`, `run`, `bundle`, `compare`, and `diff-lock`. Sinkhole observations and baselines use separate cache identities.

Use `--env-profile ci` or `prod` to exercise environment-dependent behavior. `--writes-only` omits ordinary read observations; it cannot establish the absence of credential reads. `--trace PREFIX` writes decoded JSONL timelines with process identity and normalized arguments. Trace files can contain target-controlled sensitive data.

Use `--repeat N` on gem observations or surveys to collect 1 to 100 samples in fresh environments.
The first sample resolves the package version and platform for the group. Manifests retain every
sample and summarize capability keys present in all samples (`stable`) or only some (`flaky`). A
failed or incomplete group cannot satisfy survey resume. Repetition samples nondeterministic behavior;
it cannot prove that unobserved behavior is absent.

The gem `exec` phase runs a declared RubyGems executable wrapper after disposable installation.
`--executable` is optional when the package declares exactly one executable. Use `--` before its
arguments; arbitrary files inside a package are not selected as declared executables.

`run` uses a disposable working directory by default. For project-relative commands, select an explicit directory, for example `bonebed run --cwd /path/to/project -- ruby script.rb`. It records an `exec` phase under the synthetic `command` identity. Arguments are passed directly; invoke a shell explicitly only when that is the command you intend to observe.

Install observations have a 600-second timeout; require observations have a 60-second timeout. Override either with `--timeout SECONDS`. Stdout and stderr are captured up to 1 MiB each; `--output-limit BYTES` changes the limit and `--quiet-target` disables live forwarding while retaining captured output. `--argv-limit COUNT` changes the default limit of 64 command arguments. Manifests mark truncated output and argument lists explicitly.

Targets also receive hard resource limits: 4 GiB address space, CPU time of timeout plus one second,
1024 file descriptors, and 256 MiB per regular output file. These are distinct from captured-output
limits. The Ruby Session API accepts `resource_limits:` overrides; there are no corresponding CLI flags.

`dig` prints a compact summary and manifest path. Target failures still produce a manifest. Observer
errors are recorded separately. Fatal setup failures return exit 2; `--strict` also reports nonfatal
observer errors when the target otherwise succeeds.

The summary includes counts by default-rule severity. Color is used only on terminal stderr and is
disabled by `NO_COLOR`. `--verbose` adds observer runtime, capture mode, syscall-count, and target-status
diagnostics to stderr; stdout remains suitable for manifest paths or structured reports.
Use `--require-container` to reject host target execution with exit 2. `--allow-host` explicitly overrides
that requirement while retaining the host warning. These controls also accept boolean defaults named
`verbose`, `require_container`, and `allow_host` in `.bonebed.yml`. Container detection is a preflight
guard, not a security boundary; use a disposable environment with the documented isolation settings.

| Exit status | Meaning |
| --- | --- |
| `0` | Successful command; nonfatal observer errors are tolerated unless strict mode is enabled |
| `1` | Target command failed or timed out, or command setup/environment checks failed |
| `2` | Fatal observation failure, or observer errors with `--strict` and an otherwise successful target |
| `3` | Policy violations at or above the selected threshold |
| `64` | Invalid arguments or command usage |

## How It Works

1. A seccomp filter sends the selected filesystem, network, execution, process, and sensitive syscall notifications to Bonebed.
2. Bonebed decodes and records each call before continuation. Offline mode rejects observed network attempts; `io_uring_setup` is recorded and rejected with `ENOSYS`. Optional Landlock rules can independently deny supported filesystem or TCP operations.
3. A matching phase-specific baseline is subtracted as startup noise: local installation of an empty gem for install, and empty require startup for require. Read probes for nonexistent paths are discarded except for sensitive paths such as credential files; write and network attempts are retained because a notification arrives before the kernel result is known.
4. Target stdout and stderr are streamed while the remaining file paths, network endpoints, commands, thread creation calls, installed gems, counts, timing, errors, and bounded output are written as JSON. Relative paths are resolved from the target process and project paths are normalized to `$PWD`; routine RubyGems cache writes stay in the file list but are excluded from `notable`. Numeric procfs process and thread identifiers and paths in command arguments are normalized for comparison.

Captured output is stored as UTF-8; invalid byte sequences are replaced so binary output cannot prevent manifest creation. `target` records `exit_status`, `signal`, and `timed_out`; `errors` describes target failures and `observer_errors` describes observation failures. Reports show these separately along with network attempts and output emitted by successful require targets. Failure reports keep compact output previews in the table and captured output in a folded section.

Schema v2 groups reads into the gem's own files, resolver configuration, and other paths. Markdown reports include a contents list, findings ordered by default-policy severity, folded target details, and a capability matrix. Capabilities without a matching rule have no assigned severity. Reports support both v1 and v2 results. See [the manifest reference](docs/manifest.md) for fields, migration, and compatibility.

Observation policies in `.bonebed.yml` classify findings after execution; they do not prevent target actions. `--enforce FILE` loads a separate Landlock configuration before execution and can be combined with `--offline`. See [policies and enforcement](docs/policies.md) for both formats and their limits, [CI integration](docs/ci.md) for the composite Action, and [datasets](docs/dataset.md) for local export and monitoring.

An optional [Bundler plugin](docs/bundler-plugin.md) checks existing observations and approvals before
a frozen `bundle install`, rejecting missing observations and unapproved changes. Install it explicitly
in a trusted project. Bundler evaluates the Gemfile before the hook; the plugin does not sandbox it.

`static PATH` parses Ruby source without executing it. It reports selected command, network, and
`eval` call sites; `--manifest FILE` adds approximate links to observed capabilities. This requires
Prism, bundled with Ruby 3.3+ or installed separately. The scan has no dataflow or dynamic-dispatch
analysis and cannot prove a source line executed. See [static analysis](docs/static-analysis.md).

In a development-container observation of `rainbow` 3.1.1, the install manifest contained zero network events and one file read: the input `.gem` package. This is a measured example of baseline noise reduction; gems that execute build scripts can produce additional activity.

Implementation notes and measured notification overhead are recorded in [NOTES.md](NOTES.md). The [threat model](docs/threat-model.md) explains observation gaps and environment limits.

## Development

```bash
bin/dev bundle exec rake
bin/dev bundle exec exe/bonebed doctor
```

The default task runs RSpec and Standard. SimpleCov writes coverage to `coverage/index.html`. The development image includes `strace` for cross-checking noteworthy observations. See [CONTRIBUTING.md](CONTRIBUTING.md) for Linux integration checks and the CI matrix.

## Contributing

Bug reports and pull requests are welcome at [github.com/ydah/bonebed](https://github.com/ydah/bonebed). Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the [changelog](CHANGELOG.md) for contribution, security reporting, and compatibility information.

## License

Bonebed is available as open source under the terms of the [MIT License](LICENSE.txt).

### Observe a bundle installation

`bonebed bundle --gemfile Gemfile --offline --results results` reads the adjacent lockfile without
executing the Gemfile, fetches the locked RubyGems.org packages, and observes `bundle install --local`
in a disposable project. `--lockfile FILE` selects a different lockfile. Git/path dependencies and
private registries are rejected explicitly. Only the Gemfile and lockfile are copied, so Gemfiles that
load additional project files need a different observation setup. The output identifies the inputs by
SHA-256 and includes process relationships; it does not claim exact per-gem attribution.
