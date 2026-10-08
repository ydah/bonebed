<div align="center">

# Bonebed

Observe file, network, and process capabilities used while installing or requiring Ruby gems.

[![Gem Version](https://img.shields.io/gem/v/bonebed.svg?colorB=319e8c)](https://rubygems.org/gems/bonebed)
[![Downloads](https://img.shields.io/gem/dt/bonebed.svg)](https://rubygems.org/gems/bonebed)
![Ruby 3.2+](https://img.shields.io/badge/Ruby-3.2%2B-CC342D?logo=ruby&logoColor=white)
![Linux](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)

[Features](#features) · [Installation](#installation) · [Quick Start](#quick-start) · [Commands](#commands) · [How It Works](#how-it-works)

</div>

---

Bonebed uses Linux seccomp user notifications to observe the files, network addresses, external commands, and thread creation syscalls touched by a Ruby gem. It subtracts normal Ruby and Bundler startup activity, then writes the remaining observations to a JSON capability manifest.

> [!WARNING]
> Bonebed is an observation tool, not a security boundary. Pointer arguments can change between inspection and syscall continuation (TOCTOU), so the manifest describes what was observed rather than guaranteeing what happened.
>
> Use a disposable environment without credentials or valuable writable files for unknown gems. Require observations currently inherit the real home and working directory. The development container mounts this checkout read-write; use it for trusted fixtures.

## Features

- Profile both `gem install` and `require`
- Observe `open`/`openat`, `connect`, `execve`, `clone`, and `clone3` calls
- Subtract cached Ruby and Bundler startup baselines
- Normalize project, home, gem, and temporary paths for comparable manifests
- Survey RubyGems rankings, gem lists, or Bundler lockfiles with resumable results
- Summarize failures, project file access, and commands by survey target as Markdown

## Installation

Install Bonebed from RubyGems:

```bash
gem install bonebed
```

### Requirements

- Linux 5.5 or newer on x86_64 or aarch64
- Ruby 3.2 or newer
- Permission to install a seccomp user-notification filter

Docker must run with `--security-opt seccomp=unconfined`. Bonebed does not run directly on macOS; use the included development container instead.

## Quick Start

Run Bonebed in its Linux development container so the gem under observation is not executed directly on the host:

```bash
docker build -f Dockerfile.dev -t bonebed-dev .
bin/dev bundle install
bin/dev bundle exec exe/bonebed doctor
bin/dev bundle exec exe/bonebed dig json
```

The manifest is written to `results/`. The first observation also caches a matching startup baseline in `.bonebed/baselines/`.

## Commands

| Command | Purpose |
| --- | --- |
| `bonebed --version` | Print the Bonebed version |
| `bonebed doctor` | Check kernel, architecture, seccomp, and container support |
| `bonebed baseline [--refresh]` | Create or refresh the startup baseline |
| `bonebed dig GEM` | Observe a gem while it is required with only its runtime dependency closure visible; common load paths are inferred, or use `--require PATH` |
| `bonebed dig GEM --phase install` | Install and observe a gem in disposable home and gem directories |
| `bonebed survey --top N` | Observe up to 100 gems from RubyGems.org's all-time ranking |
| `bonebed survey --file FILE` | Observe gems listed as `NAME [VERSION|-] [REQUIRE_PATH]` |
| `bonebed survey --gemfile Gemfile.lock` | Observe gems from a Bundler lockfile |
| `bonebed report results --format md` | Summarize collected manifests as Markdown |

Use `bonebed COMMAND --help` for command-specific options. `dig --version VERSION` selects the gem version.

Use `--offline` with `dig` or `survey` to return `ENETUNREACH` for observed connections. It does not block every way to send traffic, including unconnected UDP. Install observations currently include RubyGems download traffic. Existing successful survey results are skipped by manifest identity and failures are retried, so interrupted surveys can resume. Each survey entry runs in a fresh worker process so its memory and operating-system resources are released; a killed worker is recorded and the survey continues.

Use `sinatra - sinatra/base` in a survey file to set a require path without pinning a version. Require paths are ignored during install surveys. Lockfile surveys support RubyGems sources; git and path sources are rejected with their gem names instead of substituting registry packages. Require observations need the selected gem and its runtime dependencies installed already.

Install observations have a 600-second timeout; require observations have a 60-second timeout. Override either with `--timeout SECONDS`. Stdout and stderr are captured up to 1 MiB each; `--output-limit BYTES` changes the limit and `--quiet-target` disables live forwarding while retaining captured output. `--argv-limit COUNT` changes the default limit of 64 command arguments. Manifests mark truncated output and argument lists explicitly.

`dig` prints a compact summary and manifest path. Target failures still produce a manifest. Observer errors are recorded separately and do not make a successful target fail unless `--strict` is enabled.

| Exit status | Meaning |
| --- | --- |
| `0` | Successful command; observer errors are tolerated unless strict mode is enabled |
| `1` | Target command failed or timed out, or command setup/environment checks failed |
| `2` | Observer errors with `--strict` and an otherwise successful target |
| `3` | Reserved for policy violations in a future release |
| `64` | Invalid arguments or command usage |

## How It Works

1. A seccomp filter sends `open`/`openat`, `connect`, `execve`, `clone`, and `clone3` notifications to Bonebed.
2. Bonebed decodes and records each call, then allows it to continue unless offline mode rejects a connection.
3. A matching empty-Ruby observation is subtracted as startup noise. Read probes for nonexistent paths are discarded except for sensitive paths such as credential files; write and network attempts are retained because a notification arrives before the kernel result is known.
4. Target stdout and stderr are streamed while the remaining file paths, network endpoints, commands, thread creation calls, installed gems, counts, timing, errors, and bounded output are written as JSON. Relative paths are resolved from the target process and project paths are normalized to `$PWD`; routine RubyGems cache writes stay in the file list but are excluded from `notable`. Numeric procfs process and thread identifiers and paths in command arguments are normalized for comparison.

Captured output is stored as UTF-8; invalid byte sequences are replaced so binary output cannot prevent manifest creation. `target` records `exit_status`, `signal`, and `timed_out`; `errors` describes target failures and `observer_errors` describes observation failures. Reports show these separately along with network attempts and output emitted by successful require targets. Failure reports keep compact output previews in the table and captured output in a folded section.

Implementation notes and measured notification overhead are recorded in [NOTES.md](NOTES.md).

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
