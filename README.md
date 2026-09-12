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

Bonebed uses Linux seccomp user notifications to observe the files, network addresses, and external commands touched by a Ruby gem. It subtracts normal Ruby and Bundler startup activity, then writes the remaining observations to a JSON capability manifest.

> [!WARNING]
> Bonebed is an observation tool, not a security boundary. Pointer arguments can change between inspection and syscall continuation (TOCTOU), so the manifest describes what was observed rather than guaranteeing what happened.

## Features

- Profile both `gem install` and `require`
- Observe `open`/`openat`, `connect`, and `execve` calls
- Subtract cached Ruby and Bundler startup baselines
- Normalize home, gem, and temporary paths for comparable manifests
- Survey RubyGems rankings, gem lists, or Bundler lockfiles with resumable results
- Summarize multiple manifests as Markdown

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
| `bonebed doctor` | Check kernel, architecture, seccomp, and container support |
| `bonebed baseline [--refresh]` | Create or refresh the startup baseline |
| `bonebed dig GEM` | Observe a gem while it is required; use `--require PATH` when its load path differs from its name |
| `bonebed dig GEM --phase install` | Install and observe a gem in disposable home and gem directories |
| `bonebed survey --top N` | Observe up to 100 gems from RubyGems.org's all-time ranking |
| `bonebed survey --file FILE` | Observe gems listed as `NAME` or `NAME VERSION` |
| `bonebed survey --gemfile Gemfile.lock` | Observe gems from a Bundler lockfile |
| `bonebed report results --format md` | Summarize collected manifests as Markdown |

Use `--offline` with `dig` or `survey` to return `ENETUNREACH` for observed connections. This is a compatibility check, not a security sandbox. Existing survey results are skipped, so interrupted surveys can resume.

`dig` still writes its manifest but exits with status 1 when the observed command fails.

## How It Works

1. A seccomp filter sends `open`/`openat`, `connect`, and `execve` notifications to Bonebed.
2. Bonebed decodes and records each call, then allows it to continue unless offline mode rejects a connection.
3. A matching empty-Ruby observation is subtracted as startup noise.
4. The remaining file paths, network endpoints, commands, counts, timing, and errors are written as JSON.

Implementation notes and measured notification overhead are recorded in [NOTES.md](NOTES.md).

## Development

```bash
bin/dev bundle exec rake
bin/dev bundle exec exe/bonebed doctor
```

The development image includes `strace` for cross-checking noteworthy observations.

## Contributing

Bug reports and pull requests are welcome at [github.com/ydah/bonebed](https://github.com/ydah/bonebed).

## License

Bonebed is available as open source under the terms of the [MIT License](LICENSE.txt).
