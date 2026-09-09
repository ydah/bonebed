# Bonebed

Bonebed observes the files, network addresses, and external commands touched while a Ruby gem is installed or required. It produces a capability manifest from Linux seccomp user notifications.

Bonebed is an observation tool, not a security boundary. Pointer arguments can change between inspection and syscall continuation (TOCTOU), so its output describes what was observed rather than guaranteeing what happened.

## Requirements

- Linux 5.5 or newer on x86_64 or aarch64
- Ruby 3.2 or newer
- Permission to install a seccomp user-notification filter

Docker users must run with `--security-opt seccomp=unconfined`. Bonebed does not support macOS directly; use the development container below.

## Installation

Add Bonebed to a bundle:

```bash
bundle add bonebed
```

Or install it directly:

```bash
gem install bonebed
```

## Diagnose the environment

```bash
bonebed doctor
```

## Observe a gem

Run Bonebed inside the development container so third-party code is not executed directly on the host:

```bash
bin/dev bundle exec exe/bonebed dig json
bin/dev bundle exec exe/bonebed dig json --phase install
```

Manifests are written to `results/`. The first run records a Ruby/Bundler baseline in `.bonebed/baselines`; refresh it after environment changes with:

```bash
bin/dev bundle exec exe/bonebed baseline --refresh
```

Use `--offline` to return `ENETUNREACH` for every observed connection. This is a compatibility check, not a security sandbox.

## Survey and report

Survey RubyGems.org's all-time download ranking, a newline-separated gem list, or a lockfile. Existing result files are skipped so interrupted surveys can resume.

```bash
bin/dev bundle exec exe/bonebed survey --top 100
bin/dev bundle exec exe/bonebed survey --gemfile Gemfile.lock --phase require
bin/dev bundle exec exe/bonebed report results --format md
```

Top surveys default to the install phase because those gems need not already be installed. A list file accepts `NAME` or `NAME VERSION` on each line.

## Development

Build the Linux development image once, install dependencies, and run the checks inside it:

```bash
docker build -f Dockerfile.dev -t bonebed-dev .
bin/dev bundle install
bin/dev bundle exec rake
bin/dev bundle exec exe/bonebed doctor
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ydah/bonebed.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
