# Contributing

Bug reports and pull requests are welcome. Use the issue templates to include enough information
to reproduce an observation. For vulnerabilities or observation bypasses, follow [SECURITY.md](SECURITY.md).

## Development environment

Use Ruby 3.2 or newer on Linux, or the development container on macOS:

```sh
docker build -f Dockerfile.dev -t bonebed-dev .
bin/dev bundle install
bin/dev bundle exec exe/bonebed doctor
bin/dev bundle exec rake
```

`bin/dev` mounts this checkout read-write and shares a Docker volume for gems. Use trusted fixtures
here; follow the security guide when investigating unknown gems. The image includes `strace` for
cross-checking observations.

The default rake task runs RSpec and Standard. Run `bin/dev bundle exec standardrb --fix` to apply
formatting. SimpleCov writes a local report to `coverage/index.html`; there is no coverage threshold yet.
Run a focused spec with `bin/dev bundle exec rspec spec/decoder_spec.rb`.

## Validate observations

Integration tests need Linux seccomp user notifications. In the RSpec output, check that the suite
finishes with no failures **and no pending examples**. A passing suite with pending Linux tests does
not validate syscall observation. `doctor` must also report seccomp notification support. If Docker
blocks filters, use `--security-opt seccomp=unconfined`, as `bin/dev` does.

CI runs the default task, doctor, and a strict gem build on Ruby 3.2, 3.3, 3.4, and 4.0 for both
`ubuntu-24.04` and `ubuntu-24.04-arm`. Check all eight jobs and their RSpec summaries before merging.

For a bug fix, first add a small spec that reproduces the bug. If observations change, update the
affected golden fixtures and include a representative manifest comparison in the pull request.
If syscall handling changes, compare runtime on the same representative command before and after.
Explain changes to manifest fields and security assumptions, and update the README and changelog.
Keep new GitHub Actions pinned to a full commit SHA, grant minimal permissions, and disable checkout
credential persistence.

## Releases

Before 1.0, minor releases may contain breaking changes; document them under `Breaking` in the
changelog. Additive manifest fields can retain the schema version; removing fields or changing their
meaning requires a schema version change.

The maintainer updates `lib/bonebed/version.rb`, dates the changelog, runs the full checks and a small
survey, then pushes the matching `vX.Y.Z` tag. The release workflow verifies the version and publishes
through RubyGems trusted publishing. Do not push a release tag as part of an ordinary contribution.
