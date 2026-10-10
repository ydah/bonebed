# Local validation record

The final local Linux suite on October 10 passed 383 examples with no failures and 91.82% line
coverage, including Standard checks. One real delegated-cgroup example remains pending because
the development container's cgroup mount is not writable and delegated.

On 2026-10-08, a production-image snapshot built from this checkout observed the current RubyGems
top 20 in a read-only container, with the bundled seccomp profile, no capabilities, an unprivileged
UID, a 2 GiB memory limit, two workers, and `--phase all --offline --timeout 60`.
Only the results directory was mounted writable; `/tmp` was an executable disposable tmpfs.
The environment was Ruby 4.0.6, aarch64 Linux 6.8.0, seccomp-notify 0.3.0.

All 20 install and 20 require phases completed successfully. All 40 recorded no target or observer
errors and no post-baseline network events. This is one sample per gem, not the roadmap's top-1000
acceptance result or a safety judgment. Native builds include json, bigdecimal, and Prism dependencies;
nokogiri used its platform package. The first attempt exposed Docker tmpfs's default `noexec`, which
blocked native builds/loads; the checked-in launchers now explicitly use `exec` on that disposable tmpfs.

| Gem | Version | Platform |
| --- | --- | --- |
| activesupport | 8.1.4 | ruby |
| addressable | 2.9.0 | ruby |
| aws-eventstream | 1.4.0 | ruby |
| aws-partitions | 1.1293.0 | ruby |
| aws-sdk-core | 3.257.0 | ruby |
| aws-sigv4 | 1.12.1 | ruby |
| bundler | 4.0.22 | ruby |
| concurrent-ruby | 1.3.8 | ruby |
| diff-lcs | 2.0.0 | ruby |
| faraday | 2.14.4 | ruby |
| i18n | 1.15.2 | ruby |
| jmespath | 1.6.2 | ruby |
| json | 3.0.2 | ruby |
| minitest | 6.0.6 | ruby |
| nokogiri | 1.19.4 | aarch64-linux-gnu |
| public_suffix | 7.0.5 | ruby |
| rack | 3.2.7 | ruby |
| rake | 13.4.2 | ruby |
| rspec-core | 3.13.6 | ruby |
| tzinfo | 2.0.6 | ruby |

Reproduce with a fresh results directory using the command in the nightly workflow. Current registry
versions and rankings may differ; use a version-pinned survey input to compare these exact releases.
Hosted CI, other kernels, and the eventual published image need their own verification.

## Container and runtime comparison smoke test, October 10, 2026

The updated production Dockerfile built successfully with Ruby 4.0.6 and the locally cached official
Ruby 3.3 image (Ruby 3.3.12). Both ran an explicit Ruby command with a project-file write under an
unprivileged UID, read-only root filesystem, all capabilities dropped, no-new-privileges, the bundled
seccomp profile, resource limits, and a private executable tmpfs. Both saved successful manifests with
empty target and observer errors. The actual `--ruby 3.3,4.0` wrapper ran both local images, kept their
output separate, checked runtime metadata, and reported no capability differences for that command.

The same restricted configuration supported a real sinkhole namespace. With Docker's default
seccomp profile instead, namespace creation was refused; the command returned exit 2 and the target's
marker file was not created. These are separate supported/blocked setup checks, not proof of complete
hostile-code containment.

Docker Hub's API confirmed amd64 and arm64 variants for the pinned Ruby 3.3/3.4 release-workflow base
digests. Pulling the new Ruby 3.3 digest locally timed out during the registry TLS handshake, so the
Ruby 3.3 build above used its existing local base image. Release-image publishing and a build of that
exact newer base digest remain separate checks.

## Before/after observations and benchmark

The same development container compared `6494f75` with the October 10 implementation using pinned
rainbow 3.1.1 and json 3.0.2, `--phase all --offline`. All eight observations completed with no target
or observer errors. The native json build gained working-directory attribution to json 3.0.2.
Capability comparisons, including counts, were unchanged after applying the scoped native-build
temporary-name normalization to both versions. Without that normalization, compiler and RubyGems
staging names alone produced 336 added and 336 removed keys for json installation.

| Gem and phase | Before observation time | After observation time |
| --- | --- | --- |
| rainbow install | 203 ms | 203 ms |
| rainbow require | 42 ms | 63 ms |
| json install | 6,703 ms | 6,977 ms |
| json require | 64 ms | 62 ms |

These are single observations, not statistically established performance differences. The fixed
1,000-read benchmark on the same Ruby 4.0.6 / aarch64 / Linux 6.8.0 host used three samples per
revision: observed-time medians were 305 ms before and 326 ms after; median observed/plain ratios
were 3.24 and 3.54. Each recorded 2,770 notifications. This measures a synthetic workload and does
not establish the roadmap's release overhead budget.

## Hosted nightly validation

[Run 38024026774](https://github.com/ydah/bonebed/actions/runs/38024026774), on `133b4ba`, passed the
fixture, production-container top-20 survey, and comparison jobs. Its retained comparison had 40
compared observations and no input errors. The previous successful workflow predated benchmark
artifacts, so the benchmark result correctly recorded `no_previous_benchmark` rather than failing
or inventing a measurement. An actual same-environment two-run benchmark comparison still needs
a later matching hosted run.
