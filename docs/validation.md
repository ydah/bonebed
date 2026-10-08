# Local validation record

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
