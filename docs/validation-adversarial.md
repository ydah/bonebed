# Appendix D fixture validation

Run the safe, local scenarios in the Linux development container:

```sh
bin/dev bundle exec rspec spec/adversarial_spec.rb
bin/dev bundle exec standardrb spec/adversarial_spec.rb spec/fixtures/gems/malicious
```

The suite builds and installs each fixture as a local gem, then observes its install, require, or RubyGems plugin phase. Assertions cover real seccomp notifications, normalized manifest fields, baseline subtraction, honeypot redaction, and applicable default policy findings. Expected paths, families, syscall names, severities, and destinations are asserted directly in the spec; nondeterministic ports and process IDs come from the test's own sockets and children.

Each target gets a disposable HOME, project directory, GEM_HOME, temporary directory, and synthetic credentials through `GemEnvironment`. `Session` clears the inherited environment. Fixture entrypoints refuse to run unless the harness explicitly sets `BONEBED_ADVERSARIAL_FIXTURE=1`; do not set this variable to run fixtures in an ordinary project. All Internet socket destinations are loopback. No registry downloads, real credentials, external payloads, or external DNS resolvers are used. The netlink case communicates only with the local kernel.

| Fixture | Phase | Verified behavior |
| --- | --- | --- |
| `credential-stealer` | require | Reads synthetic AWS and SSH files; both appear in notable paths, `sensitive_read` is true, and the default credential rule emits critical findings. |
| `env-exfil` | require | Attempts a DNS question containing the synthetic GitHub token and a loopback HTTP connection under forced offline fallback. DNS intent and both destinations are recorded, sends are denied, and the DNS name is redacted with a canary hit. |
| `fileless` | require | Copies the container's harmless `/bin/true` ELF into a memfd and executes it through `execveat`. Both syscalls are recorded, fileless-exec is critical, and the target exits successfully. |
| `plugin-persist` | plugin | An installed `rubygems_plugin.rb` appends an inert comment to the disposable `.bashrc`; the plugin manifest reports home writing. |
| `pwd-tamper` | require | Creates an inert pre-commit hook in the disposable project and changes its mode to `0700`; write and chmod events and the critical hook rule are asserted. |
| `extconf-dropper` | install | `extconf.rb` pipes curl output to sh. A test-owned loopback HTTP server serves only a script that writes a fixture marker in the disposable HOME. The exec chain, loopback connection, marker write, and install-network finding are asserted. |
| `ci-only` | require | The default environment produces no network events; an explicit synthetic CI environment causes a loopback UDP send. |
| `at-exit` | require | A loopback UDP send inside `at_exit` remains in the require manifest. |
| `daemonize` | require | Double fork plus `setsid`, closed standard streams, and a sleeping grandchild produce process events. Observation finishes without timeout and the reported grandchild PID no longer exists. |
| `server` | require | A loopback TCP listener is recorded with the listen syscall. |
| `udp-noconnect` | require | Unconnected UDP sends are denied and a test-owned receiver stays empty. Separate tests exercise forced syscall fallback and the available normal offline isolation mode. |
| `anti-analysis` | require | Reading `/proc/self/status` appears in anti-analysis metadata even when the fixture sees seccomp and does nothing further. |
| `netlink` | require | A local AF_NETLINK connect is recorded as `netlink` without decoder errors. |
| `io-uring` | require | `io_uring_setup` appears in suspicious syscalls and the fixture checks that the inner filter returns ENOSYS. |

The native probes obtain syscall numbers from the installed `seccomp-notify` architecture table through the harness. They do not embed x86-only syscall numbers. Fiddle is copied from the local installation when it is not a default gem, including Ruby 4; no dependency is fetched. The extension fixture needs curl, sh, and make, which are present in the development image.

## Limits and recorded result

The completed local run on Linux aarch64 with Ruby 4.0.6 passed **15 examples, 0 failures**. The suite is skipped on non-Linux hosts. The development container allows the inner seccomp observer to receive the probes; an outer filter can deny a syscall before the observer sees it, particularly io_uring. This result does not establish successful execution on every kernel, CPU architecture, or restricted host.

The DNS fixture constructs a valid DNS question directly rather than invoking a public resolver. Its HTTP connection is deliberately refused before the POST body is sent. The suite therefore does **not** validate an HTTP sinkhole, TLS interception, HTTP hostname/body extraction, or `network_intent`: these remain outside this implementation. Canary redaction is verified for DNS intent, not an unobserved HTTP payload.

A detected syscall is an observed attempt, not proof that the requested operation succeeded or that a gem is malicious. These synthetic scenarios verify the listed observation paths; they are not a general sandbox escape or malware coverage guarantee.
