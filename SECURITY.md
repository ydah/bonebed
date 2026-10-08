# Security policy

## Reporting a vulnerability

Report vulnerabilities in Bonebed itself and techniques that bypass its observation through
[GitHub private vulnerability reporting](https://github.com/ydah/bonebed/security/advisories/new).
If that form is unavailable, email the maintainer at <t.yudai92@gmail.com>.
Do not disclose exploitable details in a public issue before the maintainer has reviewed them.

Include the Bonebed and Ruby versions, kernel and architecture, reproduction steps, expected and
observed behavior, and a minimal harmless example when possible. Remove credentials and other
private data from manifests and logs before sharing them. Reports about behavior observed in a
third-party gem should distinguish an observed capability from evidence of malicious intent.

Security fixes target the latest release. Older releases may not receive backports.

## Limits of observation

Bonebed executes the gem being observed. Use a disposable environment without credentials or
valuable writable files. The development container mounts the repository read-write; it is suitable
for trusted fixtures, not a boundary for running potentially hostile gems.

Bonebed is not a security sandbox. It observes selected syscalls before they finish and cannot
guarantee their results. Pointer arguments can change between inspection and continuation (TOCTOU).
An empty manifest does not establish that a gem is safe, and unobserved syscall paths can perform
additional activity. Target execution defaults to disposable home and project directories with decoy
credentials and a reduced environment. This does not restrict access to other files by absolute path.
`--real-home` and `--cwd` explicitly expose the selected real directories.

`--offline` attempts a user/network namespace. If unavailable, it records an observer error and falls
back to rejecting observed connection and datagram calls. Use `--strict` to fail automation on that
fallback. Package prefetching runs outside observation and may use the network even with `--offline`.
Optional Landlock enforcement restricts supported filesystem and TCP operations, with limits determined
by the kernel ABI. See [the threat model](docs/threat-model.md) for further limits.
