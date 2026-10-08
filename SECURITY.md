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
additional activity. Require observations currently inherit the working directory and home environment.

`--offline` rejects observed `connect` calls. It does not isolate the network or block every way to
send traffic, including unconnected UDP. Install observations can include RubyGems download traffic.
