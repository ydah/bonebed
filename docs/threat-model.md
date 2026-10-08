# Threat model

Bonebed helps investigate what code attempts while installing or requiring a Ruby gem. The gem runs
with code execution privileges in the selected environment. A capability manifest is evidence for
review, not a maliciousness verdict and not proof that the gem is safe.

## What is observed

The current observation policy covers selected file opens and changes, socket connections/listeners,
datagram destinations, bounded DNS questions, command execution, process/thread creation, and sensitive
syscalls. Notifications expose arguments before the kernel
completes the syscall; a recorded connection or write can fail afterward. Bonebed subtracts matching
startup activity and normalizes paths. That reduces noise but cannot establish the success of an
individual syscall or assign every action to a particular dependency.

Sensitive read attempts are retained even when files are absent. Disposable home and project
directories contain fake credential files, and selected environment variables contain decoy tokens.
Tokens found in captured manifest fields, including output, command arguments, and decoded DNS names,
are reported as canary hits and replaced by source markers in saved manifests. All decoy values
are synthetic; they do not authenticate to real accounts. A missing hit does not show that a token
was never read, transformed, or transmitted. Output and argument capture limits can hide later data.

## What is not observed

- Pointer arguments can change after inspection and before syscall continuation (TOCTOU).
- Reads and writes through already-open file descriptors are not generally observed.
- Unmonitored syscalls, shared memory, and activity outside the traced process family can escape the manifest.
- vDSO operations do not enter the kernel through monitored syscalls.
- io_uring setup attempts are recorded and rejected with `ENOSYS`; this does not observe I/O through pre-existing rings.
- An already-attached debugger or another process with sufficient access can change target state.
- DNS parsing covers bounded plaintext UDP questions, not DNS over TCP, DoH, TLS, or arbitrary application protocols.
- Datagram destination attribution on connected sockets is best-effort and can be affected by descriptor reuse.
- `--writes-only` deliberately omits ordinary read observations and cannot establish the absence of credential reads.

Native extensions execute arbitrary machine code. Kernel vulnerabilities, privileged host access,
container escapes, and kernel-independent communication paths are outside Bonebed's security guarantees.

## Environment and network limits

Targets normally receive disposable home, project, gem, and temporary directories and a reduced
environment. This limits accidental interaction with ordinary user files; it is not filesystem
confinement. Target code can still open accessible absolute paths or use other interfaces. `--real-home`
and `--cwd DIR` explicitly make the selected real directories available and increase exposure.

`--offline` first tries util-linux `unshare` to create user and network namespaces. The target has no
external interfaces, and loopback remains down. The external wrapper avoids the single-threaded
requirement that can make in-process user namespace creation fail in Ruby. Namespace availability is
probed, but the actual target setup can still fail if its execution environment imposes extra restrictions.

If namespace creation is unavailable, Bonebed records an observer error and rejects observed connection
and datagram calls instead. That fallback is best-effort syscall mediation, not equivalent isolation.
`--strict` makes the observer error fail automation. Inspect `run.mode.isolation`, which records
`network_namespace`, `syscall_fallback`, or `none`. Prefetching resolves and downloads packages outside
observation, before local installation, and can use the network even when `--offline` is selected.
Package fetching processes untrusted metadata and archives; it must also run in an appropriate environment.

Use a disposable container or VM without credentials, sensitive environment values, writable host
data, or privileged mounts for unfamiliar gems. `bin/dev` mounts the repository read-write and
disables Docker's default seccomp filter to allow observation. It is a trusted-fixture development
environment, not a hardened service for executing hostile code.

## Optional kernel enforcement and cleanup

`--enforce FILE` applies a separate Landlock allowlist in the target child before execution. Unsupported
or invalid rules fail rather than silently disabling enforcement. Read paths also permit execution;
write paths permit supported mutations beneath the selected directory. Runtime libraries and the
disposable observation environment receive baseline allowances. Review those allowances for your use case.

Landlock enforcement is limited by ABI and operation. ABI 1 cannot grant cross-directory rename; ABIs
1 and 2 cannot restrict truncation. ABI 4 adds TCP bind/connect restrictions; older ABIs run filesystem
rules only and reject nonempty TCP allowlists. UDP, existing file descriptors, metadata operations,
and other unsupported actions are not covered by these filesystem/TCP rules. Rules affect the calling
thread and its subsequent children, so Bonebed applies them immediately before target execution.
Allowed paths are canonicalized and pinned with `O_PATH`; concurrent parent-directory replacement
between resolution and open remains a setup race. Landlock does not repair observation TOCTOU gaps.

The supervisor becomes a child subreaper and tracks descendant identities. Cleanup uses pidfds and
start-time checks to avoid signaling unrelated processes after PID reuse, and covers tested detached
and double-forked children. A process that forks and reparents entirely between tracking points may
escape that set. Complete tree cleanup requires a delegated cgroup; this implementation currently
reports cgroup availability but does not create a target cgroup or use `cgroup.kill`.

## Evasion and incomplete observations

A gem can detect seccomp, inspect environment variables, or condition behavior on time, platform,
network availability, or CI-specific state. One install/require run cannot explore every execution
path. Honeypots can themselves be recognized. An empty manifest therefore cannot rule out behavior
that was inactive, filtered as baseline noise, or outside observation coverage.

Target failures and timeouts are recorded separately from observer errors. Successful target execution
does not imply complete observation. Review `observer_errors`, truncation flags, and environment
metadata alongside capabilities; use `--strict` when observer errors must fail automation.

Report vulnerabilities in Bonebed and observation bypasses through the private channels in
[SECURITY.md](../SECURITY.md).
