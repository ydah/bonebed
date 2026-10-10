# Best-effort policy denial

`--deny FILE` applies an existing Bonebed policy YAML while observing a target:

```sh
bonebed dig example --version 1.2.3 --phase all --deny .bonebed.yml
bonebed run --deny .bonebed.yml -- ruby script.rb
```

The policy uses the same `rules`, `allow`, gem names, phase names, and `defaults.fail_on` threshold as `bonebed check`. Matching, non-allowed findings at or above the threshold cause the intercepted syscall to return `EPERM`. Other operations continue. There is no automatic fallback from `--enforce` to `--deny`. An empty policy mapping (`{}`) selects the standard rules and the default `high` threshold.

This is a mitigation, **not a security boundary**. Use a disposable container for untrusted targets. A target can change pointed-to memory, path components, symlinks, or file descriptors between inspection and syscall execution. Denial applies to the copied arguments that Bonebed decoded. It does not establish that an allowed operation uses those same arguments.

The supported pre-call observations are:

| Syscalls | Policy capability families |
| --- | --- |
| `open`, `openat`, `openat2` | `file:read`, `file:write`, `file:create`, `file:truncate`, `file:append`, `file:rw` |
| Observed rename, unlink, link, chmod, and other file mutation calls | Corresponding `file:OPERATION` keys |
| `execve`, `execveat` | `exec`, plus `syscall:execveat` |
| `connect`, `sendto`, `sendmsg`, `sendmmsg` | Decoded `network` destinations and plaintext `network:dns` questions |
| `socket`, and sinkhole-mode `socketpair` | `socket:FAMILY:TYPE:PROTOCOL` |
| `bind`, `listen` | `listen` destinations |
| Observed clone/fork calls | `thread:spawn` or `process:spawn` |
| Observed suspicious calls | `syscall:NAME` |

The initial command launcher is permitted so the target can start. Offline namespace setup also needs its launcher exec and initial unshare call. Subsequent exec calls are checked, including shell commands and child processes. All observations in an install/require/plugin phase use that phase's selected gem identity; this does not attribute individual dependency actions to separate gems. Arbitrary command runs use the synthetic gem name `command`; aggregate bundle installs use `bundle`.

Captured attempts remain in normal manifest capability fields. Refused calls also produce optional `denied` records containing `syscall`, `capability`, `rule_id`, `severity`, and `count`; trace rows identify refused calls when trace output is enabled. Counts represent matched findings on refused calls, so one syscall may contribute several records. The policy fingerprint is part of observation/cache identity, and denial evidence is retained independently of baseline subtraction. If a program catches `EPERM` and exits successfully, observation can still exit successfully; use `check` to apply the usual policy violation exit status.

`--writes-only` is rejected with `--deny`, because suppressing read notifications would skip credential-read rules. Existing offline and sinkhole restrictions continue to apply. Policies cannot grant access forbidden by those restrictions or by Landlock. The unconditional io_uring mitigation remains in effect independently of policy matching.

Baseline capture uses the same policy and gem/phase context as its target. A policy that refuses operations needed by the baseline can prevent observation; Bonebed reports the baseline failure instead of relaxing the policy. Read-capable `RDWR` and `RDONLY | CREAT` opens are also checked against read rules, even though ordinary file observations classify these as writes.

Limitations include:

- Decode failures are recorded as observer errors and the call continues, except existing offline/sinkhole guards that already fail closed. Use `--strict` to report observer errors with exit status 2; it does not make argument inspection race-free.
- Existing or inherited file descriptors, ordinary `read`/`write`, memory mappings, unobserved syscall variants, ancillary-descriptor passing, and operations performed before the initial exec are not comprehensively mediated.
- HTTP/TLS sinkhole intent, decrypted application payloads, canary detections, and other evidence obtained after a syscall cannot be used to refuse that earlier call. Post-run policy checks still evaluate captured evidence.
- The feature does not replace Landlock, namespace isolation, or a container security policy, and does not guarantee that all policy violations are prevented.
