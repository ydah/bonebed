# Manifest format

Bonebed writes one JSON document per observed phase. A manifest describes observed syscall attempts,
not confirmed kernel results or a guarantee that a gem is safe. See [SECURITY.md](../SECURITY.md).

## Schema and compatibility

Current observations use `schema_version: 2`. The machine-readable definition is
[manifest-v2.json](../schema/manifest-v2.json), using JSON Schema 2020-12. Readers must ignore unknown
fields: additive fields are compatible within a schema version. Removing fields or changing their
meaning increments `schema_version`. Before Bonebed 1.0, minor releases can introduce a new schema;
breaking changes are documented in the changelog.

Reports accept both v1 and v2, including mixed result directories. Support for reading v1 is planned
for removal at Bonebed 1.0; migrate old results before upgrading then.

## Result identity and storage

Files are stored under `RESULTS/PHASE/NAME/VERSION-PLATFORM+IDENTITY_HASH.json`. The SHA-256 suffix
covers phase, gem identity, require path, observation settings, repetition group/index, and an explicit command or gem executable invocation when present,
including missing values. Different require paths, platforms, or modes cannot overwrite each other's
observations. A missing platform is displayed as `unknown`.
The readable filename is only a convenience; readers use the identity inside the document.

Writes use a temporary file in the destination directory followed by an atomic rename. Repeating
the same identity replaces its previous result. Survey resume checks target success, name, phase,
and any requested version, platform, require path, or mode. Observer errors do not change target success.
Incomplete or unreadable JSON is not a successful cached observation.

`bonebed migrate RESULTS` creates v2 documents in this layout while retaining the original v1 files.
Repeating migration preserves existing v2 results. Reports recursively read result directories and
prefer v2 when both versions describe the same identity, so migrated observations are not counted twice.
Invalid or incomplete manifests are ignored by result lookup and reporting.

## Fields

| Field | Meaning |
| --- | --- |
| `tool` | Bonebed and seccomp-notify versions used for observation |
| `run` | Shared run ID, start timestamp, and observation mode; phases from one run can share the ID |
| `run.repeat`, `stability` | Optional sample group/index/count and complete-group stable/flaky capability keys |
| `gem` | Name, resolved version, platform, require path, package SHA-256, extensions, executables, and RubyGems plugin presence |
| `phase` | Observed phase: `install`, `require`, `plugin`, or command `exec` |
| `environment` | Ruby version, architecture, kernel, and startup baseline identifier |
| `target` | Target `exit_status`, terminating `signal`, and `timed_out` |
| `capabilities` | Boolean summaries of observed behavior; unknown historical values are `null` |
| `files.read` | Arrays grouped into `self` (target gem directory), `resolver` (resolver configuration), and `other` |
| `files.write` | File write attempts after baseline subtraction |
| `files.notable` | Noteworthy home, project, and temporary file accesses, excluding routine gem caches |
| `network` | Socket address family and available address/port/path, with observation count |
| `exec` | Command path, captured argument list, count, and optional `argv_truncated` flag |
| `threads` | Thread-creating syscall names and counts |
| `processes`, `process_tree` | Process creation events and observed parent/executable relationships |
| `sockets` | Socket family, type, protocol, and attempt count |
| `files.create`, `files.truncate`, `files.append`, `files.rw` | Open-flag or explicit truncation attempts, alongside aggregate writes |
| `dns`, `listen` | Decoded DNS questions and listening socket observations |
| `suspicious`, `anti_analysis` | Selected sensitive syscall attempts and observation-evasion indicators |
| `dependencies` | Runtime dependency names and versions |
| `stats` | `open_total`, `open_after_baseline`, notification round trips, and elapsed milliseconds |
| `errors` | Target failures |
| `observer_errors` | Decoder, baseline, or other observation failures; these do not establish target failure |
| `stdout`, `stderr` | Bounded UTF-8 output; invalid bytes are replaced |
| `stdout_truncated`, `stderr_truncated` | Whether captured output exceeded its configured limit |
| `canary_hits` | Decoy source and location where its token was observed |

Paths can use `$HOME`, `$PWD`, `$GEM_HOME`, and `$TMPDIR` placeholders. These refer to the observed
environment, not necessarily the reader's current environment. Sensitive nonexistent reads remain
visible, while routine nonexistent read probes are discarded. The `self` category does not remove
a read from the manifest; it separates it from accesses outside the target gem.

Capability keys include `network`, `dns`, `exec`, `process`, `threads`, `home_read`, `home_write`,
`project_write`, `sensitive_read`, `native_extension`, `plugin`, `suspicious_syscalls`, and
`anti_analysis`. A false value means that capability was not observed, not that it is impossible.
The report's Home column combines reads and writes; PWD indicates project writes. `?` means unknown.
The schema permits additional observation fields as syscall coverage grows.

`run.mode.isolation` distinguishes `network_namespace`, `syscall_fallback`, and `none`. Observer errors
explain namespace fallback. `run.mode` also records observation settings used for cache identity;
legacy results with unknown settings remain readable but may not satisfy current-mode resume checks.
`run.kind: command` identifies `bonebed run` observations. They use the synthetic gem name `command`,
version `0`, and record normalized command arguments separately from package metadata.
Gem executable observations also use phase `exec`, retain their real gem identity, and record
`run.executable` and `run.arguments` so different invocations do not share cached results.

With `--repeat N`, each sample has `run.repeat` containing a shared `group`, one-based `index`, and
`count`. The optional `stability` object records `samples`, `complete`, and `stable`/`flaky` capability
key arrays for the phase. Only complete successful groups satisfy repeated-observation resume.
Stable means seen in every collected sample, not guaranteed behavior in every future execution.

Optional JSONL traces contain elapsed time, thread/process/parent IDs, syscall names, and decoded
arguments. They are separate artifacts from the manifest and can contain target-controlled private
data. Process relationships describe observed events, not a complete guarantee of ancestry or cleanup.
Gem observation trace names include the requested prefix, gem, version, run UUID, and phase, avoiding
overwrites between workers and repeated runs.

## Migrating historical metadata

Migration renames `stats.openat_total` and `stats.openat_after_baseline` to `open_total` and
`open_after_baseline`, and keeps old file reads in `files.read.other`. It preserves measured target
status, output, and observer errors when present. Unrecorded tool versions, execution timestamps,
target status, package metadata, truncation flags, dependencies, and canary hits become `null`.
The migration run ID is a deterministic digest of the original document; it is not a measured run ID.
Capabilities infer only what historical observations support. Migration never re-executes a gem or
fills missing metadata from the current machine.

Bundle observations use `run.kind: bundle`, a synthetic `bundle` gem at version `0`, and phase
`install`. `bundle.gemfile_sha256` and `bundle.lockfile_sha256` distinguish inputs in stored identities.
The Gemfile executes only inside the observed local install after prefetching succeeds.
