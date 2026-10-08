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
covers version, platform, and require path, including missing values, so different require paths or
platforms cannot overwrite each other's observations. A missing platform is displayed as `unknown`.
The readable filename is only a convenience; readers use the identity inside the document.

Writes use a temporary file in the destination directory followed by an atomic rename. Repeating
the same identity replaces its previous result. Survey resume checks target success, name, phase,
and any requested version, platform, or require path. Observer errors do not change target success.
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
| `gem` | Name, resolved version, platform, require path, package SHA-256, extensions, executables, and RubyGems plugin presence |
| `phase` | Observed phase; current workflows use `install` and `require` |
| `environment` | Ruby version, architecture, kernel, and startup baseline identifier |
| `target` | Target `exit_status`, terminating `signal`, and `timed_out` |
| `capabilities` | Boolean summaries of observed behavior; unknown historical values are `null` |
| `files.read` | Arrays grouped into `self` (target gem directory), `resolver` (resolver configuration), and `other` |
| `files.write` | File write attempts after baseline subtraction |
| `files.notable` | Noteworthy home, project, and temporary file accesses, excluding routine gem caches |
| `network` | Socket address family and available address/port/path, with observation count |
| `exec` | Command path, captured argument list, count, and optional `argv_truncated` flag |
| `threads` | Thread-creating syscall names and counts |
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

## Migrating historical metadata

Migration renames `stats.openat_total` and `stats.openat_after_baseline` to `open_total` and
`open_after_baseline`, and keeps old file reads in `files.read.other`. It preserves measured target
status, output, and observer errors when present. Unrecorded tool versions, execution timestamps,
target status, package metadata, truncation flags, dependencies, and canary hits become `null`.
The migration run ID is a deterministic digest of the original document; it is not a measured run ID.
Capabilities infer only what historical observations support. Migration never re-executes a gem or
fills missing metadata from the current machine.
